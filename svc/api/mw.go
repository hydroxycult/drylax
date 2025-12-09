package api

import (
	"context"
	"crypto/subtle"
	"drylax/cfg"
	"drylax/pkg/domain"
	"drylax/svc/lim"
	"drylax/svc/util"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Mw struct {
	lim *lim.Limiter
	cfg *cfg.Cfg
}

func NewMw(limiter *lim.Limiter, c *cfg.Cfg) *Mw {
	return &Mw{lim: limiter, cfg: c}
}
func (m *Mw) RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := util.NewRequestID()
		ctx := util.SetRequestID(r.Context(), requestID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (m *Mw) ContextTimeout(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), m.cfg.ContextTimeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
func (m *Mw) SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none';")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				requestID := util.GetRequestID(r.Context())
				util.Error().
					Interface("panic", rvr).
					Str("request_id", requestID).
					Msg("panic recovered")
				if w.Header().Get("Content-Type") == "" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					json.NewEncoder(w).Encode(map[string]string{
						"error":      "internal server error",
						"request_id": requestID,
					})
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) RateLimitCreate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := m.lim.CheckLimit(w, r, "create")
		requestID := util.GetRequestID(r.Context())
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.Reset.Unix()))
		if !result.Allowed {
			util.Warn().
				Str("ip", util.RedactIP(r.RemoteAddr)).
				Str("endpoint", "create").
				Msg("rate limit exceeded")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(result.Reset).Seconds())))
			writeErr(w, domain.ErrRateLimitExceeded, requestID)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) RateLimitRead(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := m.lim.CheckLimit(w, r, "view")
		requestID := util.GetRequestID(r.Context())
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.Reset.Unix()))
		if !result.Allowed {
			util.Warn().
				Str("ip", util.RedactIP(r.RemoteAddr)).
				Str("endpoint", "read").
				Msg("rate limit exceeded")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(result.Reset).Seconds())))
			writeErr(w, domain.ErrRateLimitExceeded, requestID)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) RateLimitDelete(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := m.lim.CheckLimit(w, r, "create")
		requestID := util.GetRequestID(r.Context())
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.Reset.Unix()))
		if !result.Allowed {
			util.Warn().
				Str("ip", util.RedactIP(r.RemoteAddr)).
				Str("endpoint", "delete").
				Msg("rate limit exceeded")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(result.Reset).Seconds())))
			writeErr(w, domain.ErrRateLimitExceeded, requestID)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		fmt.Printf("CORS DEBUG: Method=%s Origin=%q AllowedOrigins=%v\n", r.Method, origin, m.cfg.AllowedOrigins)
		isAllowed := false
		for _, allowed := range m.cfg.AllowedOrigins {
			fmt.Printf("CORS DEBUG: Comparing origin=%q with allowed=%q\n", origin, allowed)
			if allowed == "*" || origin == allowed {
				isAllowed = true
				fmt.Printf("CORS DEBUG: MATCH! isAllowed=true\n")
				break
			}
		}
		fmt.Printf("CORS DEBUG: Final isAllowed=%v\n", isAllowed)
		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Paste-Password, X-Deletion-Token")
			w.Header().Set("Access-Control-Max-Age", "300")
			fmt.Printf("CORS DEBUG: Set CORS headers for origin=%q\n", origin)
		} else {
			fmt.Printf("CORS DEBUG: BLOCKED! No CORS headers set\n")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			fmt.Printf("CORS DEBUG: Responded to OPTIONS with NoContent\n")
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) JSONContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) BasicAuthMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.cfg.MetricsUser == "" && m.cfg.MetricsPass.Value() == "" {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userMatch := 0
		passMatch := 0
		if ok {
			userMatch = subtle.ConstantTimeCompare([]byte(user), []byte(m.cfg.MetricsUser))
			passMatch = subtle.ConstantTimeCompare([]byte(pass), []byte(m.cfg.MetricsPass.Value()))
		}
		if !ok || userMatch != 1 || passMatch != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="metrics"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (m *Mw) AnomalyDetection(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.lim.RecordRequest()
		ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)
		if ww.status >= 500 {
			m.lim.RecordError()
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
