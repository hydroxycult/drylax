package api

import (
	"drylax/cfg"
	"drylax/pkg/domain"
	"drylax/svc/lim"
	"drylax/svc/svc"
	"drylax/svc/util"
	"encoding/json"
	"html"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/hlog"
	"golang.org/x/text/unicode/norm"
)

const (
	maxRequestSize = 128 * 1024
	maxTTL         = 30 * 24 * time.Hour
	minTTL         = 60 * time.Second
)

type Hdl struct {
	paste *svc.Paste
	cfg   *cfg.Cfg
}
type CreateReq struct {
	Content  string `json:"content"`
	Password string `json:"password,omitempty"`
	Duration string `json:"duration,omitempty"`
}
type CreateResp struct {
	ID            string    `json:"id"`
	DeletionToken string    `json:"deletion_token"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (h *Hdl) CreatePaste(w http.ResponseWriter, r *http.Request) {
	log := hlog.FromRequest(r)
	requestID := util.GetRequestID(r.Context())
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		log.Warn().
			Str("content_type", contentType).
			Str("request_id", requestID).
			Msg("invalid Content-Type header")
		w.WriteHeader(http.StatusUnsupportedMediaType)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "expected Content-Type: application/json",
			"request_id": requestID,
		})
		return
	}

	limit := h.cfg.MaxPasteSize * 2
	if clHeader := r.Header.Get("Content-Length"); clHeader != "" {
		cl, err := strconv.ParseInt(clHeader, 10, 64)
		if err != nil || cl < 0 {
			log.Warn().Str("content_length", clHeader).Msg("invalid Content-Length")
			writeErr(w, domain.ErrInvalidRequest, requestID)
			return
		}
		if cl > limit {
			log.Warn().Int64("content_length", cl).Msg("Content-Length exceeds maximum")
			writeErr(w, domain.ErrPasteTooLarge, requestID)
			return
		}
		if ce := r.Header.Get("Content-Encoding"); ce != "" {
			log.Warn().Str("content_encoding", ce).Msg("compressed content not allowed")
			writeErr(w, domain.ErrInvalidRequest, requestID)
			return
		}
	} else {
		log.Warn().Msg("missing Content-Length on POST")
		writeErr(w, domain.ErrInvalidRequest, requestID)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	var req CreateReq
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		if err == io.EOF {
			log.Warn().Msg("empty request body")
		} else {
			log.Warn().Err(err).Msg("invalid request")
		}
		writeErr(w, domain.ErrInvalidRequest, requestID)
		return
	}
	if req.Content == "" {
		log.Warn().Msg("empty content")
		writeErr(w, domain.ErrContentRequired, requestID)
		return
	}
	if int64(len(req.Content)) > h.cfg.MaxPasteSize {
		log.Warn().Int("content_length", len(req.Content)).Msg("content exceeds maximum size")
		writeErr(w, domain.ErrPasteTooLarge, requestID)
		return
	}
	dur := 24 * time.Hour
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			log.Warn().Err(err).Str("duration", req.Duration).Msg("invalid duration")
			writeErr(w, domain.ErrInvalidDuration, requestID)
			return
		}
		if d > maxTTL {
			log.Warn().Dur("requested", d).Msg("duration exceeds max, capping")
			d = maxTTL
		}
		if d < minTTL {
			log.Warn().Dur("requested", d).Msg("duration below min, rejecting")
			writeErr(w, domain.ErrInvalidDuration, requestID)
			return
		}
		dur = d
	}

	realIP := lim.GetRealIP(r, h.cfg.TrustedProxies)
	ipHasher, err := util.GetIPHasher()
	if err != nil {
		log.Error().Err(err).Msg("IP hasher not initialized")
		writeErr(w, domain.ErrInternalServer, requestID)
		return
	}
	ipHash, err := ipHasher.HashIP(realIP)
	if err != nil {
		log.Error().Err(err).Str("ip", util.RedactIP(realIP)).Msg("failed to hash client IP")
		writeErr(w, domain.ErrInternalServer, requestID)
		return
	}

	params := domain.CreateParams{
		Content:      sanitizeContent(req.Content),
		Password:     req.Password,
		Duration:     dur,
		ClientIPHash: ipHash,
	}
	paste, deletionToken, err := h.paste.Create(r.Context(), params)
	if err != nil {
		log.Error().Err(err).Msg("failed to create paste")
		if errors.Is(err, domain.ErrPasteTooLarge) || errors.Is(err, domain.ErrIDGenerationFailed) {
			writeErr(w, err, requestID)
			return
		}
		writeErr(w, domain.ErrInternalServer, requestID)
		return
	}
	log.Info().
		Str("paste_id", paste.ID).
		Str("ttl", dur.String()).
		Bool("password_protected", req.Password != "").
		Msg("paste created")
	resp := CreateResp{
		ID:            paste.ID,
		DeletionToken: deletionToken,
		ExpiresAt:     paste.ExpiresAt,
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}
func (h *Hdl) DeletePaste(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	token := r.Header.Get("X-Deletion-Token")
	log := hlog.FromRequest(r)
	requestID := util.GetRequestID(r.Context())
	if token == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "missing X-Deletion-Token header",
			"request_id": requestID,
		})
		return
	}
	if err := h.paste.Delete(r.Context(), id, token); err != nil {
		if errors.Is(err, domain.ErrUnauthorized) || errors.Is(err, util.ErrTokenForged) ||
			errors.Is(err, util.ErrTokenExpired) || errors.Is(err, util.ErrTokenUsed) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":      "invalid deletion token",
				"request_id": requestID,
			})
			return
		}
		if errors.Is(err, domain.ErrPasteNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		log.Error().Err(err).Str("id", id).Msg("failed to delete paste")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      "internal server error",
			"request_id": requestID,
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}
func (h *Hdl) GetPaste(w http.ResponseWriter, r *http.Request) {
	log := hlog.FromRequest(r)
	requestID := util.GetRequestID(r.Context())
	id := chi.URLParam(r, "id")
	password := r.URL.Query().Get("password")
	if password == "" {
		password = r.Header.Get("X-Paste-Password")
	}
	paste, err := h.paste.Get(r.Context(), id, password)
	if err != nil {
		log.Warn().Err(err).Str("paste_id", id).Msg("get failed")
		if errors.Is(err, domain.ErrPasteNotFound) {
			writeErr(w, domain.ErrPasteNotFound, requestID)
			return
		}
		if errors.Is(err, domain.ErrPasteExpired) {
			writeErr(w, domain.ErrPasteExpired, requestID)
			return
		}
		if errors.Is(err, domain.ErrUnauthorized) {
			writeErr(w, domain.ErrUnauthorized, requestID)
			return
		}
		if errors.Is(err, domain.ErrPasswordRequired) || errors.Is(err, domain.ErrInvalidPassword) {
			log.Warn().
				Str("paste_id", id).
				Str("client_ip", util.RedactIP(r.RemoteAddr)).
				Msg("failed password attempt")
			writeErr(w, domain.ErrUnauthorized, requestID)
			return
		}
		writeErr(w, domain.ErrInternalServer, requestID)
		return
	}
	log.Info().
		Str("paste_id", id).
		Str("client_ip", util.RedactIP(r.RemoteAddr)).
		Int64("views", int64(paste.Views)).
		Msg("paste retrieved")
	json.NewEncoder(w).Encode(paste)
}
func (h *Hdl) GetPresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	presets := make([]string, len(h.cfg.TTLPresets))
	for i, d := range h.cfg.TTLPresets {
		presets[i] = d.String()
	}
	json.NewEncoder(w).Encode(presets)
}
func writeErr(w http.ResponseWriter, err error, requestID string) {
	statusCode := domain.Status(err)
	w.WriteHeader(statusCode)
	errorMsg := domain.ToResp(err).Error.Msg
	if statusCode >= 500 {
		errorMsg = "internal server error"
		util.Error().
			Err(err).
			Str("request_id", requestID).
			Msg("internal error with detailed info")
	}
	json.NewEncoder(w).Encode(map[string]string{
		"error":      errorMsg,
		"request_id": requestID,
	})
}
func sanitizeContent(s string) string {
	s = norm.NFC.String(s)
	if !utf8.ValidString(s) {
		v := make([]rune, 0, len(s))
		for _, r := range s {
			if r != utf8.RuneError {
				v = append(v, r)
			}
		}
		s = string(v)
	}
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, s)

	return html.EscapeString(s)
}
