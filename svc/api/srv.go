package api

import (
	"context"
	"drylax/cfg"
	"drylax/svc/db"
	"drylax/svc/lim"
	"drylax/svc/svc"
	"drylax/svc/util"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/hlog"
)

type Server struct {
	router     *chi.Mux
	paste      *svc.Paste
	lim        *lim.Limiter
	cfg        *cfg.Cfg
	db         *db.SQLite
	rdb        *db.Redis
	httpServer *http.Server
}

func NewServer(c *cfg.Cfg, p *svc.Paste, l *lim.Limiter, sqlDB *db.SQLite, rdb *db.Redis) *Server {
	r := chi.NewRouter()
	mw := NewMw(l, c)
	r.Group(func(r chi.Router) {
		r.Use(mw.Recoverer)
		s := &Server{db: sqlDB, rdb: rdb, cfg: c}
		r.Get("/health", s.Health)
		r.Get("/ready", s.Ready)
	})
	r.Group(func(r chi.Router) {
		r.Use(mw.Recoverer)
		r.Handle("/metrics", mw.BasicAuthMetrics(promhttp.Handler()))
	})
	r.Mount("/debug", middleware.Profiler())

	r.Group(func(r chi.Router) {
		r.Use(mw.Recoverer)
		r.Use(mw.RequestID)
		r.Use(hlog.NewHandler(util.GetLogger()))
		r.Use(hlog.AccessHandler(func(req *http.Request, status, size int, dur time.Duration) {
			hlog.FromRequest(req).Info().
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Int("status", status).
				Int("size", size).
				Dur("duration", dur).
				Str("request_id", util.GetRequestID(req.Context())).
				Msg("http request")
		}))
		if len(c.TrustedProxies) > 0 {
			r.Use(middleware.RealIP)
		}
		r.Use(mw.ContextTimeout)
		r.Use(mw.SecurityHeaders)
		r.Use(mw.CORS)
		r.Use(mw.JSONContentType)
		r.Use(mw.AnomalyDetection)
		hdl := &Hdl{paste: p, cfg: c}
		r.With(mw.RateLimitCreate).Post("/pastes", hdl.CreatePaste)
		r.With(mw.RateLimitRead).Get("/pastes/{id}", hdl.GetPaste)
		r.With(mw.RateLimitDelete).Delete("/pastes/{id}", hdl.DeletePaste)
		r.With(mw.RateLimitRead).Get("/config/presets", hdl.GetPresets)
	})
	s := &Server{
		router: r,
		paste:  p,
		lim:    l,
		cfg:    c,
		db:     sqlDB,
		rdb:    rdb,
		httpServer: &http.Server{
			Addr:           ":" + c.Port,
			Handler:        r,
			ReadTimeout:    15 * time.Second,
			WriteTimeout:   15 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 256 * 1024,
		},
	}
	return s
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}
func (s *Server) SetTimeouts(read, write, idle time.Duration) {
	s.httpServer.ReadTimeout = read
	s.httpServer.WriteTimeout = write
	s.httpServer.IdleTimeout = idle
}
func (s *Server) Start() error {
	util.Info().Str("port", s.cfg.Port).Msg("starting server")
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		util.Error().Err(err).Str("port", s.cfg.Port).Msg("server failed to start")
		return err
	}
	return nil
}
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}
