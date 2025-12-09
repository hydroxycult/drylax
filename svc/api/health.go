package api

import (
	"context"
	"drylax/svc/util"
	"encoding/json"
	"net/http"
	"time"
)

type HealthResponse struct {
	Status string `json:"status"`
}
type ReadyResponse struct {
	Ready    bool   `json:"ready"`
	Degraded bool   `json:"degraded"`
	Database string `json:"database"`
	Cache    string `json:"cache"`
}

func (s *Server) Health(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status: "ok",
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
func (s *Server) Ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	resp := ReadyResponse{
		Ready:    true,
		Degraded: false,
		Database: "up",
		Cache:    "up",
	}
	dbCtx, dbCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer dbCancel()
	if err := s.db.Ping(dbCtx); err != nil {
		util.Error().Err(err).Msg("database health check failed")
		resp.Database = "down"
		resp.Degraded = true
		resp.Ready = false
	}
	cacheCtx, cacheCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cacheCancel()
	rdb := s.rdb
	if rdb != nil {
		if err := rdb.Ping(cacheCtx); err != nil {
			util.Error().Err(err).Msg("cache health check failed")
			resp.Cache = "down"
			resp.Degraded = true
			resp.Ready = false
		}
	} else {
		resp.Cache = "unavailable"
	}
	w.Header().Set("Content-Type", "application/json")
	if !resp.Ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else if resp.Degraded {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(resp)
}
