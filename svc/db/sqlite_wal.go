package db

import (
	"context"
	"database/sql"
	"drylax/svc/util"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"time"
)

const (
	walSizeThreshold   = 10 * 1024 * 1024
	checkpointInterval = 5 * time.Minute
)

func StartWALMaintenance(db *sql.DB, quit chan struct{}) {
	ticker := time.NewTicker(checkpointInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := performWALCheckpoint(db); err != nil {
				util.Error().Err(err).Msg("WAL checkpoint failed")
			}
		case <-quit:
			if err := performWALCheckpoint(db); err != nil {
				util.Error().Err(err).Msg("final WAL checkpoint failed")
			}
			return
		}
	}
}
func performWALCheckpoint(db *sql.DB) error {
	start := time.Now()
	if _, err := db.Exec("PRAGMA synchronous=FULL"); err != nil {
		return fmt.Errorf("set synchronous: %w", err)
	}
	var walSize int64
	if err := db.QueryRow("PRAGMA wal_checkpoint").Scan(&walSize); err == nil {
		util.Debug().Int64("wal_size", walSize).Msg("WAL size check")
	}
	var busyPages, logPages, checkpointed int
	err := db.QueryRow("PRAGMA wal_checkpoint(PASSIVE)").Scan(&busyPages, &logPages, &checkpointed)
	if err != nil {
		util.Warn().Err(err).Msg("PASSIVE checkpoint query failed")
		if _, err := db.Exec("PRAGMA wal_checkpoint(PASSIVE)"); err != nil {
			return fmt.Errorf("PASSIVE checkpoint exec failed: %w", err)
		}
	} else {
		util.Debug().
			Int("busy", busyPages).
			Int("log", logPages).
			Int("checkpointed", checkpointed).
			Msg("PASSIVE checkpoint result")
		if logPages > 1000 || busyPages > 0 {
			util.Info().Msg("escalating to TRUNCATE checkpoint")
			err = db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busyPages, &logPages, &checkpointed)
			if err != nil {
				if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
					return fmt.Errorf("TRUNCATE checkpoint failed: %w", err)
				}
			} else {
				util.Info().
					Int("busy", busyPages).
					Int("log", logPages).
					Int("checkpointed", checkpointed).
					Msg("TRUNCATE checkpoint result")
			}
		}
	}
	if err := verifyIntegrity(db); err != nil {
		util.Error().Err(err).Msg("CRITICAL: database integrity check failed after checkpoint")
		return fmt.Errorf("integrity check failed: %w", err)
	}
	util.Debug().Dur("duration", time.Since(start)).Msg("WAL checkpoint completed")
	return nil
}
func verifyIntegrity(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var result string
	err := db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return fmt.Errorf("integrity_check query failed: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("integrity_check returned: %s", result)
	}
	return nil
}
