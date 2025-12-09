package db

import (
	"context"
)

func (s *SQLite) Ping(ctx context.Context) error {
	var result int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&result)
}
