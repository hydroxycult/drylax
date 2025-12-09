package db

import (
	"context"
	"time"
)

func (r *Redis) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	key := "health_check_" + time.Now().Format(time.RFC3339Nano)
	if err := r.client.Set(ctx, key, "ok", 5*time.Second).Err(); err != nil {
		return err
	}
	return r.client.Del(ctx, key).Err()
}
