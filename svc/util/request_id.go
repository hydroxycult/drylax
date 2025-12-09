package util

import (
	"context"
	"github.com/google/uuid"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}
func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok && id != "" {
		return id
	}
	return uuid.New().String()
}
func NewRequestID() string {
	return uuid.New().String()
}
