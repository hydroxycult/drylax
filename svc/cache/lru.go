package cache

import (
	"context"
	"drylax/pkg/domain"
	"errors"
	lru "github.com/hashicorp/golang-lru/v2"
	"sync"
	"time"
)

type LRU struct {
	c  *lru.Cache[string, item]
	mu sync.Mutex
}
type item struct {
	paste *domain.Paste
	exp   time.Time
}

func NewLRU(size int) (*LRU, error) {
	if size <= 0 {
		return nil, errors.New("cache size must be positive")
	}
	if size > 100000 {
		return nil, errors.New("cache size too large")
	}
	c, err := lru.New[string, item](size)
	if err != nil {
		return nil, err
	}
	return &LRU{c: c}, nil
}
func (l *LRU) Get(ctx context.Context, id string) *domain.Paste {
	select {
	case <-ctx.Done():
		return nil
	default:
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	it, ok := l.c.Get(id)
	if !ok {
		return nil
	}
	if time.Now().After(it.exp) {
		l.c.Remove(id)
		return nil
	}
	return it.paste
}
func (l *LRU) Set(ctx context.Context, p *domain.Paste, ttl time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.c.Add(p.ID, item{
		paste: p,
		exp:   time.Now().Add(ttl),
	})
}
func (l *LRU) Delete(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.c.Remove(id)
}
