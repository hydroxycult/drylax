package kms
import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type KEKCache struct {
	cache    sync.Map
	ttl      time.Duration
	adapter  *Adapter
	group    singleflight.Group
	stopChan chan struct{}
	stopped  bool
	mu       sync.Mutex
}

type cachedKEK struct {
	unwrappedDEK []byte
	expiresAt    time.Time
	mu           sync.RWMutex
}

func NewKEKCache(adapter *Adapter, ttl time.Duration) *KEKCache {
	c := &KEKCache{
		ttl:      ttl,
		adapter:  adapter,
		stopChan: make(chan struct{}),
	}
	go c.evictionLoop()
	return c
}

func (c *KEKCache) DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return nil, ErrProviderUnavailable
	}
	c.mu.Unlock()

	cacheKey := c.cacheKeyFromDEK(encryptedDEK)

	result, err, _ := c.group.Do(cacheKey, func() (interface{}, error) {

		if cached, ok := c.cache.Load(cacheKey); ok {
			entry := cached.(*cachedKEK)
			entry.mu.RLock()
			expired := time.Now().After(entry.expiresAt)
			entry.mu.RUnlock()

			if !expired {

				entry.mu.RLock()
				defer entry.mu.RUnlock()

				dek := make([]byte, len(entry.unwrappedDEK))
				copy(dek, entry.unwrappedDEK)
				return dek, nil
			}

			c.cache.Delete(cacheKey)
		}

		unwrappedDEK, err := c.adapter.Decrypt(ctx, encryptedDEK)
		if err != nil {

			return nil, err
		}

		jitter := time.Duration(hashToJitter(cacheKey, int64(c.ttl/10)))
		expiresAt := time.Now().Add(c.ttl).Add(jitter)

		entry := &cachedKEK{
			unwrappedDEK: make([]byte, len(unwrappedDEK)),
			expiresAt:    expiresAt,
		}
		copy(entry.unwrappedDEK, unwrappedDEK)

		c.cache.Store(cacheKey, entry)

		dek := make([]byte, len(unwrappedDEK))
		copy(dek, unwrappedDEK)
		return dek, nil
	})

	if err != nil {
		return nil, err
	}
	return result.([]byte), nil
}

func (c *KEKCache) cacheKeyFromDEK(dek []byte) string {
	h := sha256.Sum256(dek)
	return hex.EncodeToString(h[:])
}

func hashToJitter(hashStr string, maxJitter int64) time.Duration {

	var sum int64
	for i := 0; i < len(hashStr) && i < 16; i++ {
		sum += int64(hashStr[i])
	}
	jitterNanos := (sum % maxJitter) * int64(time.Millisecond)
	return time.Duration(jitterNanos)
}

func (c *KEKCache) evictionLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

func (c *KEKCache) evictExpired() {
	now := time.Now()
	c.cache.Range(func(key, value interface{}) bool {
		entry := value.(*cachedKEK)
		entry.mu.RLock()
		expired := now.After(entry.expiresAt)
		entry.mu.RUnlock()

		if expired {
			c.cache.Delete(key)
		}
		return true
	})
}

func (c *KEKCache) Stop() {
	c.mu.Lock()
	if c.stopped {
		c.mu.Unlock()
		return
	}
	c.stopped = true
	close(c.stopChan)
	c.mu.Unlock()

	c.cache.Range(func(key, value interface{}) bool {
		entry := value.(*cachedKEK)
		entry.mu.Lock()
		wipeBytes(entry.unwrappedDEK)
		entry.unwrappedDEK = nil
		entry.mu.Unlock()
		c.cache.Delete(key)
		return true
	})
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *KEKCache) Stats() CacheStats {
	var stats CacheStats
	c.cache.Range(func(key, value interface{}) bool {
		stats.Entries++
		entry := value.(*cachedKEK)
		entry.mu.RLock()
		if time.Now().After(entry.expiresAt) {
			stats.Expired++
		}
		entry.mu.RUnlock()
		return true
	})
	return stats
}

type CacheStats struct {
	Entries int
	Expired int
}
