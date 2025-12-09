package lim

import (
	"context"
	"drylax/svc/db"
	"drylax/svc/util"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

const (
	maxLimiters     = 10000
	cleanupInterval = 5 * time.Minute
	limiterTTL      = 30 * time.Minute
)

type Limiter struct {
	rdb               *db.Redis
	trustedProxies    []string
	detector          *AnomalyDetector
	adaptiveModeUntil int64
	adaptiveMu        sync.RWMutex
	localLimiters     map[string]*limiterEntry
	mu                sync.Mutex
	conservativeLimit int
	burstLimit        int
	globalRPM         int
	quit              chan struct{}
	evictionSem       chan struct{}
}
type limiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}
type RateLimitResult struct {
	Allowed   bool
	Limit     int
	Remaining int
	Reset     time.Time
}

func New(globalRPM, perIPBurst, conservativeLimit int, rdb *db.Redis, trustedProxies []string) *Limiter {
	for _, proxy := range trustedProxies {
		if strings.Contains(proxy, "/") {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				panic(fmt.Sprintf("invalid CIDR in trustedProxies: %s: %v", proxy, err))
			}
		} else {
			if net.ParseIP(proxy) == nil {
				panic(fmt.Sprintf("invalid IP in trustedProxies: %s", proxy))
			}
		}
	}
	l := &Limiter{
		rdb:               rdb,
		trustedProxies:    trustedProxies,
		localLimiters:     make(map[string]*limiterEntry),
		conservativeLimit: conservativeLimit,
		burstLimit:        perIPBurst,
		globalRPM:         globalRPM,
		quit:              make(chan struct{}),
		evictionSem:       make(chan struct{}, 1),
	}
	l.detector = NewAnomalyDetector(l.TriggerAdaptiveMode)
	l.detector.Start()
	go l.cleanupLoop()
	return l
}
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.evictExpiredLimiters()
		case <-l.quit:
			return
		}
	}
}
func (l *Limiter) evictExpiredLimiters() {
	now := time.Now()
	toDelete := make([]string, 0, 100)
	l.mu.Lock()
	for key, entry := range l.localLimiters {
		if now.Sub(entry.lastAccess) > limiterTTL {
			toDelete = append(toDelete, key)
		}
	}
	for _, key := range toDelete {
		delete(l.localLimiters, key)
	}
	evicted := len(toDelete)
	remaining := len(l.localLimiters)
	l.mu.Unlock()
	if evicted > 0 {
		util.Debug().Int("evicted", evicted).Int("remaining", remaining).Msg("rate limiter cleanup")
	}
}
func (l *Limiter) Stop() {
	close(l.quit)
	l.detector.Stop()
}
func (l *Limiter) TriggerAdaptiveMode() {
	atomic.StoreInt64(&l.adaptiveModeUntil, time.Now().Add(60*time.Second).Unix())
}
func (l *Limiter) isAdaptiveMode() bool {
	until := atomic.LoadInt64(&l.adaptiveModeUntil)
	return time.Now().Unix() < until
}
func (l *Limiter) RecordRequest() {
	l.detector.RecordRequest()
}
func (l *Limiter) RecordError() {
	l.detector.RecordError()
}
func (l *Limiter) CheckLimit(w http.ResponseWriter, r *http.Request, endpoint string) *RateLimitResult {
	ip := GetRealIP(r, l.trustedProxies)
	now := time.Now()
	globalLimit := l.globalRPM
	if l.isAdaptiveMode() {
		globalLimit = l.globalRPM / 2
		if globalLimit < 1 {
			globalLimit = 1
		}
	}
	if l.rdb != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 100*time.Millisecond)
		defer cancel()
		usage, err := l.rdb.RateLimit(ctx, "global:"+endpoint, globalLimit, time.Minute)
		if err != nil {
			util.Warn().Err(err).Msg("redis rate limit unavailable, using local fallback")
			return l.failClosedLocal(ip, endpoint)
		}
		remaining := globalLimit - usage
		if remaining < 0 {
			remaining = 0
		}
		if usage > globalLimit {
			return &RateLimitResult{
				Allowed:   false,
				Limit:     globalLimit,
				Remaining: 0,
				Reset:     now.Add(time.Minute),
			}
		}
		return &RateLimitResult{
			Allowed:   true,
			Limit:     globalLimit,
			Remaining: remaining,
			Reset:     now.Add(time.Minute),
		}
	}
	return l.failClosedLocal(ip, endpoint)
}
func (l *Limiter) failClosedLocal(ip, endpoint string) *RateLimitResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	threshold := (maxLimiters * 9) / 10
	if len(l.localLimiters) >= threshold {
		toEvict := len(l.localLimiters) / 10
		if toEvict > 0 {
			select {
			case l.evictionSem <- struct{}{}:
				go func() {
					defer func() { <-l.evictionSem }()
					l.asyncEvictOldest(toEvict)
				}()
			default:
			}
		}
	}
	if len(l.localLimiters) >= maxLimiters {
		util.Warn().
			Int("limiters", len(l.localLimiters)).
			Str("ip", ip).
			Msg("rate limiter at capacity, rejecting request")
		return &RateLimitResult{
			Allowed:   false,
			Limit:     l.conservativeLimit,
			Remaining: 0,
			Reset:     time.Now().Add(time.Minute),
		}
	}
	limit := l.conservativeLimit
	if l.isAdaptiveMode() {
		limit = limit / 2
		if limit < 1 {
			limit = 1
		}
	}
	key := ip + ":" + endpoint
	entry, exists := l.localLimiters[key]
	if !exists {
		entry = &limiterEntry{
			limiter:    rate.NewLimiter(rate.Limit(limit)/60.0, limit),
			lastAccess: time.Now(),
		}
		l.localLimiters[key] = entry
	} else {
		entry.lastAccess = time.Now()
	}
	if !entry.limiter.Allow() {
		return &RateLimitResult{
			Allowed:   false,
			Limit:     limit,
			Remaining: 0,
			Reset:     time.Now().Add(time.Minute),
		}
	}
	return &RateLimitResult{
		Allowed:   true,
		Limit:     limit,
		Remaining: l.conservativeLimit - 1,
		Reset:     time.Now().Add(time.Minute),
	}
}
func (l *Limiter) asyncEvictOldest(count int) {
	l.mu.Lock()
	if len(l.localLimiters) < (maxLimiters*8)/10 {
		l.mu.Unlock()
		return
	}
	type kv struct {
		key        string
		lastAccess time.Time
	}
	entries := make([]kv, 0, len(l.localLimiters))
	for k, v := range l.localLimiters {
		entries = append(entries, kv{k, v.lastAccess})
	}
	l.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].lastAccess.Before(entries[j].lastAccess)
	})
	l.mu.Lock()
	defer l.mu.Unlock()
	evicted := 0
	for i := 0; i < count && i < len(entries); i++ {
		if _, exists := l.localLimiters[entries[i].key]; exists {
			delete(l.localLimiters, entries[i].key)
			evicted++
		}
	}
	if evicted > 0 {
		util.Debug().
			Int("evicted", evicted).
			Msg("async limiter eviction completed")
	}
}

func GetRealIP(r *http.Request, trustedProxies []string) string {
	remoteIP := stripPort(r.RemoteAddr)
	if len(trustedProxies) == 0 {
		return remoteIP
	}
	if !isTrustedProxy(remoteIP, trustedProxies) {
		return remoteIP
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP
	}

	const maxIPsToParse = 100
	parsedCount := 0
	remaining := xff

	for len(remaining) > 0 && parsedCount < maxIPsToParse {

		lastComma := strings.LastIndexByte(remaining, ',')

		var ipStr string
		if lastComma == -1 {

			ipStr = strings.TrimSpace(remaining)
			remaining = ""
		} else {

			ipStr = strings.TrimSpace(remaining[lastComma+1:])
			remaining = remaining[:lastComma]
		}

		if ipStr == "" {
			continue
		}

		parsedCount++

		parsedIP := net.ParseIP(ipStr)
		if parsedIP == nil {
			util.Warn().Str("ip", ipStr).Msg("invalid IP in X-Forwarded-For, skipping")
			continue
		}

		if !isTrustedProxy(ipStr, trustedProxies) {
			return ipStr
		}

	}

	if parsedCount >= maxIPsToParse {
		util.Warn().Int("parsed", parsedCount).Str("remote", remoteIP).Msg("XFF header excessive, truncated parsing")
	}
	return remoteIP
}
func isTrustedProxy(ip string, trustedProxies []string) bool {
	for _, proxy := range trustedProxies {
		if ip == proxy {
			return true
		}
		if strings.Contains(proxy, "/") {
			_, subnet, err := net.ParseCIDR(proxy)
			if err == nil {
				parsedIP := net.ParseIP(ip)
				if parsedIP != nil && subnet.Contains(parsedIP) {
					return true
				}
			}
		}
	}
	return false
}
func stripPort(ip string) string {
	if host, _, err := net.SplitHostPort(ip); err == nil {
		return host
	}
	return ip
}
