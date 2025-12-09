package cfg

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

type Secret struct {
	value []byte
}

func NewSecret(s string) Secret {
	return Secret{value: []byte(s)}
}
func (s Secret) Value() string {
	return string(s.value)
}
func (s Secret) Wipe() {
	for i := range s.value {
		s.value[i] = 0
	}
}
func (s Secret) String() string {
	return "***REDACTED***"
}

type Cfg struct {
	Port                   string
	Environment            string
	LogLevel               string
	DatabasePath           string
	RedisURL               string
	RedisTLS               bool
	RedisUsername          string
	RedisPassword          Secret
	RedisTimeout           time.Duration
	LRUCacheSize           int
	Argon2Time             uint32
	Argon2Memory           uint32
	Argon2Parallelism      uint8
	Argon2KeyLen           uint32
	HasherWorkerCount      int
	RateLimit              RateLimitCfg
	MaxPasteSize           int64
	MaxWorkerLoad          int
	DeletionTokenExpiry    time.Duration
	TokenReplayTTL         time.Duration
	TrustedProxies         []string
	MetricsUser            string
	MetricsPass            Secret
	MetricsRequireMTLS     bool
	WorkerPoolSize         int
	TTLPresets             []time.Duration
	Pepper                 Secret
	PepperFromKMS          bool
	ContextTimeout         time.Duration
	AllowedOrigins         []string
	DBMaxOpenConns         int
	DBMaxIdleConns         int
	DBQueryTimeout         time.Duration
	IPHashRotationInterval time.Duration
	KEKCacheTTL            time.Duration
}

type RateLimitCfg struct {
	RPM               int
	Burst             int
	ConservativeLimit int
}

func Load() (*Cfg, error) {
	c := &Cfg{}
	c.Port = getEnv("PORT", "8080")
	c.Environment = getEnv("ENVIRONMENT", "development")
	c.LogLevel = getEnv("LOG_LEVEL", "info")
	c.DatabasePath = getEnv("DATABASE_PATH", "drylax.db")
	c.RedisURL = getEnv("REDIS_URL", "")
	c.RedisTLS = getEnv("REDIS_TLS", "false") == "true"
	c.RedisUsername = getEnv("REDIS_USERNAME", "")
	c.RedisPassword = NewSecret(getEnv("REDIS_PASSWORD", ""))
	var err error
	c.RedisTimeout, err = getDuration("REDIS_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.LRUCacheSize, err = getInt("LRU_CACHE_SIZE", 1000)
	if err != nil {
		return nil, err
	}
	c.Argon2Time, err = getUint32("ARGON2_TIME", 4)
	if err != nil {
		return nil, err
	}
	c.Argon2Memory, err = getUint32("ARGON2_MEMORY", 128*1024)
	if err != nil {
		return nil, err
	}
	p, err := getUint32("ARGON2_PARALLELISM", 2)
	if err != nil {
		return nil, err
	}
	if p > 255 {
		return nil, errors.New("ARGON2_PARALLELISM must be <= 255")
	}
	c.Argon2Parallelism = uint8(p)
	c.Argon2KeyLen, err = getUint32("ARGON2_KEYLEN", 32)
	if err != nil {
		return nil, err
	}
	c.HasherWorkerCount, err = getInt("HASHER_WORKER_COUNT", 4)
	if err != nil {
		return nil, err
	}
	c.RateLimit.RPM, err = getInt("RATE_LIMIT_RPM", 60)
	if err != nil {
		return nil, err
	}
	c.RateLimit.Burst, err = getInt("RATE_LIMIT_BURST", 10)
	if err != nil {
		return nil, err
	}
	c.RateLimit.ConservativeLimit, err = getInt("RATE_LIMIT_CONSERVATIVE", 5)
	if err != nil {
		return nil, err
	}
	c.MaxPasteSize, err = getInt64("MAX_PASTE_SIZE", 64*1024)
	if err != nil {
		return nil, err
	}
	c.MaxWorkerLoad, err = getInt("MAX_WORKER_LOAD", 100)
	if err != nil {
		return nil, err
	}
	c.DeletionTokenExpiry, err = getDuration("DELETION_TOKEN_EXPIRY", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	c.TokenReplayTTL, err = getDuration("TOKEN_REPLAY_TTL", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	c.TrustedProxies = getSlice("TRUSTED_PROXIES", []string{})
	c.MetricsUser = getEnv("METRICS_USER", "")
	c.MetricsPass = NewSecret(getEnv("METRICS_PASS", ""))
	c.MetricsRequireMTLS = getEnv("METRICS_REQUIRE_MTLS", "false") == "true"
	c.WorkerPoolSize, err = getInt("WORKER_POOL_SIZE", 20)
	if err != nil {
		return nil, err
	}
	c.ContextTimeout, err = getDuration("CONTEXT_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	presetsStr := getEnv("TTL_PRESETS", "1h,24h,168h,720h")
	for _, s := range strings.Split(presetsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("invalid TTL preset %q: %w", s, err)
		}
		c.TTLPresets = append(c.TTLPresets, d)
	}
	c.Pepper = NewSecret(getEnv("PEPPER", ""))
	c.PepperFromKMS = getEnv("PEPPER_FROM_KMS", "false") == "true"
	c.AllowedOrigins = getSlice("ALLOWED_ORIGINS", []string{})

	c.DBMaxOpenConns, err = getInt("DB_MAX_OPEN_CONNS", 100)
	if err != nil {
		return nil, err
	}
	c.DBMaxIdleConns, err = getInt("DB_MAX_IDLE_CONNS", 10)
	if err != nil {
		return nil, err
	}
	c.DBQueryTimeout, err = getDuration("DB_QUERY_TIMEOUT", 5*time.Second)
	if err != nil {
		return nil, err
	}
	c.IPHashRotationInterval, err = getDuration("IP_HASH_ROTATION_INTERVAL", 1*time.Hour)
	if err != nil {
		return nil, err
	}
	c.KEKCacheTTL, err = getDuration("KEK_CACHE_TTL", 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return c, nil
}
func Validate(c *Cfg) error {
	if c.Port == "" {
		return errors.New("PORT is required")
	}
	if _, err := strconv.Atoi(c.Port); err != nil {
		return errors.New("PORT must be a number")
	}

	if c.DatabasePath == "" {
		return errors.New("DATABASE_PATH is required")
	}
	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}
	absWorkDir, err := filepath.Abs(workDir)
	if err != nil {
		return fmt.Errorf("failed to resolve working directory: %w", err)
	}
	absDBPath, err := filepath.Abs(c.DatabasePath)
	if err != nil {
		return fmt.Errorf("invalid DATABASE_PATH: %w", err)
	}
	if !strings.HasPrefix(absDBPath, absWorkDir+string(filepath.Separator)) && absDBPath != absWorkDir {
		return fmt.Errorf("DATABASE_PATH must be within working directory %s", absWorkDir)
	}
	if c.RedisURL != "" {
		if !strings.HasPrefix(c.RedisURL, "redis://") && !strings.HasPrefix(c.RedisURL, "rediss://") {
			return errors.New("REDIS_URL must start with redis:// or rediss://")
		}
		if strings.HasPrefix(c.RedisURL, "rediss://") && !c.RedisTLS {
			return errors.New("REDIS_URL uses rediss:// but REDIS_TLS=false")
		}
	}

	if c.LRUCacheSize <= 0 {
		return errors.New("LRU_CACHE_SIZE must be positive")
	}
	if c.Argon2Time < 4 {
		return errors.New("ARGON2_TIME must be >= 4")
	}
	if c.Argon2Memory < 128*1024 {
		return errors.New("ARGON2_MEMORY must be >= 131072 (128MB)")
	}
	if c.Argon2Parallelism < 1 {
		return errors.New("ARGON2_PARALLELISM must be at least 1")
	}
	if c.Argon2KeyLen < 32 {
		return errors.New("ARGON2_KEYLEN must be >= 32")
	}
	if c.RateLimit.RPM <= 0 {
		return errors.New("RATE_LIMIT_RPM must be positive")
	}

	if c.MaxPasteSize <= 0 {
		return errors.New("MAX_PASTE_SIZE must be positive")
	}
	if c.MaxPasteSize > 10*1024*1024 {
		return errors.New("MAX_PASTE_SIZE cannot exceed 10MB")
	}

	if c.DeletionTokenExpiry > 7*24*time.Hour {
		return errors.New("DELETION_TOKEN_EXPIRY cannot exceed 7 days")
	}
	if c.DeletionTokenExpiry < 1*time.Minute {
		return errors.New("DELETION_TOKEN_EXPIRY must be at least 1 minute")
	}
	if c.TokenReplayTTL < 1*time.Minute {
		return errors.New("TOKEN_REPLAY_TTL must be at least 1 minute")
	}
	if c.TokenReplayTTL > 7*24*time.Hour {
		return errors.New("TOKEN_REPLAY_TTL cannot exceed 7 days")
	}
	for _, proxy := range c.TrustedProxies {
		if strings.Contains(proxy, "/") {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return fmt.Errorf("invalid CIDR in TRUSTED_PROXIES: %s", proxy)
			}
		} else {
			if net.ParseIP(proxy) == nil {
				return fmt.Errorf("invalid IP in TRUSTED_PROXIES: %s", proxy)
			}
		}
	}

	if c.Environment == "production" {
		if c.MetricsUser == "" || c.MetricsPass.Value() == "" {
			return errors.New("METRICS_USER and METRICS_PASS are required in production")
		}
		// if c.RedisURL == "" {
		// 	return errors.New("REDIS_URL is required in production")
		// }
	}
	if !c.PepperFromKMS {
		if len(c.Pepper.Value()) == 0 {
			return errors.New("PEPPER is required if PEPPER_FROM_KMS is false")
		}
		if len(c.Pepper.Value()) < 32 {
			return errors.New("PEPPER must be at least 32 bytes")
		}
	}

	if c.IPHashRotationInterval < 15*time.Minute {
		return errors.New("IP_HASH_ROTATION_INTERVAL must be at least 15 minutes")
	}
	if c.IPHashRotationInterval > 24*time.Hour {
		return errors.New("IP_HASH_ROTATION_INTERVAL should not exceed 24 hours")
	}
	if c.KEKCacheTTL < 1*time.Minute {
		return errors.New("KEK_CACHE_TTL must be at least 1 minute")
	}
	if c.KEKCacheTTL > 1*time.Hour {
		return errors.New("KEK_CACHE_TTL should not exceed 1 hour (security risk)")
	}

	return nil
}
func (c *Cfg) Wipe() {
	c.RedisPassword.Wipe()
	c.MetricsPass.Wipe()
	c.Pepper.Wipe()
}
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}
func getInt(key string, fallback int) (int, error) {
	s := getEnv(key, "")
	if s == "" {
		return fallback, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %w", key, err)
	}
	return v, nil
}
func getInt64(key string, fallback int64) (int64, error) {
	s := getEnv(key, "")
	if s == "" {
		return fallback, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid integer for %s: %w", key, err)
	}
	return v, nil
}
func getUint32(key string, fallback uint32) (uint32, error) {
	s := getEnv(key, "")
	if s == "" {
		return fallback, nil
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid uint32 for %s: %w", key, err)
	}
	return uint32(v), nil
}
func getDuration(key string, fallback time.Duration) (time.Duration, error) {
	s := getEnv(key, "")
	if s == "" {
		return fallback, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration for %s: %w", key, err)
	}
	return v, nil
}
func getSlice(key string, fallback []string) []string {
	s := getEnv(key, "")
	if s == "" {
		return fallback
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
