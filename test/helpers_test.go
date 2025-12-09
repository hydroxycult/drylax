package test

import (
	"context"
	"drylax/cfg"
	"drylax/pkg/kms"
	"drylax/svc/auth"
	"drylax/svc/cache"
	"drylax/svc/db"
	"drylax/svc/util"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

var (
	envLoadOnce sync.Once
	envLoadErr  error
)

func loadTestEnv() error {
	envLoadOnce.Do(func() {

		paths := []string{
			".env.test",
			"../.env.test",
			"../../.env.test",
		}

		for _, p := range paths {
			if absPath, err := filepath.Abs(p); err == nil {
				if _, err := os.Stat(absPath); err == nil {
					if err := godotenv.Load(absPath); err == nil {
						return
					}
				}
			}
		}

		if os.Getenv("KMS_LOCAL_KEY") == "" {
			os.Setenv("KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
		}
		if os.Getenv("PEPPER") == "" {
			os.Setenv("PEPPER", "0123456789ABCDEF0123456789ABCDEF")
		}
	})
	return envLoadErr
}

func createTestConfig() *cfg.Cfg {

	_ = loadTestEnv()

	deletionKey := os.Getenv("DELETION_TOKEN_KEY")
	if deletionKey == "" {
		deletionKey = "test-deletion-key-32-bytes-long!"
	}
	_ = util.InitDeletionTokenKey([]byte(deletionKey))

	c, err := cfg.Load()
	if err != nil {
		fmt.Printf("DEBUG: cfg.Load() failed: %v\n", err)

		return &cfg.Cfg{
			Port:                "0",
			Environment:         "test",
			LogLevel:            "error",
			DatabasePath:        ":memory:",
			LRUCacheSize:        1000,
			Argon2Time:          4,
			Argon2Memory:        128 * 1024,
			Argon2Parallelism:   2,
			Argon2KeyLen:        32,
			HasherWorkerCount:   4,
			MaxPasteSize:        1024 * 1024,
			MaxWorkerLoad:       1000,
			DeletionTokenExpiry: 24 * time.Hour,
			TokenReplayTTL:      1 * time.Hour,
			WorkerPoolSize:      100,
			TTLPresets:          []time.Duration{5 * time.Minute},
			Pepper:              cfg.NewSecret("0123456789ABCDEF0123456789ABCDEF"),
			ContextTimeout:      30 * time.Second,
			RateLimit: cfg.RateLimitCfg{
				RPM:               100000,
				Burst:             10000,
				ConservativeLimit: 50000,
			},
			IPHashRotationInterval: 1 * time.Hour,
			KEKCacheTTL:            10 * time.Minute,
		}
	}

	c.Port = "0"
	c.Environment = "test"
	c.LogLevel = "error"
	c.DatabasePath = ":memory:"

	return c
}

func createTestDB(t *testing.T, c *cfg.Cfg) *db.SQLite {

	dsn := fmt.Sprintf("file:memdb%d?mode=memory&cache=shared", time.Now().UnixNano())

	maxOpenConns := c.DBMaxOpenConns
	if maxOpenConns == 0 {
		maxOpenConns = 250
	}
	maxIdleConns := c.DBMaxIdleConns
	if maxIdleConns == 0 {
		maxIdleConns = 25
	}
	queryTimeout := c.DBQueryTimeout
	if queryTimeout == 0 {
		queryTimeout = 10 * time.Second
	}

	sqlDB, err := db.NewSQLiteWithConfig(dsn, maxOpenConns, maxIdleConns, queryTimeout)
	if err != nil {
		t.Fatal(err)
	}
	return sqlDB
}

func createTestLRU(t *testing.T, size int) *cache.LRU {
	lru, err := cache.NewLRU(size)
	if err != nil {
		t.Fatal(err)
	}
	return lru
}

func createTestHasher(t *testing.T, c *cfg.Cfg) *auth.Hasher {
	hasher, err := auth.NewHasher(c.Argon2Time, c.Argon2Memory, c.Argon2Parallelism, []byte(c.Pepper.Value()))
	if err != nil {
		t.Fatal(err)
	}
	if err := hasher.Start(c.HasherWorkerCount); err != nil {
		t.Fatal(err)
	}
	return hasher
}

func createTestKMS(t *testing.T) *kms.Adapter {

	if os.Getenv("KMS_LOCAL_KEY") == "" && os.Getenv("VAULT_ADDR") == "" && os.Getenv("AWS_REGION") == "" {

		t.Setenv("KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	}

	kmsAdapter, err := kms.NewAdapter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return kmsAdapter
}
