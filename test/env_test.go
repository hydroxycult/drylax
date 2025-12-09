package test

import (
	"os"
	"testing"
)

func TestEnvLoading(t *testing.T) {
	_ = loadTestEnv()

	tests := []struct {
		key      string
		expected string
	}{
		{"HASHER_WORKER_COUNT", "128"},
		{"WORKER_POOL_SIZE", "1000"},
		{"MAX_WORKER_LOAD", "5000"},
		{"PEPPER", "0123456789ABCDEF0123456789ABCDEF"},
		{"KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}

	for _, tt := range tests {
		got := os.Getenv(tt.key)
		if got != tt.expected {
			t.Errorf("Environment variable %s = %q, want %q", tt.key, got, tt.expected)
		} else {
			t.Logf("%s = %q", tt.key, got)
		}
	}

	cfg := createTestConfig()
	t.Logf("Config loaded successfully:")
	t.Logf("  HasherWorkerCount: %d", cfg.HasherWorkerCount)
	t.Logf("  WorkerPoolSize: %d", cfg.WorkerPoolSize)
	t.Logf("  MaxWorkerLoad: %d", cfg.MaxWorkerLoad)
	t.Logf("  Pepper length: %d bytes", len(cfg.Pepper.Value()))
}
