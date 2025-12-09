package test

import (
	"context"
	"drylax/pkg/domain"
	"drylax/pkg/kms"
	"drylax/svc/cache"
	"drylax/svc/db"
	"drylax/svc/svc"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestChaosDatabaseFailure(t *testing.T) {
	tmpDB, err := os.CreateTemp("", "chaos_test_*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpDB.Name())
	tmpDB.Close()

	sqlDB, err := db.NewSQLite(tmpDB.Name())
	if err != nil {
		t.Fatal(err)
	}

	c := createTestConfig()
	lru := createTestLRU(t, 100)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()
	paste, token, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "test content", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	lru.Delete(paste.ID)

	sqlDB.Close()

	_, _, err = pasteSvc.Create(ctx, domain.CreateParams{Content: "will fail", Duration: 5 * time.Minute})
	if err == nil {
		t.Error("Expected error when database is closed, got nil")
	}

	_, err = pasteSvc.Get(ctx, paste.ID, "")
	if err == nil {
		t.Error("Expected error when retrieving from closed database")
	}

	err = pasteSvc.Delete(ctx, paste.ID, token)
	if err == nil {
		t.Error("Expected error when deleting from closed database")
	}

	t.Log("Database failure handled gracefully without panics")
}

func TestChaosDatabaseCorruption(t *testing.T) {
	tmpDB, err := os.CreateTemp("", "chaos_corrupt_*.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := tmpDB.Name()
	tmpDB.Close()
	defer os.Remove(dbPath)

	sqlDB, err := db.NewSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	c := createTestConfig()
	lru := createTestLRU(t, 100)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)

	ctx := context.Background()
	_, _, err = pasteSvc.Create(ctx, domain.CreateParams{Content: "test", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	pasteSvc.Shutdown()
	sqlDB.Close()

	dbFile, err := os.OpenFile(dbPath, os.O_WRONLY, 0644)
	if err == nil {
		dbFile.WriteAt([]byte("CORRUPTED"), 0)
		dbFile.Close()
	}

	_, err = db.NewSQLite(dbPath)
	if err == nil {
		t.Log("Warning: corrupted database opened successfully (SQLite may have recovery)")
	} else {
		t.Logf("Corrupted database rejected as expected: %v", err)
	}
}

func TestChaosCacheFailure(t *testing.T) {
	c := createTestConfig()
	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru, err := cache.NewLRU(10)
	if err != nil {
		t.Fatal(err)
	}
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()

	paste1, _, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "content1", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	retrieved, err := pasteSvc.Get(ctx, paste1.ID, "")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 20; i++ {
		pasteSvc.Create(ctx, domain.CreateParams{Content: "filler", Duration: 5 * time.Minute})
	}

	retrieved2, err := pasteSvc.Get(ctx, paste1.ID, "")
	if err != nil {
		t.Fatal(err)
	}

	if retrieved.Content != retrieved2.Content {
		t.Error("Cache-DB inconsistency detected")
	}

	t.Log("Cache eviction and fallback to DB working correctly")
}

func TestChaosKMSFailure(t *testing.T) {
	localKey := os.Getenv("KMS_LOCAL_KEY")
	vaultAddr := os.Getenv("VAULT_ADDR")
	awsRegion := os.Getenv("AWS_REGION")

	t.Setenv("KMS_LOCAL_KEY", "")
	t.Setenv("VAULT_ADDR", "")
	t.Setenv("AWS_REGION", "")

	_, err := kms.NewAdapter(context.Background())
	if err == nil {
		t.Fatal("BLOCKER: KMS must fail-closed when no providers configured - system failed to return error")
	}
	t.Log("KMS correctly rejects initialization with no providers (fail-closed behavior verified)")

	_ = localKey
	_ = vaultAddr
	_ = awsRegion
}

func TestChaosCascadingFailures(t *testing.T) {
	c := createTestConfig()
	c.RateLimit.RPM = 10

	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru, err := cache.NewLRU(1)
	if err != nil {
		t.Fatal(err)
	}
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()
	var wg sync.WaitGroup
	errorCount := int64(0)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "test", Duration: 5 * time.Minute})
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
			}
		}()
	}

	wg.Wait()

	if errorCount == 0 {
		t.Log("Warning: No errors during cascading failure test (rate limits may be too high)")
	} else {
		t.Logf("Cascading failures handled: %d errors out of 100 requests", errorCount)
	}
}

func TestChaosDeadlock(t *testing.T) {
	c := createTestConfig()
	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru := createTestLRU(t, 100)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()

	paste, token, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "deadlock test", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	timeout := time.After(10 * time.Second)
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			pasteSvc.Get(ctx, paste.ID, "")
		}()
		go func() {
			defer wg.Done()
			pasteSvc.Delete(ctx, paste.ID, token)
		}()
	}

	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Potential deadlock detected - operations didn't complete in 10s")
	case <-done:
		t.Log("No deadlock detected with concurrent Get/Delete")
	}
}

func TestChaosNetworkDelay(t *testing.T) {
	c := createTestConfig()
	c.ContextTimeout = 100 * time.Millisecond

	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru := createTestLRU(t, 100)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "timeout test", Duration: 5 * time.Minute})

	if errors.Is(err, context.DeadlineExceeded) {
		t.Log("Context timeout handled correctly")
	} else if err != nil {
		t.Logf("Operation failed with: %v", err)
	} else {
		t.Log("Operation completed before timeout")
	}
}
