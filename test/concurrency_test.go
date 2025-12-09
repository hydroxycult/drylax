package test

import (
	"context"
	"drylax/pkg/domain"
	"drylax/svc/svc"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConcurrencyRaceDetection(t *testing.T) {

	c := createTestConfig()
	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru := createTestLRU(t, 1000)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, _, _ = pasteSvc.Create(ctx, domain.CreateParams{Content: "concurrent content", Duration: 5 * time.Minute})
		}(i)
	}

	wg.Wait()
	t.Log("Race detection test completed (run with -race flag)")
}

func TestConcurrentSameIDCreation(t *testing.T) {
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
	var wg sync.WaitGroup
	successCount := int64(0)
	errorCount := int64(0)

	numGoroutines := 1000
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "test", Duration: 5 * time.Minute})
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	t.Logf("Concurrent creation: %d success, %d errors out of %d",
		successCount, errorCount, numGoroutines)

	if errorCount > 0 {
		t.Logf("Warning: %d errors during concurrent creation", errorCount)
	}
}

func TestConcurrentDeleteSamePaste(t *testing.T) {
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

	paste, token, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "delete me", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	successCount := int64(0)
	errorCount := int64(0)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := pasteSvc.Delete(ctx, paste.ID, token)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)

				if atomic.LoadInt64(&errorCount) == 1 {
					t.Logf("Deletion error: %v", err)
				}
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()

	t.Logf("Concurrent deletion: %d success, %d errors", successCount, errorCount)

	if successCount == 0 {
		t.Error("No successful deletions (expected at least one)")
	}
}

func TestConcurrentReadWrite(t *testing.T) {
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

	paste, _, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "initial", Duration: 5 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stopChan := make(chan struct{})

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					pasteSvc.Get(ctx, paste.ID, "")
				}
			}
		}()
	}

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopChan:
					return
				default:
					pasteSvc.Create(ctx, domain.CreateParams{Content: "concurrent write", Duration: 5 * time.Minute})
				}
			}
		}()
	}

	time.Sleep(3 * time.Second)
	close(stopChan)
	wg.Wait()

	t.Log("Concurrent read/write test completed without deadlock")
}

func TestConcurrentCacheAccess(t *testing.T) {
	lru := createTestLRU(t, 100)
	var wg sync.WaitGroup

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

		}(i)
	}

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lru.Get(context.Background(), "key")
		}()
	}

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lru.Delete("key")
		}()
	}

	wg.Wait()
	t.Log("Concurrent cache access completed (test with -race)")
}

func TestGoroutineLeak(t *testing.T) {

	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseline := runtime.NumGoroutine()

	c := createTestConfig()
	sqlDB := createTestDB(t, createTestConfig())
	lru := createTestLRU(t, 100)
	hasher := createTestHasher(t, c)
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)

	ctx := context.Background()

	for i := 0; i < 1000; i++ {
		pasteSvc.Create(ctx, domain.CreateParams{Content: "leak test", Duration: 5 * time.Minute})
	}

	pasteSvc.Shutdown()
	hasher.Stop()
	sqlDB.Close()

	runtime.GC()
	time.Sleep(500 * time.Millisecond)

	final := runtime.NumGoroutine()
	growth := final - baseline

	t.Logf("Goroutine count: baseline=%d, final=%d, growth=%d", baseline, final, growth)

	if growth > 10 {
		t.Errorf("Possible goroutine leak: %d goroutines not cleaned up", growth)
	}
}

func TestMemoryLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	runtime.GC()
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	c := createTestConfig()
	sqlDB := createTestDB(t, createTestConfig())
	defer sqlDB.Close()
	lru := createTestLRU(t, 10000)
	hasher := createTestHasher(t, c)
	defer hasher.Stop()
	kmsAdapter := createTestKMS(t)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	defer pasteSvc.Shutdown()

	ctx := context.Background()

	for i := 0; i < 10000; i++ {
		paste, token, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "memory test", Duration: 5 * time.Minute})
		if err == nil && i%2 == 0 {
			pasteSvc.Delete(ctx, paste.ID, token)
		}
	}

	runtime.GC()
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)

	growthMB := float64(memEnd.Alloc-memStart.Alloc) / 1024 / 1024

	t.Logf("Memory growth: %.2f MB", growthMB)

	if growthMB > 100 {
		t.Errorf("Excessive memory growth: %.2f MB", growthMB)
	}
}

func TestDeadlockAvoidance(t *testing.T) {
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

	var pasteIDs []string
	var tokens []string
	for i := 0; i < 10; i++ {
		paste, token, err := pasteSvc.Create(ctx, domain.CreateParams{Content: "deadlock test", Duration: 5 * time.Minute})
		if err == nil {
			pasteIDs = append(pasteIDs, paste.ID)
			tokens = append(tokens, token)
		}
	}

	var wg sync.WaitGroup
	timeout := time.After(30 * time.Second)
	done := make(chan bool)

	for _, id := range pasteIDs {
		for j := 0; j < 10; j++ {
			wg.Add(3)
			go func(pid string, tok string) {
				defer wg.Done()
				pasteSvc.Get(ctx, pid, "")
			}(id, tokens[0])
			go func(pid string, tok string) {
				defer wg.Done()
				pasteSvc.Delete(ctx, pid, tok)
			}(id, tokens[0])
			go func() {
				defer wg.Done()
				pasteSvc.Create(ctx, domain.CreateParams{Content: "new", Duration: 5 * time.Minute})
			}()
		}
	}

	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("Deadlock detected - operations didn't complete in 30s")
	case <-done:
		t.Log("No deadlock detected with mixed concurrent operations")
	}
}

