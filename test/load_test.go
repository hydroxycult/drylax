package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"drylax/svc/api"
	"drylax/svc/lim"
	"drylax/svc/svc"
	"drylax/svc/util"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type LoadTestMetrics struct {
	TotalRequests   int64
	SuccessCount    int64
	ErrorCount      int64
	Latencies       []time.Duration
	MemoryGrowthMB  float64
	GoroutineGrowth int
	mu              sync.Mutex
}

func (m *LoadTestMetrics) RecordLatency(d time.Duration) {
	m.mu.Lock()
	m.Latencies = append(m.Latencies, d)
	m.mu.Unlock()
}

func (m *LoadTestMetrics) Percentile(p float64) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.Latencies) == 0 {
		return 0
	}

	idx := int(float64(len(m.Latencies)) * p / 100.0)
	if idx >= len(m.Latencies) {
		idx = len(m.Latencies) - 1
	}
	return m.Latencies[idx]
}

func setupLoadTestServer(t *testing.T) (*httptest.Server, *LoadTestMetrics, func()) {
	util.InitLog("error", false)

	c := createTestConfig()

	if c.RateLimit.RPM < 100000 {
		c.RateLimit.RPM = 100000
		c.RateLimit.Burst = 10000
		c.RateLimit.ConservativeLimit = 50000
	}

	sqlDB := createTestDB(t, c)
	lru := createTestLRU(t, c.LRUCacheSize)
	hasher := createTestHasher(t, c)
	kmsAdapter := createTestKMS(t)

	t.Logf("KMS adapter created successfully")

	util.StopIPHasher()
	if err := util.InitIPHasher([]byte(c.Pepper.Value()), c.IPHashRotationInterval); err != nil {
		t.Fatalf("Failed to initialize IP hasher: %v", err)
	}

	limiter := lim.New(c.RateLimit.RPM, c.RateLimit.Burst, c.RateLimit.ConservativeLimit, nil, nil)
	pasteSvc := svc.NewPaste(sqlDB, lru, nil, hasher, kmsAdapter, c)
	server := api.NewServer(c, pasteSvc, limiter, sqlDB, nil)

	ts := httptest.NewServer(server)
	t.Logf("Test server started at %s", ts.URL)

	metrics := &LoadTestMetrics{
		Latencies: make([]time.Duration, 0, 100000),
	}

	cleanup := func() {
		ts.Close()
		pasteSvc.Shutdown()
		hasher.Stop()
		util.StopIPHasher()
		sqlDB.Close()
	}

	return ts, metrics, cleanup
}

func TestLoadRampUp(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping load test in short mode")
	}

	ts, metrics, cleanup := setupLoadTestServer(t)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	targetRPS := 100
	rampDuration := 30 * time.Second
	testDuration := 60 * time.Second

	startTime := time.Now()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var wg sync.WaitGroup
	goroutineStart := runtime.NumGoroutine()
	var memStart runtime.MemStats
	runtime.ReadMemStats(&memStart)

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			t.Fatal("Test timeout")
		case <-ticker.C:
			elapsed := time.Since(startTime)
			if elapsed > testDuration {
				wg.Wait()
				goto done
			}

			var currentRPS int
			if elapsed < rampDuration {
				currentRPS = int(float64(targetRPS) * elapsed.Seconds() / rampDuration.Seconds())
			} else {
				currentRPS = targetRPS
			}

			requestsThisTick := currentRPS / 100
			for i := 0; i < requestsThisTick; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					makeCreatePasteRequest(t, ts.URL, metrics, 100)
				}()
			}
		}
	}

done:
	var memEnd runtime.MemStats
	runtime.ReadMemStats(&memEnd)
	goroutineEnd := runtime.NumGoroutine()

	metrics.MemoryGrowthMB = float64(memEnd.Alloc-memStart.Alloc) / 1024 / 1024
	metrics.GoroutineGrowth = goroutineEnd - goroutineStart

	errorRate := float64(metrics.ErrorCount) / float64(metrics.TotalRequests) * 100
	if errorRate > 0.1 {
		t.Errorf("Error rate %.2f%% exceeds threshold of 0.1%%", errorRate)
	}

	p99 := metrics.Percentile(99)
	if p99 > 500*time.Millisecond {
		t.Errorf("P99 latency %v exceeds 500ms threshold", p99)
	}

	t.Logf("Ramp test results:")
	t.Logf("  Total requests: %d", metrics.TotalRequests)
	t.Logf("  Success: %d, Errors: %d (%.2f%%)", metrics.SuccessCount, metrics.ErrorCount, errorRate)
	t.Logf("  P50: %v, P95: %v, P99: %v", metrics.Percentile(50), metrics.Percentile(95), p99)
	t.Logf("  Memory growth: %.2f MB", metrics.MemoryGrowthMB)
	t.Logf("  Goroutine growth: %d", metrics.GoroutineGrowth)
}

func TestLoadSustained(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping sustained load test in short mode")
	}

	ts, metrics, cleanup := setupLoadTestServer(t)
	defer cleanup()

	targetRPS := 50
	duration := 2 * time.Minute
	tickInterval := 10 * time.Millisecond

	var wg sync.WaitGroup
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()

	deadline := time.Now().Add(duration)
	requestsPerTick := targetRPS / 100

	var memorySamples []float64
	memTicker := time.NewTicker(30 * time.Second)
	defer memTicker.Stop()

	go func() {
		for range memTicker.C {
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			memorySamples = append(memorySamples, float64(mem.Alloc)/1024/1024)
		}
	}()

	for time.Now().Before(deadline) {
		<-ticker.C
		for i := 0; i < requestsPerTick; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				makeCreatePasteRequest(t, ts.URL, metrics, 1024)
			}()
		}
	}

	wg.Wait()

	if len(memorySamples) > 1 {
		growthRate := (memorySamples[len(memorySamples)-1] - memorySamples[0]) / float64(len(memorySamples))
		if growthRate > 5.0 {
			t.Errorf("Memory growth rate %.2f MB/sample exceeds threshold", growthRate)
		}
		t.Logf("Memory growth rate: %.2f MB/sample", growthRate)
	}

	errorRate := float64(metrics.ErrorCount) / float64(metrics.TotalRequests) * 100
	if errorRate > 0.1 {
		t.Errorf("Error rate %.2f%% exceeds threshold", errorRate)
	}

	t.Logf("Sustained load test results:")
	t.Logf("  Duration: %v, Target RPS: %d", duration, targetRPS)
	t.Logf("  Total requests: %d", metrics.TotalRequests)
	t.Logf("  Success: %d, Errors: %d (%.2f%%)", metrics.SuccessCount, metrics.ErrorCount, errorRate)
	t.Logf("  P50: %v, P95: %v, P99: %v, P999: %v",
		metrics.Percentile(50), metrics.Percentile(95), metrics.Percentile(99), metrics.Percentile(99.9))
}

func TestLoadSpikes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping spike test in short mode")
	}

	ts, metrics, cleanup := setupLoadTestServer(t)
	defer cleanup()

	baselineRPS := 10
	spikeRPS := 100
	spikeDuration := 5 * time.Second
	spikeInterval := 30 * time.Second
	totalDuration := 2 * time.Minute

	var wg sync.WaitGroup
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	deadline := time.Now().Add(totalDuration)
	startTime := time.Now()

	for time.Now().Before(deadline) {
		<-ticker.C
		elapsed := time.Since(startTime)

		cyclePosition := int(elapsed.Seconds()) % int(spikeInterval.Seconds())
		var currentRPS int
		if cyclePosition < int(spikeDuration.Seconds()) {
			currentRPS = spikeRPS
		} else {
			currentRPS = baselineRPS
		}

		requestsPerTick := currentRPS / 100
		for i := 0; i < requestsPerTick; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				makeCreatePasteRequest(t, ts.URL, metrics, 512)
			}()
		}
	}

	wg.Wait()

	errorRate := float64(metrics.ErrorCount) / float64(metrics.TotalRequests) * 100
	if errorRate > 1.0 {
		t.Errorf("Error rate %.2f%% exceeds 1.0%% threshold", errorRate)
	}

	t.Logf("Spike test results:")
	t.Logf("  Baseline RPS: %d, Spike RPS: %d", baselineRPS, spikeRPS)
	t.Logf("  Total requests: %d", metrics.TotalRequests)
	t.Logf("  P99: %v, P999: %v", metrics.Percentile(99), metrics.Percentile(99.9))
}

func TestLoadBinaryContent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping binary content test in short mode")
	}

	ts, metrics, cleanup := setupLoadTestServer(t)
	defer cleanup()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			size := 1024 + (idx * 100)
			randomData := make([]byte, size)
			rand.Read(randomData)

			body := map[string]string{"content": string(randomData)}
			jsonBody, _ := json.Marshal(body)

			start := time.Now()
			req, _ := http.NewRequest("POST", ts.URL+"/pastes", bytes.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")

			resp, err := http.DefaultClient.Do(req)
			latency := time.Since(start)

			atomic.AddInt64(&metrics.TotalRequests, 1)
			metrics.RecordLatency(latency)

			if err != nil || resp.StatusCode >= 400 {
				atomic.AddInt64(&metrics.ErrorCount, 1)
			} else {
				atomic.AddInt64(&metrics.SuccessCount, 1)
			}

			if resp != nil {
				io.ReadAll(resp.Body)
				resp.Body.Close()
			}
		}(i)
	}

	wg.Wait()

	errorRate := float64(metrics.ErrorCount) / float64(metrics.TotalRequests) * 100
	t.Logf("Binary content test: %d requests, %.2f%% errors", metrics.TotalRequests, errorRate)

	if errorRate > 10.0 {
		t.Errorf("Error rate %.2f%% too high for binary content", errorRate)
	}
}

func makeCreatePasteRequest(t *testing.T, baseURL string, metrics *LoadTestMetrics, contentSize int) {
	content := make([]byte, contentSize)
	for i := range content {
		content[i] = byte('a' + (i % 26))
	}

	body := map[string]string{"content": string(content)}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		atomic.AddInt64(&metrics.ErrorCount, 1)
		return
	}

	start := time.Now()
	resp, err := http.Post(baseURL+"/pastes", "application/json", bytes.NewReader(jsonBody))
	latency := time.Since(start)

	atomic.AddInt64(&metrics.TotalRequests, 1)
	metrics.RecordLatency(latency)

	if err != nil || resp == nil {
		atomic.AddInt64(&metrics.ErrorCount, 1)
		return
	}
	defer resp.Body.Close()

	io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusCreated {
		atomic.AddInt64(&metrics.SuccessCount, 1)
	} else {
		atomic.AddInt64(&metrics.ErrorCount, 1)
	}
}
