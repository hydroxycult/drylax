package util

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIPHasherDeterministic(t *testing.T) {
	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	hasher := &IPHasher{
		rotationInterval: 1 * time.Hour,
		pepper:           pepper,
		stopChan:         make(chan struct{}),
	}
	hasher.currentEpoch = hasher.getEpoch(time.Now())
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer hasher.Stop()

	ip := "192.168.1.100"

	hash1, err := hasher.HashIP(ip)
	if err != nil {
		t.Fatalf("HashIP failed: %v", err)
	}

	hash2, err := hasher.HashIP(ip)
	if err != nil {
		t.Fatalf("HashIP failed: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("HashIP not deterministic: %s != %s", hash1, hash2)
	}

	if !strings.HasPrefix(hash1, "hmac-sha256:") {
		t.Errorf("Hash has wrong prefix: %s", hash1)
	}

	parts := strings.Split(hash1, ":")
	if len(parts) != 3 {
		t.Errorf("Hash has wrong format (expected 3 parts): %s", hash1)
	}
}

func TestIPHasherDifferentIPs(t *testing.T) {
	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	hasher := &IPHasher{
		rotationInterval: 1 * time.Hour,
		pepper:           pepper,
		stopChan:         make(chan struct{}),
	}
	hasher.currentEpoch = hasher.getEpoch(time.Now())
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer hasher.Stop()

	ip1 := "192.168.1.100"
	ip2 := "10.0.0.50"

	hash1, _ := hasher.HashIP(ip1)
	hash2, _ := hasher.HashIP(ip2)

	if hash1 == hash2 {
		t.Errorf("Different IPs produced same hash: %s", hash1)
	}
}

func TestIPHasherKeyRotation(t *testing.T) {
	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	hasher := &IPHasher{
		rotationInterval: 1 * time.Second,
		pepper:           pepper,
		stopChan:         make(chan struct{}),
	}
	hasher.currentEpoch = hasher.getEpoch(time.Now())
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer hasher.Stop()

	ip := "192.168.1.100"
	hash1, _ := hasher.HashIP(ip)
	epoch1 := hasher.currentEpoch

	time.Sleep(2 * time.Second)

	newEpoch := hasher.getEpoch(time.Now())
	hasher.mu.Lock()
	hasher.currentEpoch = newEpoch
	hasher.mu.Unlock()
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to rotate keys: %v", err)
	}

	hash2, _ := hasher.HashIP(ip)

	if hash1 == hash2 {
		t.Errorf("Hash didn't change after key rotation. Epoch1: %d, Epoch2: %d", epoch1, newEpoch)
	}

	verified, err := hasher.VerifyIPHash(ip, hash2)
	if err != nil {
		t.Fatalf("VerifyIPHash failed for current hash: %v", err)
	}
	if !verified {
		t.Errorf("Current hash not verified")
	}
}

func TestIPHasherConcurrency(t *testing.T) {
	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	hasher := &IPHasher{
		rotationInterval: 1 * time.Hour,
		pepper:           pepper,
		stopChan:         make(chan struct{}),
	}
	hasher.currentEpoch = hasher.getEpoch(time.Now())
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	defer hasher.Stop()

	var wg sync.WaitGroup
	results := make(chan string, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hash, err := hasher.HashIP("192.168.1.100")
			if err != nil {
				t.Errorf("HashIP failed: %v", err)
				return
			}
			results <- hash
		}(i)
	}

	wg.Wait()
	close(results)

	var first string
	count := 0
	for hash := range results {
		if first == "" {
			first = hash
		}
		if hash != first {
			t.Errorf("Concurrent hashing produced different results")
		}
		count++
	}

	if count != 100 {
		t.Errorf("Expected 100 results, got %d", count)
	}
}

func TestIPHasherStop(t *testing.T) {
	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	hasher := &IPHasher{
		rotationInterval: 1 * time.Hour,
		pepper:           pepper,
		stopChan:         make(chan struct{}),
	}
	hasher.currentEpoch = hasher.getEpoch(time.Now())
	if err := hasher.generateKeys(); err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}

	hasher.Stop()

	_, err := hasher.HashIP("192.168.1.100")
	if err != ErrHasherStopped {
		t.Errorf("Expected ErrHasherStopped, got: %v", err)
	}

	if hasher.currentKey != nil {
		t.Errorf("Current key not wiped after stop")
	}
	if hasher.previousKey != nil {
		t.Errorf("Previous key not wiped after stop")
	}
	if hasher.nextKey != nil {
		t.Errorf("Next key not wiped after stop")
	}
}

func TestGlobalIPHasherInit(t *testing.T) {

	globalIPHasher = nil
	ipHasherOnce = sync.Once{}

	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	err := InitIPHasher(pepper, 1*time.Hour)
	if err != nil {
		t.Fatalf("InitIPHasher failed: %v", err)
	}
	defer StopIPHasher()

	hasher, err := GetIPHasher()
	if err != nil {
		t.Fatalf("GetIPHasher failed: %v", err)
	}

	hash, err := hasher.HashIP("192.168.1.100")
	if err != nil {
		t.Fatalf("HashIP failed: %v", err)
	}

	if !strings.HasPrefix(hash, "hmac-sha256:") {
		t.Errorf("Hash has wrong format: %s", hash)
	}

	globalIPHasher = nil
	ipHasherOnce = sync.Once{}
}

func TestIPHasherInvalidConfig(t *testing.T) {

	globalIPHasher = nil
	ipHasherOnce = sync.Once{}
	defer func() {
		globalIPHasher = nil
		ipHasherOnce = sync.Once{}
	}()

	shortPepper := []byte("short")
	err := InitIPHasher(shortPepper, 1*time.Hour)
	if err == nil {
		t.Error("Expected error for short pepper")
	}

	globalIPHasher = nil
	ipHasherOnce = sync.Once{}

	pepper := []byte("test-pepper-must-be-at-least-32bytes-long-for-security")
	err = InitIPHasher(pepper, 5*time.Minute)
	if err != ErrInvalidInterval {
		t.Errorf("Expected ErrInvalidInterval, got: %v", err)
	}
}
