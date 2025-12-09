package kms

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestKEKCache_HitMiss(t *testing.T) {

	callCount := 0
	var mu sync.Mutex

	mockAdapter := &Adapter{
		primary: &mockProvider{
			decryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				mu.Lock()
				callCount++
				mu.Unlock()

				return append([]byte("decrypted-"), ciphertext...), nil
			},
		},
	}

	cache := NewKEKCache(mockAdapter, 1*time.Hour)
	defer cache.Stop()

	ctx := context.Background()
	encryptedDEK := []byte("test-encrypted-dek")

	result1, err := cache.DecryptDEK(ctx, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("Expected 1 KMS call on cache miss, got %d", callCount)
	}
	mu.Unlock()

	result2, err := cache.DecryptDEK(ctx, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	mu.Lock()
	if callCount != 1 {
		t.Errorf("Expected still 1 KMS call on cache hit, got %d", callCount)
	}
	mu.Unlock()

	if string(result1) != string(result2) {
		t.Errorf("Cache hit returned different result")
	}
}

func TestKEKCache_Expiration(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	mockAdapter := &Adapter{
		primary: &mockProvider{
			decryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				mu.Lock()
				callCount++
				mu.Unlock()
				return []byte("decrypted"), nil
			},
		},
	}

	cache := NewKEKCache(mockAdapter, 100*time.Millisecond)
	defer cache.Stop()

	ctx := context.Background()
	encryptedDEK := []byte("test-dek")

	_, err := cache.DecryptDEK(ctx, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	_, err = cache.DecryptDEK(ctx, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	mu.Lock()

	if callCount < 1 || callCount > 2 {
		t.Errorf("Expected 1-2 KMS calls, got %d", callCount)
	}
	mu.Unlock()
}

func TestKEKCache_ConcurrentAccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	mockAdapter := &Adapter{
		primary: &mockProvider{
			decryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {

				time.Sleep(50 * time.Millisecond)
				mu.Lock()
				callCount++
				mu.Unlock()
				return []byte("decrypted"), nil
			},
		},
	}

	cache := NewKEKCache(mockAdapter, 1*time.Hour)
	defer cache.Stop()

	ctx := context.Background()
	encryptedDEK := []byte("test-dek")

	var wg sync.WaitGroup
	numRequests := 10

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.DecryptDEK(ctx, encryptedDEK)
			if err != nil {
				t.Errorf("DecryptDEK failed: %v", err)
			}
		}()
	}

	wg.Wait()

	mu.Lock()
	if callCount != 1 {
		t.Errorf("Expected 1 KMS call (single-flight), got %d", callCount)
	}
	mu.Unlock()
}

func TestKEKCache_DifferentDEKs(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	mockAdapter := &Adapter{
		primary: &mockProvider{
			decryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				mu.Lock()
				callCount++
				mu.Unlock()
				return append([]byte("decrypted-"), ciphertext...), nil
			},
		},
	}

	cache := NewKEKCache(mockAdapter, 1*time.Hour)
	defer cache.Stop()

	ctx := context.Background()

	dek1 := []byte("dek1")
	dek2 := []byte("dek2")

	_, err := cache.DecryptDEK(ctx, dek1)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	_, err = cache.DecryptDEK(ctx, dek2)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}

	mu.Lock()
	if callCount != 2 {
		t.Errorf("Expected 2 KMS calls for different DEKs, got %d", callCount)
	}
	mu.Unlock()
}

func TestKEKCache_Stop(t *testing.T) {
	mockAdapter := &Adapter{
		primary: &mockProvider{
			decryptFunc: func(ctx context.Context, ciphertext []byte) ([]byte, error) {
				return []byte("decrypted"), nil
			},
		},
	}

	cache := NewKEKCache(mockAdapter, 1*time.Hour)

	ctx := context.Background()
	_, _ = cache.DecryptDEK(ctx, []byte("dek1"))
	_, _ = cache.DecryptDEK(ctx, []byte("dek2"))

	stats := cache.Stats()
	if stats.Entries != 2 {
		t.Errorf("Expected 2 cache entries, got %d", stats.Entries)
	}

	cache.Stop()

	stats = cache.Stats()
	if stats.Entries != 0 {
		t.Errorf("Expected 0 cache entries after stop, got %d", stats.Entries)
	}
}

type mockProvider struct {
	decryptFunc func(ctx context.Context, ciphertext []byte) ([]byte, error)
}

func (m *mockProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (m *mockProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, ciphertext)
	}
	return ciphertext, nil
}

func (m *mockProvider) EncryptWithContext(ctx context.Context, plaintext []byte, encContext []byte) ([]byte, error) {
	return plaintext, nil
}

func (m *mockProvider) DecryptWithContext(ctx context.Context, ciphertext []byte, encContext []byte) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(ctx, ciphertext)
	}
	return ciphertext, nil
}

func (m *mockProvider) GetSecret(ctx context.Context, key string) (string, error) {
	return "secret", nil
}
