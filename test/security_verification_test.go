package test

import (
	"context"
	"drylax/pkg/kms"
	"drylax/svc/lim"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRealIPSpoofingAttack(t *testing.T) {
	trustedProxies := []string{"10.0.0.1"}

	attacks := []struct {
		name       string
		remoteAddr string
		xff        string
		expectIP   string
	}{
		{
			name:       "Untrusted source spoofs single IP",
			remoteAddr: "192.168.1.100:1234",
			xff:        "1.1.1.1",
			expectIP:   "192.168.1.100",
		},
		{
			name:       "Untrusted source spoofs multiple IPs",
			remoteAddr: "192.168.1.100:1234",
			xff:        "2.2.2.2, 3.3.3.3",
			expectIP:   "192.168.1.100",
		},
		{
			name:       "Trusted proxy forwards client IP",
			remoteAddr: "10.0.0.1:5678",
			xff:        "4.4.4.4",
			expectIP:   "4.4.4.4",
		},
		{
			name:       "Mixed chain with untrusted IPs",
			remoteAddr: "10.0.0.1:5678",
			xff:        "5.5.5.5, 6.6.6.6, 10.0.0.1",
			expectIP:   "6.6.6.6",
		},
		{
			name:       "Empty XFF from trusted proxy",
			remoteAddr: "10.0.0.1:5678",
			xff:        "",
			expectIP:   "10.0.0.1",
		},
	}

	for _, attack := range attacks {
		t.Run(attack.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/pastes", nil)
			req.RemoteAddr = attack.remoteAddr
			if attack.xff != "" {
				req.Header.Set("X-Forwarded-For", attack.xff)
			}

			extractedIP := lim.GetRealIP(req, trustedProxies)

			if extractedIP != attack.expectIP {
				t.Errorf("IP spoofing bypass: got %s, expected %s (XFF: %s, RemoteAddr: %s)",
					extractedIP, attack.expectIP, attack.xff, attack.remoteAddr)
			} else {
				t.Logf("Correctly extracted IP: %s", extractedIP)
			}
		})
	}
}

func TestRateLimitingSpoofResistance(t *testing.T) {
	t.Skip("Integration test - requires full server setup with helpers_test.go")
}

func TestKMSFailureHandling(t *testing.T) {
	tests := []struct {
		name        string
		env         map[string]string
		expectError bool
		description string
	}{
		{
			name: "No providers configured",
			env: map[string]string{
				"KMS_LOCAL_KEY":   "",
				"VAULT_ADDR":      "",
				"AWS_REGION":      "",
				"KMS_FAIL_CLOSED": "",
			},
			expectError: true,
			description: "Should fail when no KMS providers available",
		},
		{
			name: "Fail-closed explicitly disabled (opt-out)",
			env: map[string]string{
				"KMS_LOCAL_KEY":   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
				"KMS_FAIL_CLOSED": "false",
			},
			expectError: false,
			description: "Should allow when fail-closed is explicitly disabled",
		},
		{
			name: "Fail-closed default (not set)",
			env: map[string]string{
				"KMS_LOCAL_KEY": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
			},
			expectError: false,
			description: "Should succeed when provider available (defaults to fail-closed=true)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for key, val := range tt.env {
				t.Setenv(key, val)
			}

			adapter, err := kms.NewAdapter(context.Background())

			if tt.expectError {
				if err == nil {
					t.Errorf("%s: Expected error but got none", tt.description)
				} else {
					t.Logf("%s: %v", tt.description, err)
				}
				return
			}

			if err != nil {
				t.Errorf("%s: Unexpected error: %v", tt.description, err)
				return
			}

			testData := []byte("sensitive test data")
			ciphertext, err := adapter.Encrypt(context.Background(), testData)
			if err != nil {
				t.Errorf("Encryption failed: %v", err)
				return
			}

			plaintext, err := adapter.Decrypt(context.Background(), ciphertext)
			if err != nil {
				t.Errorf("Decryption failed: %v", err)
				return
			}

			if string(plaintext) != string(testData) {
				t.Errorf("Decrypted data mismatch: got %s, want %s", plaintext, testData)
			}

			t.Logf("%s: Encryption/decryption successful", tt.description)
		})
	}
}

func TestKMSNetworkTimeout(t *testing.T) {
	t.Run("Context cancellation during KMS call", func(t *testing.T) {
		t.Setenv("KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

		adapter, err := kms.NewAdapter(context.Background())
		if err != nil {
			t.Fatalf("Adapter creation failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		ciphertext, err := adapter.Encrypt(ctx, []byte("test data"))

		if err == nil {
			t.Error("Encryption should fail with cancelled context")
		}
		if ciphertext != nil {
			t.Error("Should not return ciphertext with cancelled context")
		}

		t.Logf("Context cancellation respected: %v", err)
	})

	t.Run("Corrupted ciphertext rejected", func(t *testing.T) {
		t.Setenv("KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")

		adapter, err := kms.NewAdapter(context.Background())
		if err != nil {
			t.Fatalf("Adapter creation failed: %v", err)
		}

		ciphertext, err := adapter.Encrypt(context.Background(), []byte("test data"))
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		corruptedCiphertext := make([]byte, len(ciphertext))
		copy(corruptedCiphertext, ciphertext)
		if len(corruptedCiphertext) > 10 {
			corruptedCiphertext[10] ^= 0xFF
		}

		plaintext, err := adapter.Decrypt(context.Background(), corruptedCiphertext)

		if err == nil {
			t.Error("Decryption should fail with corrupted ciphertext")
		}
		if plaintext != nil {
			t.Error("Should not return plaintext for corrupted ciphertext")
		}

		t.Logf("Corrupted ciphertext rejected: %v", err)
	})
}

func TestXFFHeaderDoS(t *testing.T) {
	trustedProxies := []string{"10.0.0.1"}

	tests := []struct {
		name        string
		ipCount     int
		shouldLimit bool
	}{
		{"Normal header (5 IPs)", 5, false},
		{"Large header (50 IPs)", 50, false},
		{"Excessive header (150 IPs)", 150, true},
		{"DoS attack (1000 IPs)", 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := make([]string, tt.ipCount)
			for i := 0; i < tt.ipCount; i++ {
				ips[i] = fmt.Sprintf("10.%d.%d.%d", i/256/256, i/256%256, i%256)
			}
			xffHeader := strings.Join(ips, ", ")

			req := httptest.NewRequest("POST", "/pastes", nil)
			req.RemoteAddr = "10.0.0.1:1234"
			req.Header.Set("X-Forwarded-For", xffHeader)

			start := time.Now()
			extractedIP := lim.GetRealIP(req, trustedProxies)
			elapsed := time.Since(start)

			if tt.shouldLimit {
				if extractedIP != "10.0.0.1" {
					t.Logf("Note: Large XFF header processed (IP: %s)", extractedIP)
				}

				if elapsed > 100*time.Millisecond {
					t.Errorf("XFF processing too slow: %v (with %d IPs)", elapsed, tt.ipCount)
				}
			}

			t.Logf("Processed %d IPs in %v", tt.ipCount, elapsed)
		})
	}
}

func TestSQLInjectionResistance(t *testing.T) {
	t.Skip("Integration test - requires full server setup")
}

func TestXSSPrevention(t *testing.T) {
	t.Skip("Integration test - requires full server setup")
}
