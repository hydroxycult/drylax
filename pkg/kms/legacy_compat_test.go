package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"
)

func TestLegacyCompatibility(t *testing.T) {
	t.Run("EnvProvider Binary Compatibility", func(t *testing.T) {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		keyStr := base64.StdEncoding.EncodeToString(key)

		p, err := newEnvProvider(keyStr)
		if err != nil {
			t.Fatalf("Failed to create provider: %v", err)
		}

		plaintext := []byte("legacy data verification")

		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		io.ReadFull(rand.Reader, nonce)

		legacyCiphertext := gcm.Seal(nonce, nonce, plaintext, nil)

		decrypted, err := p.DecryptWithContext(context.Background(), legacyCiphertext, nil)
		if err != nil {
			t.Fatalf("Failed to decrypt legacy data with new code: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted legacy data mismatch: got %q, want %q", decrypted, plaintext)
		}

		newCiphertext, err := p.EncryptWithContext(context.Background(), plaintext, nil)
		if err != nil {
			t.Fatalf("Failed to encrypt with nil context: %v", err)
		}

		nonceSize := gcm.NonceSize()
		if len(newCiphertext) < nonceSize {
			t.Fatal("New ciphertext too short")
		}
		newNonce := newCiphertext[:nonceSize]
		newEncrypted := newCiphertext[nonceSize:]

		standardDecrypted, err := gcm.Open(nil, newNonce, newEncrypted, nil)
		if err != nil {
			t.Fatalf("Old code failed to decrypt new nil-context data: %v", err)
		}

		if string(standardDecrypted) != string(plaintext) {
			t.Errorf("Old code decrypted mismatch: got %q, want %q", standardDecrypted, plaintext)
		}

		t.Log("EnvProvider is 100% backward compatible")
	})
}
