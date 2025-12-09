package kms_test

import (
	"context"
	"drylax/pkg/kms"
	"testing"
)

func TestEncryptionContextAAD(t *testing.T) {
	t.Setenv("KMS_LOCAL_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	adapter, err := kms.NewAdapter(context.Background())
	if err != nil {
		t.Fatalf("Failed to create adapter: %v", err)
	}
	plaintext := []byte("sensitive user data")

	t.Run("Matching context succeeds", func(t *testing.T) {
		ctx := kms.EncryptionContext{
			"user_id":  "user123",
			"paste_id": "paste456",
		}
		ciphertext, err := adapter.EncryptWithContext(context.Background(), plaintext, ctx)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		decrypted, err := adapter.DecryptWithContext(context.Background(), ciphertext, ctx)
		if err != nil {
			t.Fatalf("Decryption with correct context failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Decrypted data mismatch: got %q, want %q", decrypted, plaintext)
		}

		t.Log("Encryption/decryption with matching context succeeded")
	})

	t.Run("Different context fails (confused deputy)", func(t *testing.T) {
		ctxA := kms.EncryptionContext{
			"user_id":  "alice",
			"paste_id": "paste123",
		}

		ciphertext, err := adapter.EncryptWithContext(context.Background(), plaintext, ctxA)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		ctxB := kms.EncryptionContext{
			"user_id":  "bob",
			"paste_id": "paste123",
		}

		decrypted, err := adapter.DecryptWithContext(context.Background(), ciphertext, ctxB)

		if err == nil {
			t.Error("CRITICAL: Decryption succeeded with different context (confused deputy vulnerability)")
			t.Logf("Attacker (bob) decrypted alice's data: %q", decrypted)
		} else {
			t.Logf("Confused deputy attack prevented: %v", err)
		}
	})

	t.Run("Missing context fails", func(t *testing.T) {
		ctx := kms.EncryptionContext{
			"user_id": "user123",
		}

		ciphertext, err := adapter.EncryptWithContext(context.Background(), plaintext, ctx)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := adapter.Decrypt(context.Background(), ciphertext)

		if err == nil {
			t.Error("CRITICAL: Decryption succeeded without context")
			t.Logf("Data decrypted without AAD: %q", decrypted)
		} else {
			t.Logf("Decryption without context failed: %v", err)
		}
	})

	t.Run("Legacy methods without context", func(t *testing.T) {
		ciphertext, err := adapter.Encrypt(context.Background(), plaintext)
		if err != nil {
			t.Fatalf("Legacy encryption failed: %v", err)
		}

		decrypted, err := adapter.Decrypt(context.Background(), ciphertext)
		if err != nil {
			t.Fatalf("Legacy decryption failed: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Legacy decryption mismatch: got %q, want %q", decrypted, plaintext)
		}

		t.Log("Legacy API (without context) still works")
	})

	t.Run("Context key ordering is deterministic", func(t *testing.T) {
		ctx1 := kms.EncryptionContext{
			"a": "1",
			"z": "26",
			"m": "13",
		}

		ctx2 := kms.EncryptionContext{
			"z": "26",
			"a": "1",
			"m": "13",
		}

		ciphertext1, _ := adapter.EncryptWithContext(context.Background(), plaintext, ctx1)
		ciphertext2, _ := adapter.EncryptWithContext(context.Background(), plaintext, ctx2)

		_, err1 := adapter.DecryptWithContext(context.Background(), ciphertext1, ctx2)
		_, err2 := adapter.DecryptWithContext(context.Background(), ciphertext2, ctx1)

		if err1 != nil || err2 != nil {
			t.Errorf("Context ordering not deterministic: err1=%v, err2=%v", err1, err2)
		} else {
			t.Log("Context serialization is deterministic (key order doesn't matter)")
		}
	})
}
