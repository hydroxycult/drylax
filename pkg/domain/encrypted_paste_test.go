package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEncryptedPasteV2_Marshal(t *testing.T) {
	now := time.Now()
	expiry := now.Add(24 * time.Hour)

	blob := NewEncryptedPasteV2("test content", now, expiry)

	jsonData, err := json.Marshal(blob)
	if err != nil {
		t.Fatalf("Failed to marshal blob: %v", err)
	}

	var unmarshaled EncryptedPasteV2
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal blob: %v", err)
	}

	if unmarshaled.Content != "test content" {
		t.Errorf("Content mismatch: got %s, want test content", unmarshaled.Content)
	}

	if unmarshaled.Version != 2 {
		t.Errorf("Version mismatch: got %d, want 2", unmarshaled.Version)
	}

	if !unmarshaled.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt mismatch")
	}

	if !unmarshaled.ExpiresAt.Equal(expiry) {
		t.Errorf("ExpiresAt mismatch")
	}

	if unmarshaled.Views != 0 {
		t.Errorf("Views should be 0, got %d", unmarshaled.Views)
	}
}

func TestEncryptedPasteV2_Version(t *testing.T) {
	blob := NewEncryptedPasteV2("test", time.Now(), time.Now().Add(time.Hour))

	if blob.Version != 2 {
		t.Errorf("Version should always be 2 for v2 format, got %d", blob.Version)
	}
}
