package domain
import (
	"time"
)
type EncryptedPasteV2 struct {
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Views     int       `json:"views"`
	MaxViews  int       `json:"max_views,omitempty"` 
	Version   int       `json:"version"`
}
func NewEncryptedPasteV2(content string, createdAt, expiresAt time.Time) *EncryptedPasteV2 {
	return &EncryptedPasteV2{
		Content:   content,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		Views:     0,
		Version:   2,
	}
}
