package domain
import (
	"time"
)
type Paste struct {
	ID                string    `json:"id"`
	Content           string    `json:"content"`
	EncryptedContent  []byte    `json:"-"` 
	EncryptedBlob     []byte    `json:"-"` 
	EncryptedDEK      []byte    `json:"-"`
	Hash              string    `json:"-"`
	DeletionTokenHash string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"` 
	ExpiresAt         time.Time `json:"expires_at"` 
	Views             int       `json:"views"`
	ClientIPHash      string    `json:"-"`
	FormatVersion     int       `json:"-"`
}
type CreateParams struct {
	Content      string
	Password     string
	Duration     time.Duration
	ClientIPHash string 
}
