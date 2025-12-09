package util

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (

	ErrTokenExpired   = errors.New("deletion token expired")
	ErrTokenForged    = errors.New("deletion token signature invalid")
	ErrTokenMalformed = errors.New("deletion token malformed")
	ErrTokenUsed      = errors.New("deletion token already used")
	tokenSecretKey    []byte
	tokenMu           sync.RWMutex
	usedTokens        UsedTokenTracker
	tokenReplayTTL    = 24 * time.Hour
)

type UsedTokenTracker interface {
	MarkUsed(ctx context.Context, tokenHash string, ttl time.Duration) error
	IsUsed(ctx context.Context, tokenHash string) (bool, error)
}

func InitDeletionTokenKey(secret []byte) error {
	if err := validateKeyEntropy(secret); err != nil {
		return err
	}
	tokenMu.Lock()
	tokenSecretKey = secret
	tokenMu.Unlock()
	return nil
}
func SetUsedTokenTracker(tracker UsedTokenTracker) {
	tokenMu.Lock()
	usedTokens = tracker
	tokenMu.Unlock()
}
func UpdateDeletionTokenKey(secret []byte) error {
	if err := validateKeyEntropy(secret); err != nil {
		return err
	}
	tokenMu.Lock()
	tokenSecretKey = secret
	tokenMu.Unlock()
	return nil
}
func validateKeyEntropy(secret []byte) error {
	if len(secret) < 32 {
		return errors.New("deletion token key must be at least 32 bytes")
	}
	unique := make(map[byte]struct{})
	for _, b := range secret {
		unique[b] = struct{}{}
	}
	if len(unique) < 16 {
		return errors.New("deletion token key has insufficient entropy (too many repeating bytes)")
	}
	return nil
}
func SetTokenReplayTTL(ttl time.Duration) {
	if ttl < 1*time.Minute {
		panic("token replay TTL must be at least 1 minute")
	}
	tokenMu.Lock()
	tokenReplayTTL = ttl
	tokenMu.Unlock()
}
func GenerateDeletionToken(pasteID string, validFor time.Duration) (string, error) {
	start := time.Now()
	defer normalizeTokenTiming(start)
	tokenMu.RLock()
	key := tokenSecretKey
	tokenMu.RUnlock()
	if key == nil {
		return "", errors.New("deletion token key not initialized")
	}
	jitter := int64(validFor) / 10
	if jitter <= 0 {
		jitter = 1
	}
	jitterVal := randomInt63(jitter*2) - jitter
	adjustedValidFor := validFor + time.Duration(jitterVal)
	expiry := time.Now().Add(adjustedValidFor).Unix()
	expiryBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiryBytes, uint64(expiry))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(pasteID))
	mac.Write(expiryBytes)
	signature := mac.Sum(nil)
	payload := make([]byte, 0, 8+len(pasteID)+32)
	payload = append(payload, expiryBytes...)
	payload = append(payload, []byte(pasteID)...)
	payload = append(payload, signature...)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := aead.Seal(nonce, nonce, payload, nil)
	return base64UrlEncode(ciphertext), nil
}
func VerifyDeletionToken(token, pasteID string) error {
	start := time.Now()
	defer normalizeTokenTiming(start)
	tokenMu.RLock()
	key := tokenSecretKey
	tracker := usedTokens
	tokenMu.RUnlock()
	if key == nil {
		performDummyCrypto()
		return errors.New("deletion token key not initialized")
	}
	valid := true
	var expiry int64
	var extractedPasteID string
	var providedMAC, expectedMAC []byte
	decoded, err := base64UrlDecode(token)
	if err != nil || len(decoded) < 24 {
		valid = false
		decoded = make([]byte, 100)
		rand.Read(decoded)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		valid = false
	}
	var plaintext []byte
	if aead != nil && len(decoded) >= aead.NonceSize() {
		nonceSize := aead.NonceSize()
		nonce := decoded[:nonceSize]
		ciphertext := decoded[nonceSize:]
		plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			valid = false
			plaintext = make([]byte, 48)
			rand.Read(plaintext)
		}
	} else {
		valid = false
		plaintext = make([]byte, 48)
		rand.Read(plaintext)
	}
	if len(plaintext) >= 40 {
		expiry = int64(binary.BigEndian.Uint64(plaintext[0:8]))
		extractedPasteID = string(plaintext[8 : len(plaintext)-32])
		providedMAC = plaintext[len(plaintext)-32:]
	} else {
		valid = false
		expiry = time.Now().Unix() + 3600
		extractedPasteID = pasteID
		providedMAC = make([]byte, 32)
		rand.Read(providedMAC)
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(extractedPasteID))
	expiryBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expiryBytes, uint64(expiry))
	mac.Write(expiryBytes)
	expectedMAC = mac.Sum(nil)
	macMatch := subtle.ConstantTimeCompare(providedMAC, expectedMAC) == 1
	pasteIDMatch := constantTimeCompareString(extractedPasteID, pasteID) == 1
	notExpired := time.Now().Unix() <= expiry

	if !valid {
		return ErrTokenMalformed
	}

	if !macMatch || !pasteIDMatch {
		return ErrTokenForged
	}

	if !notExpired {
		return ErrTokenExpired
	}
	if tracker != nil {
		tokenHash := hashToken(token)
		used, err := tracker.IsUsed(context.Background(), tokenHash)
		if err != nil {
			Error().Err(err).Msg("CRITICAL: token replay check failed")
			return errors.New("token verification temporarily unavailable")
		}
		if used {
			return ErrTokenUsed
		}
		tokenMu.RLock()
		ttl := tokenReplayTTL
		tokenMu.RUnlock()
		if err := tracker.MarkUsed(context.Background(), tokenHash, ttl); err != nil {
			Error().Err(err).Msg("CRITICAL: failed to mark token as used")
			return errors.New("token verification failed")
		}
	}
	return nil
}
func normalizeTokenTiming(start time.Time) {
	elapsed := time.Since(start)
	target := time.Duration(30+randomInt(30)) * time.Millisecond
	if elapsed < target {
		time.Sleep(target - elapsed)
	}
}
func performDummyCrypto() {
	dummy := make([]byte, 32)
	rand.Read(dummy)
	mac := hmac.New(sha256.New, dummy)
	mac.Write(dummy)
	_ = mac.Sum(nil)
}
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64UrlEncode(h[:])
}
func randomInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return int(n.Int64())
}
func randomInt63(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}
func constantTimeCompareString(a, b string) int {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}
func base64UrlEncode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	result := make([]byte, (len(data)*8+5)/6)
	var bits uint32
	var bitsLen uint
	j := 0
	for _, b := range data {
		bits = bits<<8 | uint32(b)
		bitsLen += 8
		for bitsLen >= 6 {
			bitsLen -= 6
			result[j] = alphabet[(bits>>bitsLen)&0x3F]
			j++
		}
	}
	if bitsLen > 0 {
		result[j] = alphabet[(bits<<(6-bitsLen))&0x3F]
		j++
	}
	return string(result[:j])
}
func base64UrlDecode(s string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	lookup := make(map[byte]byte)
	for i, c := range alphabet {
		lookup[byte(c)] = byte(i)
	}
	result := make([]byte, len(s)*6/8)
	var bits uint32
	var bitsLen uint
	j := 0
	for i := 0; i < len(s); i++ {
		val, ok := lookup[s[i]]
		if !ok {
			return nil, errors.New("invalid character in token")
		}
		bits = bits<<6 | uint32(val)
		bitsLen += 6
		if bitsLen >= 8 {
			bitsLen -= 8
			result[j] = byte(bits >> bitsLen)
			j++
		}
	}
	return result[:j], nil
}
