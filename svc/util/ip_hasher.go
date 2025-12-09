package util

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"
)

type IPHasher struct {
	rotationInterval time.Duration
	pepper           []byte
	mu               sync.RWMutex
	currentKey       []byte
	previousKey      []byte
	nextKey          []byte
	currentEpoch     int64
	stopChan         chan struct{}
	stopped          bool
}

var (
	globalIPHasher     *IPHasher
	ipHasherOnce       sync.Once
	ipHasherInitErr    error
	ErrHasherNotInit   = errors.New("IP hasher not initialized")
	ErrHasherStopped   = errors.New("IP hasher stopped")
	ErrInvalidInterval = errors.New("rotation interval must be >= 15 minutes")
)

func InitIPHasher(pepper []byte, rotationInterval time.Duration) error {
	if rotationInterval < 15*time.Minute {
		return ErrInvalidInterval
	}
	if len(pepper) < 32 {
		return errors.New("pepper must be at least 32 bytes")
	}

	ipHasherOnce.Do(func() {
		hasher := &IPHasher{
			rotationInterval: rotationInterval,
			pepper:           make([]byte, len(pepper)),
			stopChan:         make(chan struct{}),
		}
		copy(hasher.pepper, pepper)

		hasher.currentEpoch = hasher.getEpoch(time.Now())
		if err := hasher.generateKeys(); err != nil {
			ipHasherInitErr = errors.Wrap(err, "failed to generate initial keys")
			return
		}

		go hasher.rotationLoop()

		globalIPHasher = hasher
	})

	return ipHasherInitErr
}

func GetIPHasher() (*IPHasher, error) {
	if globalIPHasher == nil {
		return nil, ErrHasherNotInit
	}
	if globalIPHasher.stopped {
		return nil, ErrHasherStopped
	}
	return globalIPHasher, nil
}

func StopIPHasher() {
	if globalIPHasher != nil {
		globalIPHasher.Stop()
		globalIPHasher = nil

		ipHasherOnce = sync.Once{}
		ipHasherInitErr = nil
	}
}

func (h *IPHasher) HashIP(ip string) (string, error) {
	if h.stopped {
		return "", ErrHasherStopped
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	mac := hmac.New(sha256.New, h.currentKey)
	mac.Write([]byte(ip))
	hash := mac.Sum(nil)

	return fmt.Sprintf("hmac-sha256:%d:%s", h.currentEpoch, hex.EncodeToString(hash)), nil
}

func (h *IPHasher) VerifyIPHash(ip string, hashStr string) (bool, error) {
	if h.stopped {
		return false, ErrHasherStopped
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	currentHash, _ := h.hashWithKey(ip, h.currentKey, h.currentEpoch)
	if currentHash == hashStr {
		return true, nil
	}

	if h.previousKey != nil {
		prevHash, _ := h.hashWithKey(ip, h.previousKey, h.currentEpoch-1)
		if prevHash == hashStr {
			return true, nil
		}
	}

	if h.nextKey != nil {
		nextHash, _ := h.hashWithKey(ip, h.nextKey, h.currentEpoch+1)
		if nextHash == hashStr {
			return true, nil
		}
	}

	return false, nil
}

func (h *IPHasher) hashWithKey(ip string, key []byte, epoch int64) (string, error) {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ip))
	hash := mac.Sum(nil)
	return fmt.Sprintf("hmac-sha256:%d:%s", epoch, hex.EncodeToString(hash)), nil
}

func (h *IPHasher) getEpoch(t time.Time) int64 {
	return t.Unix() / int64(h.rotationInterval.Seconds())
}

func (h *IPHasher) generateKeys() error {

	currentKey, err := h.deriveKey(h.currentEpoch)
	if err != nil {
		return err
	}

	previousKey, err := h.deriveKey(h.currentEpoch - 1)
	if err != nil {
		return err
	}

	nextKey, err := h.deriveKey(h.currentEpoch + 1)
	if err != nil {
		return err
	}

	h.mu.Lock()

	if h.currentKey != nil {
		Wipe(h.currentKey)
	}
	if h.previousKey != nil {
		Wipe(h.previousKey)
	}
	if h.nextKey != nil {
		Wipe(h.nextKey)
	}

	h.currentKey = currentKey
	h.previousKey = previousKey
	h.nextKey = nextKey
	h.mu.Unlock()

	return nil
}

func (h *IPHasher) deriveKey(epoch int64) ([]byte, error) {

	mac := hmac.New(sha256.New, h.pepper)

	epochBytes := []byte(fmt.Sprintf("ip-hasher-v1:%d", epoch))
	mac.Write(epochBytes)

	key := mac.Sum(nil)
	return key, nil
}

func (h *IPHasher) rotationLoop() {
	ticker := time.NewTicker(h.rotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.stopChan:
			return
		case <-ticker.C:
			newEpoch := h.getEpoch(time.Now())

			h.mu.Lock()
			if newEpoch != h.currentEpoch {
				h.currentEpoch = newEpoch
				h.mu.Unlock()

				if err := h.generateKeys(); err != nil {
					Error().Err(err).Msg("failed to rotate IP hasher keys")
				} else {
					Debug().Int64("epoch", newEpoch).Msg("rotated IP hasher keys")
				}
			} else {
				h.mu.Unlock()
			}
		}
	}
}

func (h *IPHasher) Stop() {
	h.mu.Lock()
	if h.stopped {
		h.mu.Unlock()
		return
	}
	h.stopped = true
	close(h.stopChan)
	h.mu.Unlock()

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.currentKey != nil {
		Wipe(h.currentKey)
		h.currentKey = nil
	}
	if h.previousKey != nil {
		Wipe(h.previousKey)
		h.previousKey = nil
	}
	if h.nextKey != nil {
		Wipe(h.nextKey)
		h.nextKey = nil
	}
	if h.pepper != nil {
		Wipe(h.pepper)
		h.pepper = nil
	}
}
