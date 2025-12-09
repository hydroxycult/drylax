package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/argon2"
)

const maxPasswordLength = 1024

type Hasher struct {
	iterations  uint32
	memory      uint32
	parallelism uint8
	keyLength   uint32
	pepper      []byte
	mu          sync.RWMutex
	jobQueue    chan hashJob
	quit        chan struct{}
	wg          sync.WaitGroup
	started     bool
	startMu     sync.Mutex
	stopOnce    sync.Once
}
type hashJob struct {
	password string
	resp     chan hashResult
}
type hashResult struct {
	hash string
	err  error
}

func NewHasher(time, memory uint32, parallelism uint8, pepper []byte) (*Hasher, error) {
	if len(pepper) == 0 {
		return nil, errors.New("pepper must not be empty")
	}
	if len(pepper) < 32 {
		return nil, errors.New("pepper must be at least 32 bytes")
	}
	if time == 0 || time > 100 {
		return nil, errors.New("iterations must be between 1 and 100")
	}
	if memory < 1*1024 || memory > 2*1024*1024 {
		return nil, errors.New("memory must be between 1024 and 2097152 KiB")
	}
	if parallelism == 0 || parallelism > 128 {
		return nil, errors.New("parallelism must be between 1 and 128")
	}
	pepperCopy := make([]byte, len(pepper))
	copy(pepperCopy, pepper)
	return &Hasher{
		iterations:  time,
		memory:      memory,
		parallelism: parallelism,
		keyLength:   32,
		pepper:      pepperCopy,
		jobQueue:    make(chan hashJob, 50000),
		quit:        make(chan struct{}),
	}, nil
}
func (h *Hasher) Start(workers int) error {
	h.startMu.Lock()
	defer h.startMu.Unlock()
	if h.started {
		return errors.New("hasher already started")
	}
	if workers <= 0 {
		workers = runtime.NumCPU()
	}
	h.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go h.worker()
	}
	h.started = true
	return nil
}
func (h *Hasher) Stop() {
	h.stopOnce.Do(func() {
		close(h.quit)
		close(h.jobQueue)
		h.wg.Wait()
		h.mu.Lock()
		wipe(h.pepper)
		h.mu.Unlock()
	})
}
func (h *Hasher) worker() {
	defer h.wg.Done()
	for {
		select {
		case job, ok := <-h.jobQueue:
			if !ok {
				return
			}
			hash, err := h.doHash(job.password)
			select {
			case job.resp <- hashResult{hash: hash, err: err}:
			case <-h.quit:
				select {
				case job.resp <- hashResult{err: errors.New("shutting down")}:
				default:
				}
				return
			}
		case <-h.quit:
			return
		}
	}
}
func (h *Hasher) Hash(password string) (string, error) {
	h.startMu.Lock()
	started := h.started
	h.startMu.Unlock()
	if !started {
		return "", errors.New("hasher not started - call Start() first")
	}
	if len(password) > maxPasswordLength {
		return "", errors.New("password too long")
	}
	respChan := make(chan hashResult, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	select {
	case h.jobQueue <- hashJob{password: password, resp: respChan}:
		select {
		case res := <-respChan:
			return res.hash, res.err
		case <-ctx.Done():
			return "", errors.New("hash timeout")
		}
	case <-ctx.Done():
		return "", errors.New("hash queue full")
	case <-h.quit:
		return "", errors.New("hasher is shutting down")
	}
}
func (h *Hasher) doHash(password string) (string, error) {
	peppered := h.applyPepper(password)
	if peppered == nil {
		return "", errors.New("hasher shutting down")
	}
	defer wipe(peppered)
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey(peppered, salt, h.iterations, h.memory, h.parallelism, h.keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.memory, h.iterations, h.parallelism, b64Salt, b64Hash), nil
}
func (h *Hasher) Verify(pwd, encoded string) (bool, bool, error) {
	startTime := time.Now()
	tooLong := len(pwd) > maxPasswordLength
	var result bool
	var needsRehash bool
	var err error
	if tooLong {
		dummyHash := "$argon2id$v=19$m=65536,t=1,p=1$ZHVtbXlzYWx0$ZHVtbXloYXNo"
		dummyPwd := strings.Repeat("x", maxPasswordLength)
		h.verifyInternal(dummyPwd, dummyHash)
		result = false
		needsRehash = false
		err = nil
	} else {
		result, needsRehash, err = h.verifyInternal(pwd, encoded)
	}
	elapsed := time.Since(startTime)
	minDuration := 350 * time.Millisecond
	if elapsed < minDuration {
		time.Sleep(minDuration - elapsed)
	}
	return result, needsRehash, err
}
func (h *Hasher) verifyInternal(pwd, encoded string) (bool, bool, error) {
	pwdBytes := []byte(pwd)
	defer wipe(pwdBytes)
	var mem, time uint32 = h.memory, h.iterations
	var threads uint8 = h.parallelism
	var salt, hash []byte
	valid := true
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		valid = false
		salt = make([]byte, 16)
		hash = make([]byte, 32)
	} else {
		if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &time, &threads); err != nil {
			valid = false
			mem, time, threads = h.memory, h.iterations, h.parallelism
			salt = make([]byte, 16)
			hash = make([]byte, 32)
		} else if mem > 2*1024*1024 || time > 1000 || threads > 128 {
			valid = false
			mem, time, threads = h.memory, h.iterations, h.parallelism
			salt = make([]byte, 16)
			hash = make([]byte, 32)
		} else {
			var err error
			salt, err = base64.RawStdEncoding.DecodeString(parts[4])
			if err != nil || len(salt) == 0 {
				valid = false
				salt = make([]byte, 16)
			}
			hash, err = base64.RawStdEncoding.DecodeString(parts[5])
			if err != nil || len(hash) == 0 || len(hash) > 256 {
				valid = false
				hash = make([]byte, 32)
			}
		}
	}
	defer wipe(hash)
	defer wipe(salt)
	peppered := h.applyPepper(pwd)
	defer wipe(peppered)
	otherHash := argon2.IDKey(peppered, salt, time, mem, threads, uint32(len(hash)))
	defer wipe(otherHash)
	match := subtle.ConstantTimeCompare(hash, otherHash) == 1
	if !valid || !match {
		return false, false, nil
	}
	needsRehash := (mem != h.memory || time != h.iterations || threads != h.parallelism)
	return true, needsRehash, nil
}
func (h *Hasher) applyPepper(password string) []byte {
	h.mu.RLock()
	pepper := h.pepper
	h.mu.RUnlock()
	if len(pepper) == 0 {
		return nil
	}
	mac := hmac.New(sha256.New, pepper)
	mac.Write([]byte(password))
	return mac.Sum(nil)
}
func (h *Hasher) UpdatePepper(newPepper []byte) {
	if len(newPepper) == 0 {
		panic("pepper not configured - this is a security misconfiguration")
	}
	pepperCopy := make([]byte, len(newPepper))
	copy(pepperCopy, newPepper)
	h.mu.Lock()
	oldPepper := h.pepper
	h.pepper = pepperCopy
	h.mu.Unlock()
	if oldPepper != nil {
		wipe(oldPepper)
	}
}
func (h *Hasher) RehashIfNeeded(password, oldHash string) (string, bool, error) {
	match, needsRehash, err := h.Verify(password, oldHash)
	if err != nil {
		return "", false, err
	}
	if !match {
		return "", false, errors.New("password mismatch")
	}
	if needsRehash {
		newHash, err := h.Hash(password)
		if err != nil {
			return "", false, err
		}
		return newHash, true, nil
	}
	return oldHash, false, nil
}
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
func randomInt(max int) int {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return max - 1
	}
	return int(n.Int64())
}
