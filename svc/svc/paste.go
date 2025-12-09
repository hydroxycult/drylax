package svc

import (
	"context"
	"drylax/cfg"
	"drylax/metrics"
	"drylax/pkg/domain"
	"drylax/pkg/kms"
	"drylax/svc/auth"
	"drylax/svc/cache"
	"drylax/svc/db"
	"drylax/svc/util"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
)

type Paste struct {
	db              *db.SQLite
	lru             *cache.LRU
	rdb             *db.Redis
	hasher          *auth.Hasher
	kmsAdapter      *kms.Adapter
	kekCache        *kms.KEKCache
	cfg             *cfg.Cfg
	viewQueue       chan string
	viewWorkerWg    sync.WaitGroup
	activeCreateOps int32
	shutdownCtx     context.Context
	shutdownFn      context.CancelFunc
	shutdown        atomic.Bool
	opWg            sync.WaitGroup
}

func NewPaste(sqlDB *db.SQLite, lru *cache.LRU, rdb *db.Redis, h *auth.Hasher, kmsAdapter *kms.Adapter, c *cfg.Cfg) *Paste {
	if sqlDB == nil || lru == nil || h == nil || c == nil || kmsAdapter == nil {
		panic("paste service: nil dependency (sqlDB, lru, hasher, cfg, or kmsAdapter)")
	}
	shutdownCtx, shutdownFn := context.WithCancel(context.Background())

	kekCache := kms.NewKEKCache(kmsAdapter, c.KEKCacheTTL)

	p := &Paste{
		db:          sqlDB,
		lru:         lru,
		rdb:         rdb,
		hasher:      h,
		kmsAdapter:  kmsAdapter,
		kekCache:    kekCache,
		cfg:         c,
		viewQueue:   make(chan string, c.WorkerPoolSize*100),
		shutdownCtx: shutdownCtx,
		shutdownFn:  shutdownFn,
	}
	if c.WorkerPoolSize <= 0 {
		c.WorkerPoolSize = 20
	}
	p.startWorkers(c.WorkerPoolSize)
	return p
}
func (p *Paste) startWorkers(n int) {
	for i := 0; i < n; i++ {
		p.viewWorkerWg.Add(1)
		go p.viewWorker()
	}
}
func (p *Paste) viewWorker() {
	defer p.viewWorkerWg.Done()
	defer func() {
		if r := recover(); r != nil {
			util.Error().Interface("panic", r).Msg("viewWorker panicked")
		}
	}()
	for id := range p.viewQueue {
		ctx, cancel := context.WithTimeout(p.shutdownCtx, 5*time.Second)
		if err := p.db.IncrViews(ctx, id); err != nil {
			if errors.Is(err, context.Canceled) {
				cancel()
				return
			}
			util.Warn().Err(err).Str("id", id).Msg("failed to incr views")
		}
		cancel()
	}
}
func (p *Paste) Shutdown() {
	p.shutdown.Store(true)
	close(p.viewQueue)
	p.shutdownFn()
	done := make(chan struct{})
	go func() {
		p.viewWorkerWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		util.Warn().Msg("view workers didn't stop in time")
	}
	p.opWg.Wait()

	if p.kekCache != nil {
		p.kekCache.Stop()
	}

	util.Debug().Msg("paste service shutdown complete")
}
func (p *Paste) Create(ctx context.Context, params domain.CreateParams) (*domain.Paste, string, error) {
	if p.shutdown.Load() {
		return nil, "", errors.New("service shutting down")
	}
	p.opWg.Add(1)
	defer p.opWg.Done()
	currentLoad := atomic.AddInt32(&p.activeCreateOps, 1)
	if currentLoad > int32(p.cfg.MaxWorkerLoad) {
		atomic.AddInt32(&p.activeCreateOps, -1)
		return nil, "", errors.New("worker pool overloaded")
	}
	defer atomic.AddInt32(&p.activeCreateOps, -1)
	if len(params.Content) > int(p.cfg.MaxPasteSize) {
		return nil, "", domain.ErrPasteTooLarge
	}
	id, err := util.GenID(func(id string) (bool, error) {
		return p.db.Exists(ctx, id)
	})
	if err != nil {
		return nil, "", errors.Wrap(err, "gen id")
	}
	dek, err := kms.GenerateDEK()
	if err != nil {
		return nil, "", errors.Wrap(err, "generate dek")
	}
	defer util.Wipe(dek)

	now := time.Now()
	blobV2 := domain.NewEncryptedPasteV2(
		params.Content,
		now,
		now.Add(params.Duration),
	)

	blobJSON, err := json.Marshal(blobV2)
	if err != nil {
		return nil, "", errors.Wrap(err, "marshal metadata blob")
	}

	encryptedBlob, err := kms.AEADSeal(blobJSON, dek)
	if err != nil {
		return nil, "", errors.Wrap(err, "encrypt blob")
	}

	encryptedDEK, err := kms.EncryptDEKWithKMS(ctx, p.kmsAdapter, dek)
	if err != nil {
		return nil, "", errors.Wrap(err, "encrypt dek")
	}
	deletionToken, err := util.GenerateDeletionToken(id, p.cfg.DeletionTokenExpiry)
	if err != nil {
		return nil, "", errors.Wrap(err, "gen deletion token")
	}
	tokenHash, err := p.hasher.Hash(deletionToken)
	if err != nil {
		return nil, "", errors.Wrap(err, "hash deletion token")
	}
	var pwHash string
	if params.Password != "" {
		pwHash, err = p.hasher.Hash(params.Password)
		if err != nil {
			return nil, "", errors.Wrap(err, "failed to hash password")
		}
	}

	paste := &domain.Paste{
		ID:                id,
		EncryptedBlob:     encryptedBlob,
		EncryptedDEK:      encryptedDEK,
		Hash:              pwHash,
		DeletionTokenHash: tokenHash,
		CreatedAt:         now,
		ExpiresAt:         now.Add(params.Duration),
		Views:             0,
		ClientIPHash:      params.ClientIPHash,
		FormatVersion:     2,
	}
	if err := p.db.Create(ctx, paste); err != nil {
		return nil, "", errors.Wrap(err, "create paste")
	}
	p.lru.Set(ctx, paste, params.Duration)
	if p.rdb != nil {
		if err := p.rdb.CachePaste(ctx, paste, params.Duration); err != nil {
			util.Warn().Err(err).Str("id", id).Msg("failed to cache in Redis")
		}
	}
	paste.Content = params.Content
	metrics.PasteCreated.Inc()
	return paste, deletionToken, nil
}
func (p *Paste) Delete(ctx context.Context, id, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	paste, err := p.db.Get(ctx, id)
	if err != nil {
		return err
	}
	if paste.DeletionTokenHash == "" {
		return domain.ErrUnauthorized
	}
	type verifyResult struct {
		valid bool
		err   error
	}
	resultCh := make(chan verifyResult, 1)
	go func() {
		if err := util.VerifyDeletionToken(token, id); err != nil {
			resultCh <- verifyResult{false, domain.ErrUnauthorized}
			return
		}
		match, _, err := p.hasher.Verify(token, paste.DeletionTokenHash)
		if err != nil || !match {
			resultCh <- verifyResult{false, domain.ErrUnauthorized}
			return
		}
		resultCh <- verifyResult{true, nil}
	}()
	select {
	case res := <-resultCh:
		if !res.valid {
			return res.err
		}
	case <-ctx.Done():
		return errors.New("deletion verification timed out")
	}
	if err := p.db.Delete(ctx, id); err != nil {
		return errors.Wrap(err, "delete from db")
	}
	p.lru.Delete(id)
	if p.rdb != nil {
		if err := p.rdb.Delete(ctx, id); err != nil {
			util.Warn().Err(err).Str("id", id).Msg("failed to delete from redis")
		}
	}
	util.Info().Str("id", id).Msg("paste deleted via token")
	return nil
}
func (p *Paste) Get(ctx context.Context, id, password string) (*domain.Paste, error) {
	if p.lru != nil {
		if paste := p.lru.Get(ctx, id); paste != nil {
			if time.Now().After(paste.ExpiresAt) {
				p.lru.Delete(id)
				if p.rdb != nil {
					p.rdb.Delete(ctx, id)
				}
				return nil, domain.ErrPasteNotFound
			}
			metrics.CacheHits.Inc()
			if err := p.checkAccess(ctx, paste, password); err != nil {
				return nil, err
			}
			select {
			case p.viewQueue <- id:
			default:
				util.Warn().Str("id", id).Msg("view queue full, dropping increment")
			}
			metrics.PasteRetrieved.Inc()
			return paste, nil
		}
		metrics.CacheMisses.Inc()
	}
	if p.rdb != nil {
		if paste, err := p.rdb.GetPaste(ctx, id); err == nil && paste != nil {
			if time.Now().After(paste.ExpiresAt) {
				p.lru.Delete(id)
				p.rdb.Delete(ctx, id)
				return nil, domain.ErrPasteNotFound
			}
			metrics.CacheHits.Inc()
			p.lru.Set(ctx, paste, time.Until(paste.ExpiresAt))
			if err := p.checkAccess(ctx, paste, password); err != nil {
				return nil, err
			}
			select {
			case p.viewQueue <- id:
			default:
				util.Warn().Str("id", id).Msg("view queue full, dropping increment")
			}
			metrics.PasteRetrieved.Inc()
			return paste, nil
		}
	}
	paste, err := p.db.Get(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrPasteNotFound) {
			return nil, domain.ErrPasteNotFound
		}
		return nil, errors.Wrap(err, "get paste")
	}
	metrics.CacheMisses.Inc()
	if paste.Hash != "" {
		if password == "" {
			return nil, domain.ErrUnauthorized
		}
		match, _, err := p.hasher.Verify(password, paste.Hash)
		if err != nil {
			return nil, err
		}
		if !match {
			return nil, domain.ErrUnauthorized
		}
	}
	dek, err := p.kekCache.DecryptDEK(ctx, paste.EncryptedDEK)
	if err != nil {
		return nil, errors.Wrap(err, "decrypt dek (cached)")
	}
	defer util.Wipe(dek)

	if paste.FormatVersion == 2 || len(paste.EncryptedBlob) > 0 {

		blobJSON, err := kms.AEADOpen(paste.EncryptedBlob, dek)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt blob (v2)")
		}

		var blobV2 domain.EncryptedPasteV2
		if err := json.Unmarshal(blobJSON, &blobV2); err != nil {
			return nil, errors.Wrap(err, "unmarshal blob (v2)")
		}

		paste.Content = blobV2.Content
		paste.CreatedAt = blobV2.CreatedAt
		paste.ExpiresAt = blobV2.ExpiresAt
		paste.Views = blobV2.Views
	} else {

		plaintext, err := kms.AEADOpen(paste.EncryptedContent, dek)
		if err != nil {
			return nil, errors.Wrap(err, "decrypt content (v1)")
		}
		paste.Content = string(plaintext)

	}

	ttl := time.Until(paste.ExpiresAt)
	p.lru.Set(ctx, paste, ttl)
	if p.rdb != nil {
		if err := p.rdb.CachePaste(ctx, paste, ttl); err != nil {
			util.Warn().Err(err).Str("id", id).Msg("failed to cache in Redis")
		}
	}
	select {
	case p.viewQueue <- id:
	default:
		util.Warn().Str("id", id).Msg("view queue full, dropping increment")
	}
	metrics.PasteRetrieved.Inc()
	return paste, nil
}
func (p *Paste) checkAccess(ctx context.Context, paste *domain.Paste, password string) error {
	if paste.Hash == "" {
		return nil
	}
	if password == "" {
		return domain.ErrUnauthorized
	}
	match, _, err := p.hasher.Verify(password, paste.Hash)
	if err != nil {
		return err
	}
	if !match {
		return domain.ErrUnauthorized
	}
	return nil
}

var (
	cleanerOnce    sync.Once
	cleanerRunning atomic.Bool
)

func StartCleaner(ctx context.Context, db *db.SQLite, interval time.Duration) error {
	if cleanerRunning.Load() {
		return errors.New("cleaner already running")
	}
	cleanerOnce.Do(func() {
		cleanerRunning.Store(true)
		go runCleaner(ctx, db, interval)
	})
	return nil
}
func runCleaner(ctx context.Context, db *db.SQLite, interval time.Duration) {
	defer cleanerRunning.Store(false)
	cleanupRequestID := util.NewRequestID()
	ctx = util.SetRequestID(ctx, cleanupRequestID)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	util.Info().
		Str("request_id", cleanupRequestID).
		Dur("interval", interval).
		Msg("cleanup worker started")
	for {
		select {
		case <-ctx.Done():
			util.Info().
				Str("request_id", cleanupRequestID).
				Msg("cleanup worker shutting down")
			return
		case <-ticker.C:
			deleted, err := db.CleanupExpired(ctx)
			if err != nil {
				util.Error().
					Err(err).
					Str("request_id", util.GetRequestID(ctx)).
					Msg("cleanup failed")
			} else if deleted > 0 {
				util.Info().
					Int("deleted", deleted).
					Str("request_id", util.GetRequestID(ctx)).
					Msg("cleanup completed")
			}
		}
	}
}
