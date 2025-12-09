package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"drylax/pkg/domain"
	"encoding/binary"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pkg/errors"
)

var ErrCircuitOpen = errors.New("database circuit breaker open")

const (
	circuitClosed      = 0
	circuitOpen        = 1
	circuitHalfOpen    = 2
	maxFailures        = 5
	cooldownSeconds    = 30
	minResponseTime    = 50 * time.Millisecond
	responseTimeJitter = 20 * time.Millisecond
)

const (
	defaultMaxOpenConns = 100
	defaultMaxIdleConns = 10
	defaultQueryTimeout = 5 * time.Second
)

type SQLite struct {
	db            *sql.DB
	failures      int32
	circuitState  int32
	circuitOpened int64
	queryTimeout  time.Duration
}

func (s *SQLite) DB() *sql.DB {
	return s.db
}
func NewSQLite(path string) (*SQLite, error) {
	return NewSQLiteWithConfig(path, defaultMaxOpenConns, defaultMaxIdleConns, defaultQueryTimeout)
}

func NewSQLiteWithConfig(path string, maxOpenConns, maxIdleConns int, queryTimeout time.Duration) (*SQLite, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open db")
	}
	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(1 * time.Hour)
	db.SetConnMaxIdleTime(10 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, errors.Wrap(err, "failed to ping db")
	}
	s := &SQLite{
		db:           db,
		queryTimeout: queryTimeout,
	}
	if err := s.migrate(); err != nil {
		return nil, errors.Wrap(err, "migration failed")
	}
	return s, nil
}
func (s *SQLite) checkCircuit() error {
	state := atomic.LoadInt32(&s.circuitState)
	switch state {
	case circuitClosed:
		return nil
	case circuitOpen:
		opened := atomic.LoadInt64(&s.circuitOpened)
		if time.Now().Unix()-opened >= cooldownSeconds {
			if atomic.CompareAndSwapInt32(&s.circuitState, circuitOpen, circuitHalfOpen) {
				return nil
			}
		}
		return ErrCircuitOpen
	case circuitHalfOpen:
		return nil
	default:
		return nil
	}
}
func (s *SQLite) recordError(err error) {
	if err == nil {
		atomic.StoreInt32(&s.failures, 0)
		atomic.StoreInt32(&s.circuitState, circuitClosed)
		return
	}
	if errors.Is(err, sql.ErrNoRows) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return
	}
	failures := atomic.AddInt32(&s.failures, 1)
	if atomic.LoadInt32(&s.circuitState) == circuitHalfOpen {
		atomic.StoreInt32(&s.circuitState, circuitOpen)
		atomic.StoreInt64(&s.circuitOpened, time.Now().Unix())
		atomic.StoreInt32(&s.failures, 0)
		return
	}
	if failures >= maxFailures && atomic.LoadInt32(&s.circuitState) == circuitClosed {
		atomic.StoreInt32(&s.circuitState, circuitOpen)
		atomic.StoreInt64(&s.circuitOpened, time.Now().Unix())
	}
}
func (s *SQLite) migrate() error {
	_, err := s.db.Exec("PRAGMA journal_mode=WAL")
	if err != nil {
		return errors.Wrap(err, "enable WAL mode")
	}
	_, err = s.db.Exec("PRAGMA busy_timeout = 5000")
	if err != nil {
		return errors.Wrap(err, "set busy timeout")
	}
	_, err = s.db.Exec("PRAGMA synchronous=FULL")
	if err != nil {
		return errors.Wrap(err, "set synchronous mode")
	}
	query := `
	CREATE TABLE IF NOT EXISTS pastes (
		id TEXT PRIMARY KEY,
		encrypted_content BLOB,
		encrypted_blob BLOB,
		encrypted_dek BLOB NOT NULL,
		hash TEXT,
		deletion_token_hash TEXT,
		created_at DATETIME NOT NULL,
		expires_at DATETIME NOT NULL,
		views INTEGER DEFAULT 0,
		format_version INTEGER DEFAULT 1,
		client_ip_hash TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_expires_at ON pastes(expires_at);
	`
	_, err = s.db.Exec(query)
	return err
}
func normalizeResponseTime(start time.Time) {
	elapsed := time.Since(start)
	var jitterNanos int64
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		jitterNanos = int64(responseTimeJitter)
	} else {
		jitterNanos = int64(binary.BigEndian.Uint64(b[:]) % uint64(responseTimeJitter))
	}
	target := minResponseTime + time.Duration(jitterNanos)
	if elapsed < target {
		time.Sleep(target - elapsed)
	}
}
func (s *SQLite) Create(ctx context.Context, p *domain.Paste) error {
	start := time.Now()
	defer normalizeResponseTime(start)
	if err := s.checkCircuit(); err != nil {
		return err
	}
	queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	q := `
	INSERT INTO pastes (id, encrypted_blob, encrypted_dek, hash, deletion_token_hash, created_at, expires_at, format_version, client_ip_hash)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := s.db.ExecContext(queryCtx, q,
		p.ID, p.EncryptedBlob, p.EncryptedDEK, p.Hash, p.DeletionTokenHash, p.CreatedAt, p.ExpiresAt, p.FormatVersion, p.ClientIPHash,
	)
	s.recordError(err)
	return errors.Wrap(err, "db create")
}
func (s *SQLite) Get(ctx context.Context, id string) (*domain.Paste, error) {
	start := time.Now()
	defer normalizeResponseTime(start)
	if err := s.checkCircuit(); err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	q := `
	SELECT id, encrypted_content, encrypted_blob, encrypted_dek, hash, deletion_token_hash, created_at, expires_at, views, COALESCE(format_version, 1) as format_version
	FROM pastes WHERE id = ? AND expires_at > ?
	`
	var p domain.Paste
	err := s.db.QueryRowContext(queryCtx, q, id, time.Now()).Scan(
		&p.ID, &p.EncryptedContent, &p.EncryptedBlob, &p.EncryptedDEK, &p.Hash, &p.DeletionTokenHash, &p.CreatedAt, &p.ExpiresAt, &p.Views, &p.FormatVersion,
	)
	if err == sql.ErrNoRows {
		return nil, domain.ErrPasteNotFound
	}
	s.recordError(err)
	if err != nil {
		return nil, errors.Wrap(err, "db get")
	}
	return &p, nil
}
func (s *SQLite) Delete(ctx context.Context, id string) error {
	start := time.Now()
	defer normalizeResponseTime(start)
	if err := s.checkCircuit(); err != nil {
		return err
	}
	queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	q := `DELETE FROM pastes WHERE id = ?`
	_, err := s.db.ExecContext(queryCtx, q, id)
	s.recordError(err)
	return errors.Wrap(err, "delete paste")
}
func (s *SQLite) IncrViews(ctx context.Context, id string) error {
	if err := s.checkCircuit(); err != nil {
		return err
	}
	queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	q := `UPDATE pastes SET views = views + 1 WHERE id = ?`
	_, err := s.db.ExecContext(queryCtx, q, id)
	s.recordError(err)
	return errors.Wrap(err, "incr views")
}
func (s *SQLite) CleanupExpired(ctx context.Context) (int, error) {
	if err := s.checkCircuit(); err != nil {
		return 0, err
	}
	totalDeleted := 0
	maxIterations := 10000
	for i := 0; i < maxIterations; i++ {
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		default:
		}
		queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
		result, err := s.db.ExecContext(queryCtx, `
			DELETE FROM pastes
			WHERE id IN (
				SELECT id FROM pastes
				WHERE expires_at < ?
				LIMIT 100
			)
		`, time.Now())
		cancel()
		s.recordError(err)
		if err != nil {
			return totalDeleted, errors.Wrap(err, "cleanup batch failed")
		}
		deleted, _ := result.RowsAffected()
		totalDeleted += int(deleted)
		if deleted == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return totalDeleted, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	if totalDeleted == maxIterations*100 {
		return totalDeleted, errors.New("cleanup hit iteration limit, more records may exist")
	}
	return totalDeleted, nil
}
func (s *SQLite) Exists(ctx context.Context, id string) (bool, error) {
	start := time.Now()
	defer normalizeResponseTime(start)
	if err := s.checkCircuit(); err != nil {
		return false, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, s.queryTimeout)
	defer cancel()
	var exists int
	q := `SELECT 1 FROM pastes WHERE id = ? LIMIT 1`
	err := s.db.QueryRowContext(queryCtx, q, id).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	s.recordError(err)
	if err != nil {
		return false, errors.Wrap(err, "exists check failed")
	}
	return exists == 1, nil
}
func (s *SQLite) Close() error {
	return s.db.Close()
}
