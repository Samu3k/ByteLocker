// Package storage owns SQLite persistence. It never derives vault keys or
// decrypts vault contents. The deployment runs one backend per data directory.
package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"passwordmanager/internal/protocol"

	"modernc.org/sqlite"
)

var (
	ErrUnavailable      = errors.New("storage: database unavailable")
	ErrInvalidDirectory = errors.New("storage: invalid data directory")
	ErrSchemaMismatch   = errors.New("storage: incompatible database schema")
)

//go:embed migrations/001_instance.sql
var instanceMigration string

type Instance struct {
	ServerID  protocol.ID
	CreatedAt time.Time
}

type Store struct {
	db       *sql.DB
	instance Instance
	now      func() time.Time
}

// Open creates or reopens a local persistent database. Schema and instance ID
// are committed atomically. Unknown schema versions or changed migrations fail
// closed: opening an older server never silently downgrades a newer database.
// On Windows, protect the directory with account ACLs; chmod modes alone do
// not restrict Windows access. Use a local volume, not a network filesystem.
func Open(ctx context.Context, directory string) (*Store, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, ErrInvalidDirectory
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return nil, ErrInvalidDirectory
	}
	if err := os.MkdirAll(abs, 0700); err != nil {
		return nil, ErrInvalidDirectory
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrInvalidDirectory
	}
	path := filepath.Join(abs, "passwordmanager.db")
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		if err := file.Close(); err != nil {
			return nil, ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, ErrUnavailable
	}
	info, err = os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrUnavailable
	}
	uriPath := filepath.ToSlash(path)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	uri := url.URL{Scheme: "file", Path: uriPath}
	query := url.Values{}
	for _, pragma := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(FULL)", "foreign_keys(ON)", "trusted_schema(OFF)", "cache_size(-2048)"} {
		query.Add("_pragma", pragma)
	}
	query.Set("_txlock", "immediate")
	query.Set("_dqs", "false")
	query.Set("_defensive", "true")
	uri.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	store := &Store{db: db, now: time.Now}
	setupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for {
		err = store.initialize(setupCtx)
		var sqliteError *sqlite.Error
		if !errors.As(err, &sqliteError) || (sqliteError.Code()&255 != 5 && sqliteError.Code()&255 != 6) {
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-setupCtx.Done():
			timer.Stop()
			err = ErrUnavailable
		case <-timer.C:
			continue
		}
		break
	}
	if err != nil {
		_ = db.Close()
		if errors.Is(err, ErrSchemaMismatch) {
			return nil, ErrSchemaMismatch
		}
		return nil, ErrUnavailable
	}
	return store, nil
}

func (s *Store) initialize(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	fresh, err := migrate(ctx, tx)
	if err != nil {
		return err
	}
	if fresh {
		var id protocol.ID
		for id.IsZero() {
			rand.Read(id[:])
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO instance(singleton,server_id,created_at_ms) VALUES(1,?,?)", id[:], time.Now().UTC().UnixMilli()); err != nil {
			return ErrUnavailable
		}
	}
	var raw []byte
	var created int64
	if err := tx.QueryRowContext(ctx, "SELECT server_id,created_at_ms FROM instance WHERE singleton=1").Scan(&raw, &created); err != nil {
		return ErrSchemaMismatch
	}
	if len(raw) != len(protocol.ID{}) {
		return ErrSchemaMismatch
	}
	copy(s.instance.ServerID[:], raw)
	if s.instance.ServerID.IsZero() {
		return ErrSchemaMismatch
	}
	s.instance.CreatedAt = time.UnixMilli(created).UTC()
	if _, err := protocol.NewTimestamp(s.instance.CreatedAt); err != nil {
		return ErrSchemaMismatch
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Instance() Instance { return s.instance }

func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrUnavailable
	}
	if err := s.db.PingContext(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return ErrUnavailable
	}
	return nil
}
