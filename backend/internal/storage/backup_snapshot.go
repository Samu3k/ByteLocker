package storage

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// SnapshotDatabase runs SQLite's consistent VACUUM INTO snapshot. Execute as
// the database service UID, so shared WAL/SHM files keep the correct ownership.
// The application can continue reading and writing the source database.
func SnapshotDatabase(ctx context.Context, source, destination string) error {
	info, err := os.Lstat(filepath.Join(source, "passwordmanager.db"))
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 2<<30 {
		return ErrUnavailable
	}
	target, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ErrUnavailable
	}
	if err = target.Close(); err != nil {
		return ErrUnavailable
	}
	abs, err := filepath.Abs(filepath.Join(source, "passwordmanager.db"))
	if err != nil {
		return ErrInvalidDirectory
	}
	path := filepath.ToSlash(abs)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {"ro"}, "_pragma": {"trusted_schema(OFF)", "busy_timeout(5000)"}, "_defensive": {"true"}, "_dqs": {"false"}}
	uri.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return ErrUnavailable
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err = db.ExecContext(ctx, "VACUUM main INTO ?", destination); err != nil {
		return ErrUnavailable
	}
	f, err := os.OpenFile(destination, os.O_RDWR, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer f.Close()
	return f.Sync()
}
