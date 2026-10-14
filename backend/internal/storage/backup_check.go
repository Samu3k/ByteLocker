package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"passwordmanager/internal/operationalkeys"
	"passwordmanager/internal/protocol"
)

// BackupReport contains only instance identity and aggregate counts.
type BackupReport struct {
	ServerID protocol.ID `json:"server_id"`
	Accounts int64       `json:"accounts"`
	Objects  int64       `json:"objects"`
}

// CheckBackup checks an offline copy without creating a database or migrating it.
// WAL recovery is supported; the caller must copy WAL alongside the database.
func CheckBackup(ctx context.Context, directory string) (BackupReport, error) {
	var report BackupReport
	info, err := os.Lstat(filepath.Join(directory, "passwordmanager.db"))
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return report, ErrUnavailable
	}
	abs, err := filepath.Abs(directory)
	if err != nil {
		return report, ErrInvalidDirectory
	}
	path := filepath.ToSlash(filepath.Join(abs, "passwordmanager.db"))
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	uri := url.URL{Scheme: "file", Path: path}
	q := url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "trusted_schema(OFF)", "busy_timeout(5000)"}, "_defensive": {"true"}, "_dqs": {"false"}}
	uri.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return report, ErrUnavailable
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return report, ErrUnavailable
	}
	checks := 0
	for rows.Next() {
		var result string
		if rows.Scan(&result) != nil || result != "ok" {
			rows.Close()
			return report, ErrUnavailable
		}
		checks++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || checks != 1 {
		return report, ErrUnavailable
	}
	rows, err = db.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return report, ErrUnavailable
	}
	invalid := rows.Next()
	err = rows.Err()
	rows.Close()
	if invalid || err != nil {
		return report, ErrUnavailable
	}
	migrations := []string{instanceMigration, invitationsMigration, emailVerificationsMigration, emailOutboxMigration, operationalKeyBindingMigration, registrationsMigration, sessionsMigration, vaultMigration, adminPanelMigration}
	rows, err = db.QueryContext(ctx, "SELECT version,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return report, ErrSchemaMismatch
	}
	installed := 0
	for rows.Next() {
		var version int
		var checksum string
		if rows.Scan(&version, &checksum) != nil || installed >= len(migrations) || version != installed+1 || checksum != migrationChecksum(migrations[installed]) {
			rows.Close()
			return report, ErrSchemaMismatch
		}
		installed++
	}
	err = rows.Err()
	rows.Close()
	if err != nil || installed != len(migrations) {
		return report, ErrSchemaMismatch
	}
	var id, binding []byte
	if err = db.QueryRowContext(ctx, "SELECT server_id FROM instance WHERE singleton=1").Scan(&id); err != nil || len(id) != 16 {
		return report, ErrSchemaMismatch
	}
	copy(report.ServerID[:], id)
	if report.ServerID.IsZero() {
		return report, ErrSchemaMismatch
	}
	keys, err := operationalkeys.LoadOrCreate(ctx, directory, report.ServerID, false)
	if err != nil {
		return report, ErrOperationalKeys
	}
	if err = db.QueryRowContext(ctx, "SELECT fingerprint FROM operational_key_binding WHERE singleton=1").Scan(&binding); err != nil {
		return report, ErrOperationalKeys
	}
	fingerprint := keys.Fingerprint()
	if subtle.ConstantTimeCompare(binding, fingerprint[:]) != 1 {
		return report, ErrOperationalKeys
	}
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM accounts").Scan(&report.Accounts); err != nil {
		return report, ErrUnavailable
	}
	if err = db.QueryRowContext(ctx, "SELECT count(*) FROM vault_objects").Scan(&report.Objects); err != nil {
		return report, ErrUnavailable
	}
	return report, nil
}
