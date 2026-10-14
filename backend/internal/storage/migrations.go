package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed migrations/002_invitations.sql
var invitationsMigration string

//go:embed migrations/003_email_verifications.sql
var emailVerificationsMigration string

//go:embed migrations/004_email_outbox.sql
var emailOutboxMigration string

//go:embed migrations/005_operational_key_binding.sql
var operationalKeyBindingMigration string

//go:embed migrations/006_registrations.sql
var registrationsMigration string

//go:embed migrations/007_sessions.sql
var sessionsMigration string

//go:embed migrations/008_vault.sql
var vaultMigration string

//go:embed migrations/009_admin_panel.sql
var adminPanelMigration string

// Migrations are append-only. Never edit an already released migration.
// CRLF normalization preserves compatibility across Windows/Linux checkouts.
func migrationChecksum(body string) string {
	digest := sha256.Sum256([]byte(strings.ReplaceAll(body, "\r\n", "\n")))
	return hex.EncodeToString(digest[:])
}

func migrate(ctx context.Context, tx *sql.Tx) (bool, error) {
	migrations := []string{instanceMigration, invitationsMigration, emailVerificationsMigration, emailOutboxMigration, operationalKeyBindingMigration, registrationsMigration, sessionsMigration, vaultMigration, adminPanelMigration}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, checksum TEXT NOT NULL
	) STRICT`); err != nil {
		return false, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, "SELECT version,checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return false, ErrUnavailable
	}
	installed := 0
	for rows.Next() {
		var version int
		var checksum string
		if err := rows.Scan(&version, &checksum); err != nil {
			rows.Close()
			return false, ErrSchemaMismatch
		}
		if version != installed+1 || version > len(migrations) || checksum != migrationChecksum(migrations[version-1]) {
			rows.Close()
			return false, ErrSchemaMismatch
		}
		installed = version
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, ErrUnavailable
	}
	for i := installed; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return false, ErrSchemaMismatch
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version,checksum) VALUES(?,?)", i+1, migrationChecksum(migrations[i])); err != nil {
			return false, ErrUnavailable
		}
	}
	return installed == 0, nil
}
