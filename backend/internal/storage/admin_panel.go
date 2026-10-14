package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"passwordmanager/internal/protocol"
	"time"
)

var ErrAdminDenied = errors.New("storage: admin access denied")

// RotateAdminPanelKey is local operator tooling. One administrator
// key exists at a time, expires in 24 hours and is stored only as SHA-256.
func (s *Store) RotateAdminPanelKey(ctx context.Context) (protocol.Secret, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return protocol.Secret{}, ErrUnavailable
	}
	defer tx.Rollback()
	var account []byte
	if err := tx.QueryRowContext(ctx, "SELECT account_id FROM accounts WHERE role='admin' AND status='active' ORDER BY account_id LIMIT 1").Scan(&account); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return protocol.Secret{}, ErrAdministratorRequired
		}
		return protocol.Secret{}, ErrUnavailable
	}
	secret := protocol.NewSecret()
	raw, err := secret.Bytes()
	if err != nil {
		secret.Clear()
		return protocol.Secret{}, ErrUnavailable
	}
	digest := sha256.Sum256(raw[:])
	clear(raw[:])
	_, err = tx.ExecContext(ctx, `INSERT INTO admin_panel_key(singleton,account_id,digest,expires_at_ms) VALUES(1,?,?,?) ON CONFLICT(singleton) DO UPDATE SET account_id=excluded.account_id,digest=excluded.digest,expires_at_ms=excluded.expires_at_ms`, account, digest[:], s.now().Add(24*time.Hour).UnixMilli())
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		secret.Clear()
		return protocol.Secret{}, ErrUnavailable
	}
	return secret, nil
}

func (s *Store) RevokeAdminPanelKey(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "DELETE FROM admin_panel_key"); err != nil {
		return ErrUnavailable
	}
	return nil
}

type AdminAccount struct {
	ID        protocol.ID        `json:"account_id"`
	Email     string             `json:"email"`
	Role      string             `json:"role"`
	CreatedAt protocol.Timestamp `json:"created_at"`
}

func (s *Store) AdminAccounts(ctx context.Context, secret protocol.Secret, after protocol.ID) ([]AdminAccount, *protocol.ID, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer tx.Rollback()
	if err := s.checkAdminTx(ctx, tx, secret); err != nil {
		return nil, nil, err
	}
	return s.adminAccountsTx(ctx, tx, after)
}

func (s *Store) checkAdminTx(ctx context.Context, tx *sql.Tx, secret protocol.Secret) error {
	raw, err := secret.Bytes()
	if err != nil {
		return ErrAdminDenied
	}
	digest := sha256.Sum256(raw[:])
	clear(raw[:])
	var valid int
	err = tx.QueryRowContext(ctx, `SELECT 1 FROM admin_panel_key k JOIN accounts a ON a.account_id=k.account_id WHERE k.singleton=1 AND k.digest=? AND k.expires_at_ms>? AND a.role='admin' AND a.status='active'`, digest[:], s.now().UnixMilli()).Scan(&valid)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAdminDenied
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) adminAccountsTx(ctx context.Context, tx *sql.Tx, after protocol.ID) ([]AdminAccount, *protocol.ID, error) {
	rows, err := tx.QueryContext(ctx, "SELECT account_id,email,role,created_at_ms FROM accounts WHERE account_id>? ORDER BY account_id LIMIT 101", after[:])
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	items := make([]AdminAccount, 0, 100)
	for rows.Next() {
		var item AdminAccount
		var id []byte
		var created int64
		if err := rows.Scan(&id, &item.Email, &item.Role, &created); err != nil {
			rows.Close()
			return nil, nil, ErrUnavailable
		}
		if len(id) != 16 {
			rows.Close()
			return nil, nil, ErrSchemaMismatch
		}
		copy(item.ID[:], id)
		item.CreatedAt, err = protocol.NewTimestamp(time.UnixMilli(created))
		if err != nil {
			rows.Close()
			return nil, nil, ErrSchemaMismatch
		}
		items = append(items, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, ErrUnavailable
	}
	var next *protocol.ID
	if len(items) > 100 {
		id := items[99].ID
		next = &id
		items = items[:100]
	}
	return items, next, nil
}

var ErrAdminProtected = errors.New("storage: administrator deletion forbidden")
var ErrAdminConfirmation = errors.New("storage: account and confirmation do not match")
var ErrAccountExists = errors.New("storage: account already exists")

// AdminDeleteAccount removes a user, all sessions, and all encrypted vault data
// atomically. Backups and data already downloaded by clients are not erased.
func (s *Store) AdminDeleteAccount(ctx context.Context, key protocol.Secret, id protocol.ID, confirmation protocol.Email) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	if err := s.checkAdminTx(ctx, tx, key); err != nil {
		return err
	}
	var email, role string
	err = tx.QueryRowContext(ctx, "SELECT email,role FROM accounts WHERE account_id=?", id[:]).Scan(&email, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAdminConfirmation
	}
	if err != nil {
		return ErrUnavailable
	}
	if role == "admin" {
		return ErrAdminProtected
	}
	if !confirmation.Valid() || email != confirmation.String() {
		return ErrAdminConfirmation
	}
	// Cancel outstanding registration attempts and invitations for this email,
	// so an existing invitation cannot recreate the deleted account.
	for _, query := range []string{
		"DELETE FROM email_verifications WHERE registration_id IN (SELECT registration_id FROM registrations WHERE email=?)",
		"DELETE FROM registrations WHERE email=?",
	} {
		if _, err := tx.ExecContext(ctx, query, email); err != nil {
			return ErrUnavailable
		}
	}
	if _, err := tx.ExecContext(ctx, "UPDATE invitations SET revoked_at_ms=max(?,created_at_ms) WHERE email=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL", s.now().UnixMilli(), email); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM accounts WHERE account_id=?", id[:]); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}
