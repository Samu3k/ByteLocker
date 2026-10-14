package storage

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
)

var ErrOperationalKeys = errors.New("storage: instance operational keys do not match database")

func (s *Store) HasOperationalKeys(ctx context.Context) (bool, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM operational_key_binding").Scan(&count); err != nil {
		return false, ErrUnavailable
	}
	return count != 0, nil
}

// BindOperationalKeys persists only a fingerprint, never key bytes. Once set,
// a different bundle is refused. Initial binding is forbidden if email state
// already exists: silently supplying new keys would orphan codes and messages.
func (s *Store) BindOperationalKeys(ctx context.Context, fingerprint [32]byte) error {
	if fingerprint == ([32]byte{}) {
		return ErrOperationalKeys
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	var stored []byte
	err = tx.QueryRowContext(ctx, "SELECT fingerprint FROM operational_key_binding WHERE singleton=1").Scan(&stored)
	if err == nil {
		if subtle.ConstantTimeCompare(stored, fingerprint[:]) != 1 {
			return ErrOperationalKeys
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		var pending int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM email_verifications)+
			(SELECT count(*) FROM email_outbox)+(SELECT count(*) FROM email_delivery_emissions)`).Scan(&pending); err != nil {
			return ErrUnavailable
		}
		if pending != 0 {
			return ErrOperationalKeys
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO operational_key_binding VALUES(1,?)", fingerprint[:]); err != nil {
			return ErrUnavailable
		}
	} else {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}
