package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

var (
	errEmailState = errors.New("storage: email verification unavailable")
	errEmailLimit = errors.New("storage: email verification issuance limited")
)

func IsEmailIssueLimited(err error) bool { return errors.Is(err, errEmailLimit) }

type emailVerdict uint8

const (
	emailInvalid emailVerdict = iota
	emailAccepted
	emailAttemptsExhausted
)

// These helpers deliberately remain private until registration orchestration
// exists. The caller owns the immediate SQLite transaction, authenticates the
// Registration capability, and checks invitation validity and account state.
// Issuance MUST share its transaction with encrypted outbox insertion. Delivery
// is forbidden before commit. Verification MUST share its transaction with
// account activation and invitation consumption. Invalid/limited verdicts are
// ordinary results: commit them so failed attempts cannot be rolled back.
// Database errors require rollback. A successful verification is not login.
func (s *Store) issueEmailCodeTx(ctx context.Context, tx *sql.Tx, key protocol.Secret, id protocol.ID, deadline time.Time) (auth.EmailCode, time.Time, error) {
	var empty auth.EmailCode
	now := s.now().UTC().Truncate(time.Millisecond)
	deadline = deadline.UTC().Truncate(time.Millisecond)
	if tx == nil || id.IsZero() || !key.Valid() || !deadline.After(now) || deadline.After(now.Add(24*time.Hour)) {
		return empty, time.Time{}, errEmailState
	}
	if _, err := protocol.NewTimestamp(now); err != nil {
		return empty, time.Time{}, errEmailState
	}
	if _, err := protocol.NewTimestamp(deadline); err != nil {
		return empty, time.Time{}, errEmailState
	}
	var storedDeadline, lastIssued int64
	var emissions, consumed int
	err := tx.QueryRowContext(ctx, `SELECT deadline_ms,issued_at_ms,emissions,consumed
		FROM email_verifications WHERE registration_id=?`, id[:]).Scan(&storedDeadline, &lastIssued, &emissions, &consumed)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, time.Time{}, ErrUnavailable
	}
	if err == nil {
		// A resend may shorten, but never extend, the original deadline.
		if deadline.UnixMilli() > storedDeadline {
			deadline = time.UnixMilli(storedDeadline).UTC()
		}
		if consumed != 0 || !deadline.After(now) {
			return empty, time.Time{}, errEmailState
		}
		if emissions >= 10 || now.UnixMilli()-lastIssued < time.Minute.Milliseconds() {
			return empty, time.Time{}, errEmailLimit
		}
		var recent int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM email_verification_emissions
			WHERE registration_id=? AND issued_at_ms>?`, id[:], now.Add(-time.Hour).UnixMilli()).Scan(&recent); err != nil {
			return empty, time.Time{}, ErrUnavailable
		}
		if recent >= 5 {
			return empty, time.Time{}, errEmailLimit
		}
	}
	code, err := auth.NewEmailCode()
	if err != nil {
		return empty, time.Time{}, ErrUnavailable
	}
	mac, err := auth.EmailCodeMAC(key, id, code)
	if err != nil {
		code.Clear()
		return empty, time.Time{}, errEmailState
	}
	defer clear(mac[:])
	expires := now.Add(10 * time.Minute)
	if deadline.Before(expires) {
		expires = deadline
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO email_verifications
		(registration_id,deadline_ms,code_mac,issued_at_ms,expires_at_ms,attempts,emissions,consumed)
		VALUES(?,?,?,?,?,0,?,0) ON CONFLICT(registration_id) DO UPDATE SET
		deadline_ms=excluded.deadline_ms,code_mac=excluded.code_mac,issued_at_ms=excluded.issued_at_ms,
		expires_at_ms=excluded.expires_at_ms,attempts=0,emissions=excluded.emissions`,
		id[:], deadline.UnixMilli(), mac[:], now.UnixMilli(), expires.UnixMilli(), emissions+1)
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO email_verification_emissions
			(registration_id,sequence,issued_at_ms) VALUES(?,?,?)`, id[:], emissions+1, now.UnixMilli())
	}
	if err == nil {
		// Invalidate any queued previous emission in the very same transaction.
		_, err = tx.ExecContext(ctx, "DELETE FROM email_outbox WHERE registration_id=?", id[:])
	}
	if err != nil {
		code.Clear()
		return empty, time.Time{}, ErrUnavailable
	}
	return code, expires, nil
}

// The input is raw text so malformed codes also count toward the five attempts.
// Call only after authentication and request body limits, never for anonymous
// probes. A consumed code cannot be reused, even after a restart.
func (s *Store) verifyEmailCodeTx(ctx context.Context, tx *sql.Tx, key protocol.Secret, id protocol.ID, input string) (emailVerdict, error) {
	if tx == nil || id.IsZero() || !key.Valid() {
		return emailInvalid, errEmailState
	}
	var mac []byte
	var expires, deadline int64
	var attempts, consumed int
	err := tx.QueryRowContext(ctx, `SELECT code_mac,expires_at_ms,deadline_ms,attempts,consumed
		FROM email_verifications WHERE registration_id=?`, id[:]).Scan(&mac, &expires, &deadline, &attempts, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return emailInvalid, nil
	}
	if err != nil {
		return emailInvalid, ErrUnavailable
	}
	defer clear(mac)
	now := s.now().UTC().UnixMilli()
	if consumed != 0 || now >= deadline {
		return emailInvalid, nil
	}
	if attempts >= 5 {
		return emailAttemptsExhausted, nil
	}
	if now >= expires {
		return emailInvalid, nil
	}
	if len(mac) != 32 {
		return emailInvalid, ErrUnavailable
	}
	var expected [32]byte
	copy(expected[:], mac)
	defer clear(expected[:])
	code, parseErr := auth.ParseEmailCode(input)
	defer code.Clear()
	if parseErr == nil && auth.VerifyEmailCode(key, id, code, expected) {
		if _, err := tx.ExecContext(ctx, `UPDATE email_verifications SET consumed=1,code_mac=NULL
			WHERE registration_id=?`, id[:]); err != nil {
			return emailInvalid, ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM email_outbox WHERE registration_id=?", id[:]); err != nil {
			return emailInvalid, ErrUnavailable
		}
		return emailAccepted, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE email_verifications SET attempts=attempts+1
		WHERE registration_id=?`, id[:]); err != nil {
		return emailInvalid, ErrUnavailable
	}
	return emailInvalid, nil
}
