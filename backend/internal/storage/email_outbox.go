package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

var (
	ErrEmailQueueConfiguration = errors.New("storage: invalid email queue configuration")
	ErrEmailQueueFull          = errors.New("storage: email queue capacity reached")
	ErrEmailDelivery           = errors.New("storage: email delivery unavailable")
)

// VerificationSender is satisfied by mailer.Gmail. Implementations must honor
// cancellation; SMTP acceptance cannot guarantee exactly-once inbox delivery.
type VerificationSender interface {
	SendVerification(context.Context, protocol.Email, auth.EmailCode, time.Time) error
}

type EmailQueue struct {
	store    *Store
	macKey   protocol.Secret
	quotaKey protocol.Secret
	seal     cipher.AEAD
}

// NewEmailQueue does not load, generate or persist operational keys. The future
// application bootstrap must supply three separate, stable secrets from its
// protected configuration. Losing or changing them invalidates queued messages
// and pending codes; these keys never encrypt or decrypt any user's vault.
func NewEmailQueue(s *Store, macKey, encryptionKey, quotaKey protocol.Secret) (*EmailQueue, error) {
	if s == nil || s.db == nil || !macKey.Valid() || !encryptionKey.Valid() || !quotaKey.Valid() ||
		macKey.Equal(encryptionKey) || macKey.Equal(quotaKey) || encryptionKey.Equal(quotaKey) {
		return nil, ErrEmailQueueConfiguration
	}
	raw, _ := encryptionKey.Bytes()
	defer clear(raw[:])
	block, err := aes.NewCipher(raw[:])
	if err != nil {
		return nil, ErrEmailQueueConfiguration
	}
	seal, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, ErrEmailQueueConfiguration
	}
	return &EmailQueue{store: s, macKey: macKey, quotaKey: quotaKey, seal: seal}, nil
}

// issueTx is only for the future authenticated registration coordinator. Any
// error requires rollback by the caller, including capacity and quota failures.
// Code state, quota reservation and encrypted payload commit together. The code
// is deliberately not returned to the caller or exposed through an API.
func (q *EmailQueue) issueTx(ctx context.Context, tx *sql.Tx, id protocol.ID, to protocol.Email, deadline time.Time) (time.Time, error) {
	if q == nil || tx == nil || !to.Valid() {
		return time.Time{}, ErrEmailQueueConfiguration
	}
	now := q.store.now().UTC().Truncate(time.Millisecond)
	if err := purgeEmailOutboxTx(ctx, tx, now); err != nil {
		return time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM email_delivery_emissions WHERE issued_at_ms<=?", now.Add(-time.Hour).UnixMilli()); err != nil {
		return time.Time{}, ErrUnavailable
	}
	raw, _ := q.quotaKey.Bytes()
	defer clear(raw[:])
	hash := hmac.New(sha256.New, raw[:])
	_, _ = hash.Write([]byte("PM-email-recipient-v1\x00"))
	_, _ = hash.Write([]byte(to.String()))
	digest := hash.Sum(nil)
	defer clear(digest)
	var total, recipient, queued int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(recipient_digest=?),0) FROM email_delivery_emissions`, digest).Scan(&total, &recipient); err != nil {
		return time.Time{}, ErrUnavailable
	}
	if total >= 100 || recipient >= 10 {
		return time.Time{}, errEmailLimit
	}
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM email_outbox WHERE registration_id!=?", id[:]).Scan(&queued); err != nil {
		return time.Time{}, ErrUnavailable
	}
	if queued >= 100 {
		return time.Time{}, ErrEmailQueueFull
	}
	code, expires, err := q.store.issueEmailCodeTx(ctx, tx, q.macKey, id, deadline)
	if err != nil {
		return time.Time{}, err
	}
	defer code.Clear()
	var emission int
	if err := tx.QueryRowContext(ctx, "SELECT emissions FROM email_verifications WHERE registration_id=?", id[:]).Scan(&emission); err != nil {
		return time.Time{}, ErrUnavailable
	}
	messageID := randomEmailID()
	value, _ := code.DeliveryValue()
	plain := make([]byte, len(to.String())+1+len(value))
	copy(plain, to.String())
	copy(plain[len(to.String())+1:], value)
	defer clear(plain)
	payload := q.seal.Seal(nil, nil, plain, q.aad(id, messageID, emission, expires.UnixMilli()))
	if _, err := tx.ExecContext(ctx, `INSERT INTO email_outbox
		(registration_id,message_id,emission,payload,expires_at_ms,available_at_ms) VALUES(?,?,?,?,?,?)`,
		id[:], messageID[:], emission, payload, expires.UnixMilli(), now.UnixMilli()); err != nil {
		return time.Time{}, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO email_delivery_emissions VALUES(?,?,?)", messageID[:], digest, now.UnixMilli()); err != nil {
		return time.Time{}, ErrUnavailable
	}
	return expires, nil
}

func randomEmailID() protocol.ID {
	var id protocol.ID
	for id.IsZero() {
		rand.Read(id[:])
	}
	return id
}

func (q *EmailQueue) aad(registration, message protocol.ID, emission int, expires int64) []byte {
	value := []byte("PM-email-outbox-v1\x00")
	server := q.store.Instance().ServerID
	value = append(value, server[:]...)
	value = append(value, registration[:]...)
	value = append(value, message[:]...)
	value = binary.BigEndian.AppendUint64(value, uint64(emission))
	return binary.BigEndian.AppendUint64(value, uint64(expires))
}

func purgeEmailOutboxTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM email_outbox WHERE expires_at_ms<=?
		OR (attempts>=5 AND lease_until_ms<=?) OR NOT EXISTS
		(SELECT 1 FROM email_verifications v WHERE v.registration_id=email_outbox.registration_id
		 AND v.consumed=0 AND v.emissions=email_outbox.emission AND v.expires_at_ms=email_outbox.expires_at_ms)`, now.UnixMilli(), now.UnixMilli())
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

type emailClaim struct {
	registration protocol.ID
	message      protocol.ID
	lease        protocol.ID
	emission     int
	attempts     int
	expires      int64
	payload      []byte
}

func (q *EmailQueue) claim(ctx context.Context) (emailClaim, bool, error) {
	var job emailClaim
	tx, err := q.store.db.BeginTx(ctx, nil)
	if err != nil {
		return job, false, ErrUnavailable
	}
	defer tx.Rollback()
	now := q.store.now().UTC().Truncate(time.Millisecond)
	if err := purgeEmailOutboxTx(ctx, tx, now); err != nil {
		return job, false, err
	}
	var registration, message []byte
	err = tx.QueryRowContext(ctx, `SELECT registration_id,message_id,emission,attempts,expires_at_ms,payload
		FROM email_outbox WHERE available_at_ms<=? AND lease_until_ms<=? AND attempts<5
		ORDER BY available_at_ms,message_id LIMIT 1`, now.UnixMilli(), now.UnixMilli()).Scan(
		&registration, &message, &job.emission, &job.attempts, &job.expires, &job.payload)
	if errors.Is(err, sql.ErrNoRows) {
		if err := tx.Commit(); err != nil {
			return job, false, ErrUnavailable
		}
		return job, false, nil
	}
	if err != nil || len(registration) != 16 || len(message) != 16 {
		return job, false, ErrUnavailable
	}
	copy(job.registration[:], registration)
	copy(job.message[:], message)
	job.lease = randomEmailID()
	job.attempts++
	if _, err := tx.ExecContext(ctx, `UPDATE email_outbox SET attempts=?,lease_token=?,lease_until_ms=?
		WHERE message_id=?`, job.attempts, job.lease[:], now.Add(time.Minute).UnixMilli(), job.message[:]); err != nil {
		return job, false, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return job, false, ErrUnavailable
	}
	return job, true, nil
}

// DeliverNext processes at most one message. It never holds a database
// transaction during SMTP. An exclusive 60-second lease survives crashes;
// SMTP is limited to 15 seconds. A future worker loop must call this method.
// Replacing/cancelling a queued message cannot retract an email already handed
// to SMTP. A stale lease can never delete or reschedule a replacement message.
func (q *EmailQueue) DeliverNext(ctx context.Context, sender VerificationSender) (bool, error) {
	if q == nil || q.store == nil || q.seal == nil || sender == nil {
		return false, ErrEmailQueueConfiguration
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	job, found, err := q.claim(ctx)
	if err != nil || !found {
		return found, err
	}
	plain, err := q.seal.Open(nil, nil, job.payload, q.aad(job.registration, job.message, job.emission, job.expires))
	if err != nil {
		return true, q.finish(ctx, job, true, ErrEmailDelivery)
	}
	defer clear(plain)
	if len(plain) < 10 || len(plain) > 263 || plain[len(plain)-9] != 0 {
		return true, q.finish(ctx, job, true, ErrEmailDelivery)
	}
	to, err := protocol.ParseEmail(string(plain[:len(plain)-9]))
	if err != nil || to.String() != string(plain[:len(plain)-9]) {
		return true, q.finish(ctx, job, true, ErrEmailDelivery)
	}
	code, err := auth.ParseEmailCode(string(plain[len(plain)-8:]))
	if err != nil {
		return true, q.finish(ctx, job, true, ErrEmailDelivery)
	}
	defer code.Clear()
	// Recheck immediately before handing plaintext to the sender. This narrows
	// but cannot eliminate the race with a concurrent resend or cancellation.
	var active int
	now := q.store.now().UTC()
	if err := q.store.db.QueryRowContext(ctx, `SELECT count(*) FROM email_outbox
		WHERE message_id=? AND lease_token=? AND lease_until_ms>? AND expires_at_ms>?`,
		job.message[:], job.lease[:], now.UnixMilli(), now.UnixMilli()).Scan(&active); err != nil {
		return true, ErrUnavailable
	}
	if active == 0 {
		return true, nil
	}
	sendCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	sendCtx, expireCancel := context.WithDeadline(sendCtx, time.UnixMilli(job.expires))
	defer expireCancel()
	err = sender.SendVerification(sendCtx, to, code, time.UnixMilli(job.expires).UTC())
	if err == nil {
		return true, q.finish(ctx, job, true, nil)
	}
	return true, q.finish(ctx, job, false, ErrEmailDelivery)
}

func (q *EmailQueue) finish(ctx context.Context, job emailClaim, discard bool, result error) error {
	// Cleanup must still run when SMTP or application shutdown cancelled ctx.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	now := q.store.now().UTC()
	if discard || job.attempts >= 5 || !time.UnixMilli(job.expires).After(now) {
		if _, err := q.store.db.ExecContext(cleanup, "DELETE FROM email_outbox WHERE message_id=? AND lease_token=?", job.message[:], job.lease[:]); err != nil {
			return ErrUnavailable
		}
	} else {
		delay := 15 * time.Second * time.Duration(1<<uint(job.attempts-1))
		if _, err := q.store.db.ExecContext(cleanup, `UPDATE email_outbox SET available_at_ms=?,lease_token=NULL,lease_until_ms=0
			WHERE message_id=? AND lease_token=?`, now.Add(delay).UnixMilli(), job.message[:], job.lease[:]); err != nil {
			return ErrUnavailable
		}
	}
	return result
}

func (q *EmailQueue) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (q *EmailQueue) LogValue() slog.Value              { return slog.StringValue("[REDACTED]") }
func (q *EmailQueue) MarshalJSON() ([]byte, error)      { return []byte(`"[REDACTED]"`), nil }
