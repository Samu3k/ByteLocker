package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/netip"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

var (
	ErrRegistrationToken       = errors.New("storage: invalid registration capability")
	ErrRegistrationExpired     = errors.New("storage: registration expired")
	ErrRegistrationConflict    = errors.New("storage: registration state conflict")
	ErrRegistrationUnavailable = errors.New("storage: registration unavailable")
	ErrRegistrationLimit       = errors.New("storage: registration quota reached")
	ErrRegistrationMaterial    = errors.New("storage: invalid registration material")
	ErrVerificationCode        = errors.New("storage: invalid verification code")
)

type Registrations struct {
	store  *Store
	queue  *EmailQueue
	engine *auth.Engine
}

func NewRegistrations(s *Store, q *EmailQueue, engine *auth.Engine) (*Registrations, error) {
	if s == nil || q == nil || q.store != s || engine == nil {
		return nil, ErrRegistrationUnavailable
	}
	return &Registrations{store: s, queue: q, engine: engine}, nil
}

type Registration struct {
	ID        protocol.ID
	AccountID protocol.ID
	VaultID   protocol.ID
	ExpiresAt time.Time
	Status    string
}
type RegistrationGrant struct {
	Registration Registration
	Token        protocol.Secret
}
type RegistrationMaterial struct {
	EpochID    protocol.ID
	Descriptor protocol.PasswordDescriptor
	AuthSecret protocol.Secret
	Envelope   *protocol.Envelope
}
type registrationRow struct {
	Registration
	invitation protocol.ID
	email      protocol.Email
	scope      string
	suppressed bool
	epoch      []byte
	descriptor []byte
	verifier   []byte
	envelope   []byte
}

// Create reserves anonymous quotas even for invalid invitations. Remote must
// come from the transport peer, never an untrusted forwarding header.
func (r *Registrations) Create(ctx context.Context, secret protocol.Secret, email protocol.Email, vault protocol.ID, remote netip.Addr) (RegistrationGrant, error) {
	var empty RegistrationGrant
	if !email.Valid() || vault.IsZero() || !remote.IsValid() {
		return empty, ErrRegistrationMaterial
	}
	if err := r.reserveAttempt(ctx, email, remote.Unmap()); err != nil {
		return empty, err
	}
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	now := r.store.now().UTC().Truncate(time.Millisecond)
	if err := cleanupRegistrationsTx(ctx, tx, now); err != nil {
		return empty, err
	}
	invitation, err := verifyInvitationTx(ctx, tx, secret, email, now)
	if err != nil {
		return empty, err
	}
	var total, byEmail, byInvite int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(email=?),0),coalesce(sum(invitation_id=?),0)
		FROM registrations WHERE status!='verified'`, email.String(), invitation.ID[:]).Scan(&total, &byEmail, &byInvite); err != nil {
		return empty, ErrUnavailable
	}
	if total >= 100 || byEmail >= 3 || byInvite >= 5 {
		return empty, ErrRegistrationLimit
	}
	var active int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE email=?", email.String()).Scan(&active); err != nil {
		return empty, ErrUnavailable
	}
	expires := now.Add(24 * time.Hour)
	if invitation.ExpiresAt.Before(expires) {
		expires = invitation.ExpiresAt
	}
	grant := RegistrationGrant{Registration: Registration{ID: randomEmailID(), AccountID: randomEmailID(), VaultID: vault, ExpiresAt: expires, Status: "awaiting_material"}, Token: protocol.NewSecret()}
	digest, _ := invitationDigest(grant.Token)
	if _, err := tx.ExecContext(ctx, `INSERT INTO registrations(registration_id,token_digest,invitation_id,email,scope,account_id,vault_id,created_at_ms,expires_at_ms,status,suppressed)
		VALUES(?,?,?,?,?,?,?,?,?,'awaiting_material',?)`, grant.Registration.ID[:], digest[:], invitation.ID[:], email.String(), invitation.Scope,
		grant.Registration.AccountID[:], vault[:], now.UnixMilli(), expires.UnixMilli(), active); err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	return grant, nil
}

func (r *Registrations) reserveAttempt(ctx context.Context, email protocol.Email, ip netip.Addr) error {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	now := r.store.now().UTC()
	if _, err := tx.ExecContext(ctx, "DELETE FROM registration_attempts WHERE created_at_ms<=?", now.Add(-time.Hour).UnixMilli()); err != nil {
		return ErrUnavailable
	}
	raw, _ := r.queue.quotaKey.Bytes()
	defer clear(raw[:])
	digest := func(domain, value string) []byte {
		mac := hmac.New(sha256.New, raw[:])
		_, _ = mac.Write([]byte(domain + "\x00" + value))
		return mac.Sum(nil)
	}
	ipHash, emailHash := digest("PM-registration-ip-v1", ip.String()), digest("PM-registration-email-v1", email.String())
	var total, ips, emails int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(ip_digest=?),0),coalesce(sum(email_digest=?),0) FROM registration_attempts`, ipHash, emailHash).Scan(&total, &ips, &emails); err != nil {
		return ErrUnavailable
	}
	if total >= 10000 || ips >= 5 || emails >= 3 {
		return ErrRegistrationLimit
	}
	id := randomEmailID()
	if _, err := tx.ExecContext(ctx, "INSERT INTO registration_attempts VALUES(?,?,?,?)", id[:], ipHash, emailHash, now.UnixMilli()); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func cleanupRegistrationsTx(ctx context.Context, tx *sql.Tx, now time.Time) error {
	// Capabilities are no longer known after collection and then yield 401.
	condition := `(status!='verified' AND expires_at_ms<=?) OR (status='verified' AND verified_at_ms<=?)`
	if _, err := tx.ExecContext(ctx, "DELETE FROM email_verifications WHERE registration_id IN (SELECT registration_id FROM registrations WHERE "+condition+")", now.UnixMilli(), now.Add(-10*time.Minute).UnixMilli()); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM registrations WHERE "+condition, now.UnixMilli(), now.Add(-10*time.Minute).UnixMilli()); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *Registrations) loadTx(ctx context.Context, tx *sql.Tx, id protocol.ID, token protocol.Secret) (registrationRow, error) {
	var row registrationRow
	digest, err := invitationDigest(token)
	if err != nil || id.IsZero() {
		return row, ErrRegistrationToken
	}
	var account, vault, invitation []byte
	var email string
	var expires int64
	var verified sql.NullInt64
	var suppressed int
	err = tx.QueryRowContext(ctx, `SELECT account_id,vault_id,invitation_id,email,scope,expires_at_ms,status,suppressed,epoch_id,descriptor,verifier,password_envelope,verified_at_ms
		FROM registrations WHERE registration_id=? AND token_digest=?`, id[:], digest[:]).Scan(&account, &vault, &invitation, &email, &row.scope, &expires, &row.Status, &suppressed, &row.epoch, &row.descriptor, &row.verifier, &row.envelope, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return row, ErrRegistrationToken
	}
	if err != nil || len(account) != 16 || len(vault) != 16 || len(invitation) != 16 {
		return row, ErrUnavailable
	}
	row.ID = id
	copy(row.AccountID[:], account)
	copy(row.VaultID[:], vault)
	copy(row.invitation[:], invitation)
	row.email, err = protocol.ParseEmail(email)
	if err != nil || row.email.String() != email {
		return row, ErrUnavailable
	}
	row.suppressed = suppressed != 0
	if row.Status == "verified" {
		expires = verified.Int64 + 10*time.Minute.Milliseconds()
	}
	row.ExpiresAt = time.UnixMilli(expires).UTC()
	if !row.ExpiresAt.After(r.store.now().UTC()) {
		return row, ErrRegistrationExpired
	}
	if row.Status != "verified" {
		if _, err := r.invitationTx(ctx, tx, row); err != nil {
			return row, err
		}
	}
	return row, nil
}

func (r *Registrations) invitationTx(ctx context.Context, tx *sql.Tx, row registrationRow) (Invitation, error) {
	now := r.store.now().UTC()
	invitation, err := scanInvitation(tx.QueryRowContext(ctx, "SELECT "+invitationColumns+" FROM invitations WHERE invitation_id=?", row.invitation[:]), now)
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	if invitation.Status != "active" || now.Before(invitation.CreatedAt) || (invitation.Email != nil && *invitation.Email != row.email) || invitation.Scope != row.scope {
		return Invitation{}, ErrRegistrationUnavailable
	}
	if invitation.Scope == "admin" {
		var closed int
		if err := tx.QueryRowContext(ctx, "SELECT bootstrap_closed FROM instance WHERE singleton=1").Scan(&closed); err != nil {
			return Invitation{}, ErrUnavailable
		}
		if closed != 0 {
			return Invitation{}, ErrRegistrationUnavailable
		}
	}
	return invitation, nil
}

func (r *Registrations) Get(ctx context.Context, id protocol.ID, token protocol.Secret) (Registration, error) {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Registration{}, ErrUnavailable
	}
	defer tx.Rollback()
	row, err := r.loadTx(ctx, tx, id, token)
	return row.Registration, err
}

func (r *Registrations) PutMaterial(ctx context.Context, id protocol.ID, token protocol.Secret, material RegistrationMaterial) (Registration, error) {
	var empty Registration
	if material.EpochID.IsZero() || !material.AuthSecret.Valid() || material.Descriptor.Validate() != nil {
		return empty, ErrRegistrationMaterial
	}
	for retry := 0; retry < 2; retry++ {
		tx, err := r.store.db.BeginTx(ctx, nil)
		if err != nil {
			return empty, ErrUnavailable
		}
		row, err := r.loadTx(ctx, tx, id, token)
		_ = tx.Rollback()
		if err != nil {
			return empty, err
		}
		if row.Status == "verified" {
			return empty, ErrRegistrationConflict
		}
		if material.Envelope.MatchServerContext(protocol.ServerContext{Kind: protocol.KindPassword, ServerID: r.store.Instance().ServerID, AccountID: row.AccountID, VaultID: row.VaultID, EpochID: material.EpochID, Generation: 1, PasswordDescriptor: &material.Descriptor}) != nil {
			return empty, ErrRegistrationMaterial
		}
		descriptor := material.Descriptor.Bytes()
		envelope := material.Envelope.Bytes()
		var record []byte
		if row.Status == "verification_pending" {
			verifier, err := auth.ParseVerifier(row.verifier)
			if err != nil {
				return empty, ErrUnavailable
			}
			matched, err := r.engine.Verify(ctx, material.AuthSecret, verifier)
			if err != nil {
				return empty, err
			}
			if !matched || !bytes.Equal(row.epoch, material.EpochID[:]) || !bytes.Equal(row.descriptor, descriptor[:]) || !bytes.Equal(row.envelope, envelope) {
				return empty, ErrRegistrationConflict
			}
		} else {
			verifier, err := r.engine.Create(ctx, material.AuthSecret)
			if err != nil {
				return empty, err
			}
			record, err = verifier.StorageRecord()
			if err != nil {
				return empty, ErrUnavailable
			}
		}
		// No SQLite transaction is held during expensive Argon2 work. Recheck
		// capability, invitation, deadline and state after it finishes.
		tx, err = r.store.db.BeginTx(ctx, nil)
		if err != nil {
			return empty, ErrUnavailable
		}
		current, err := r.loadTx(ctx, tx, id, token)
		if err != nil {
			_ = tx.Rollback()
			return empty, err
		}
		if current.Status != row.Status || !bytes.Equal(current.verifier, row.verifier) {
			_ = tx.Rollback()
			continue
		}
		if current.Status == "verification_pending" {
			_ = tx.Rollback()
			return current.Registration, nil
		}
		_, err = tx.ExecContext(ctx, `UPDATE registrations SET status='verification_pending',epoch_id=?,descriptor=?,verifier=?,password_envelope=? WHERE registration_id=?`, material.EpochID[:], descriptor[:], record, envelope, id[:])
		if err == nil {
			_, err = r.queue.issueTx(ctx, tx, id, current.email, current.ExpiresAt)
		}
		if err == nil && current.suppressed {
			_, err = tx.ExecContext(ctx, "DELETE FROM email_outbox WHERE registration_id=?", id[:])
		}
		if err != nil {
			_ = tx.Rollback()
			return empty, err
		}
		if err := tx.Commit(); err != nil {
			return empty, ErrUnavailable
		}
		current.Status = "verification_pending"
		return current.Registration, nil
	}
	return empty, ErrRegistrationConflict
}

func (r *Registrations) Resend(ctx context.Context, id protocol.ID, token protocol.Secret) (Registration, error) {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return Registration{}, ErrUnavailable
	}
	defer tx.Rollback()
	row, err := r.loadTx(ctx, tx, id, token)
	if err != nil {
		return Registration{}, err
	}
	if row.Status != "verification_pending" {
		return Registration{}, ErrRegistrationConflict
	}
	if _, err := r.queue.issueTx(ctx, tx, id, row.email, row.ExpiresAt); err != nil {
		return Registration{}, err
	}
	if row.suppressed {
		if _, err := tx.ExecContext(ctx, "DELETE FROM email_outbox WHERE registration_id=?", id[:]); err != nil {
			return Registration{}, ErrUnavailable
		}
	}
	if err := tx.Commit(); err != nil {
		return Registration{}, ErrUnavailable
	}
	return row.Registration, nil
}

func (r *Registrations) Verify(ctx context.Context, id protocol.ID, token protocol.Secret, input string) error {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	row, err := r.loadTx(ctx, tx, id, token)
	if err != nil {
		return err
	}
	if row.Status == "verified" {
		code, err := auth.ParseEmailCode(input)
		code.Clear()
		if err != nil {
			return ErrVerificationCode
		}
		return nil
	}
	if row.Status != "verification_pending" {
		return ErrRegistrationConflict
	}
	verdict, err := r.store.verifyEmailCodeTx(ctx, tx, r.queue.macKey, id, input)
	if err != nil {
		return err
	}
	if verdict != emailAccepted {
		if err := tx.Commit(); err != nil {
			return ErrUnavailable
		}
		if verdict == emailAttemptsExhausted {
			return errEmailLimit
		}
		return ErrVerificationCode
	}
	var duplicate int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM accounts WHERE email=? OR vault_id=?", row.email.String(), row.VaultID[:]).Scan(&duplicate); err != nil {
		return ErrUnavailable
	}
	if row.suppressed || duplicate != 0 {
		return ErrRegistrationUnavailable
	}
	invitation, err := r.invitationTx(ctx, tx, row)
	if err != nil {
		return err
	}
	now := r.store.now().UTC().Truncate(time.Millisecond)
	if !row.ExpiresAt.After(now) {
		return ErrRegistrationExpired
	}
	var codeExpiry int64
	if err := tx.QueryRowContext(ctx, "SELECT expires_at_ms FROM email_verifications WHERE registration_id=?", id[:]).Scan(&codeExpiry); err != nil {
		return ErrUnavailable
	}
	if now.UnixMilli() >= codeExpiry {
		return ErrVerificationCode
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO accounts(account_id,email,role,vault_id,epoch_id,descriptor,verifier,password_envelope,created_at_ms)
		VALUES(?,?,?,?,?,?,?,?,?)`, row.AccountID[:], row.email.String(), invitation.Scope, row.VaultID[:], row.epoch, row.descriptor, row.verifier, row.envelope, now.UnixMilli()); err != nil {
		return ErrUnavailable
	}
	if _, err := consumeVerifiedInvitationTx(ctx, tx, invitation, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE registrations SET status='verified',verified_at_ms=?,epoch_id=NULL,descriptor=NULL,verifier=NULL,password_envelope=NULL WHERE registration_id=?`, now.UnixMilli(), id[:]); err != nil {
		return ErrUnavailable
	}
	// Invalidate competitors without ever persisting the original invite secret.
	condition := `registration_id!=? AND status!='verified' AND (invitation_id=? OR email=? OR (?='admin' AND scope='admin'))`
	args := []any{id[:], row.invitation[:], row.email.String(), invitation.Scope}
	if _, err := tx.ExecContext(ctx, "DELETE FROM email_verifications WHERE registration_id IN (SELECT registration_id FROM registrations WHERE "+condition+")", args...); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM registrations WHERE "+condition, args...); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (r *Registrations) Cancel(ctx context.Context, id protocol.ID, token protocol.Secret) error {
	tx, err := r.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	row, err := r.loadTx(ctx, tx, id, token)
	if err != nil {
		return err
	}
	if row.Status == "verified" {
		return ErrRegistrationConflict
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM email_verifications WHERE registration_id=?", id[:]); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM registrations WHERE registration_id=?", id[:]); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}
