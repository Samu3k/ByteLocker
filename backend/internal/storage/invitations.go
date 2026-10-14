package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"passwordmanager/internal/protocol"
)

const (
	DefaultInvitationTTL = 7 * 24 * time.Hour
	MaxLiveInvitations   = 1000
)

var (
	ErrInvalidInvitation        = errors.New("storage: invitation unavailable")
	ErrInvalidInvitationOptions = errors.New("storage: invalid invitation options")
	ErrInvitationLimit          = errors.New("storage: invitation limit reached")
	ErrBootstrapClosed          = errors.New("storage: administrator bootstrap is closed")
	ErrAdministratorRequired    = errors.New("storage: activate the first administrator before inviting users")
)

// Invitation contains metadata only. The original invitation secret cannot
// be reconstructed from this record or retrieved by listing invitations.
type Invitation struct {
	ID        protocol.ID
	Email     *protocol.Email
	Scope     string
	CreatedAt time.Time
	ExpiresAt time.Time
	Status    string
}

type InvitationGrant struct {
	Invitation Invitation
	Secret     protocol.Secret
}

// CreateBootstrapInvitation is an operator-only local operation. It does not
// create an administrator account or accept a Master Password. The public
// HTTP service must never expose this method as an unauthenticated endpoint.
func (s *Store) CreateBootstrapInvitation(ctx context.Context, email *protocol.Email, ttl time.Duration) (InvitationGrant, error) {
	return s.createInvitation(ctx, email, ttl, "admin")
}

// CreateUserInvitation is local operator tooling, not a public API. The email
// is mandatory and the role is always user; callers cannot grant admin access.
func (s *Store) CreateUserInvitation(ctx context.Context, email protocol.Email, ttl time.Duration) (InvitationGrant, error) {
	return s.createInvitation(ctx, &email, ttl, "user")
}

func (s *Store) createInvitation(ctx context.Context, email *protocol.Email, ttl time.Duration, scope string) (InvitationGrant, error) {
	return s.createInvitationAuthorized(ctx, email, ttl, scope, nil)
}

// AdminCreateInvitation authenticates inside the invitation transaction.
// This endpoint can issue user invitations only, never administrator accounts.
func (s *Store) AdminCreateInvitation(ctx context.Context, key protocol.Secret, email protocol.Email, ttl time.Duration) (InvitationGrant, error) {
	return s.createInvitationAuthorized(ctx, &email, ttl, "user", &key)
}

func (s *Store) createInvitationAuthorized(ctx context.Context, email *protocol.Email, ttl time.Duration, scope string, key *protocol.Secret) (InvitationGrant, error) {
	var zero InvitationGrant
	if ttl < 5*time.Minute || ttl > DefaultInvitationTTL || ttl%time.Second != 0 || (email != nil && !email.Valid()) {
		return zero, ErrInvalidInvitationOptions
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	expires := now.Add(ttl)
	if now.UnixMilli() < 0 {
		return zero, ErrInvalidInvitationOptions
	}
	if _, err := protocol.NewTimestamp(expires); err != nil {
		return zero, ErrInvalidInvitationOptions
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, ErrUnavailable
	}
	defer tx.Rollback()
	if key != nil {
		if err := s.checkAdminTx(ctx, tx, *key); err != nil {
			return zero, err
		}
		var exists int
		err := tx.QueryRowContext(ctx, "SELECT 1 FROM accounts WHERE email=?", email.String()).Scan(&exists)
		if err == nil {
			return zero, ErrAccountExists
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return zero, ErrUnavailable
		}
	}
	var closed int
	if err := tx.QueryRowContext(ctx, "SELECT bootstrap_closed FROM instance WHERE singleton=1").Scan(&closed); err != nil {
		return zero, ErrUnavailable
	}
	if scope == "admin" && closed != 0 {
		return zero, ErrBootstrapClosed
	}
	if scope == "user" && closed == 0 {
		return zero, ErrAdministratorRequired
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM invitations
		WHERE consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>?`, now.UnixMilli()).Scan(&count); err != nil {
		return zero, ErrUnavailable
	}
	if count >= MaxLiveInvitations {
		return zero, ErrInvitationLimit
	}
	var id protocol.ID
	for id.IsZero() {
		rand.Read(id[:])
	}
	secret := protocol.NewSecret()
	committed := false
	defer func() {
		if !committed {
			secret.Clear()
		}
	}()
	digest, err := invitationDigest(secret)
	if err != nil {
		return zero, ErrInvalidInvitation
	}
	var recipient any
	if email != nil {
		recipient = email.String()
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO invitations
		(invitation_id,secret_digest,scope,email,created_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?)`,
		id[:], digest[:], scope, recipient, now.UnixMilli(), expires.UnixMilli()); err != nil {
		return zero, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return zero, ErrUnavailable
	}
	committed = true
	metadata := Invitation{ID: id, Scope: scope, CreatedAt: now, ExpiresAt: expires, Status: "active"}
	if email != nil {
		copy := *email
		metadata.Email = &copy
	}
	return InvitationGrant{Invitation: metadata, Secret: secret}, nil
}

func invitationDigest(secret protocol.Secret) ([32]byte, error) {
	raw, err := secret.Bytes()
	if err != nil {
		return [32]byte{}, ErrInvalidInvitation
	}
	digest := sha256.Sum256(raw[:])
	clear(raw[:])
	return digest, nil
}

// VerifyInvitation does not reserve or consume an invitation. Registration
// must recheck it inside the final account-activation transaction. Wrong secret,
// wrong recipient, expired, consumed, revoked and closed bootstrap are uniform.
func (s *Store) VerifyInvitation(ctx context.Context, secret protocol.Secret, email protocol.Email) (Invitation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	defer tx.Rollback()
	invitation, err := verifyInvitationTx(ctx, tx, secret, email, s.now().UTC())
	if err != nil {
		return Invitation{}, err
	}
	if err := tx.Commit(); err != nil {
		return Invitation{}, ErrUnavailable
	}
	return invitation, nil
}

const invitationColumns = "invitation_id,email,scope,created_at_ms,expires_at_ms,consumed_at_ms,revoked_at_ms"

func verifyInvitationTx(ctx context.Context, tx *sql.Tx, secret protocol.Secret, email protocol.Email, now time.Time) (Invitation, error) {
	if !email.Valid() {
		return Invitation{}, ErrInvalidInvitation
	}
	digest, err := invitationDigest(secret)
	if err != nil {
		return Invitation{}, err
	}
	invitation, err := scanInvitation(tx.QueryRowContext(ctx, "SELECT "+invitationColumns+" FROM invitations WHERE secret_digest=?", digest[:]), now)
	if errors.Is(err, sql.ErrNoRows) {
		return Invitation{}, ErrInvalidInvitation
	}
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	if invitation.Status != "active" || now.Before(invitation.CreatedAt) || (invitation.Email != nil && *invitation.Email != email) {
		return Invitation{}, ErrInvalidInvitation
	}
	if invitation.Scope == "admin" {
		var closed int
		if err := tx.QueryRowContext(ctx, "SELECT bootstrap_closed FROM instance WHERE singleton=1").Scan(&closed); err != nil {
			return Invitation{}, ErrUnavailable
		}
		if closed != 0 {
			return Invitation{}, ErrInvalidInvitation
		}
	}
	return invitation, nil
}

// consumeInvitationTx is intentionally private and requires the caller's
// transaction. The account-activation implementation must insert the verified
// account and consume the invitation in this same transaction, then commit.
// It must also invalidate other pending admin registrations when scope=admin.
func consumeInvitationTx(ctx context.Context, tx *sql.Tx, secret protocol.Secret, email protocol.Email, now time.Time) (Invitation, error) {
	invitation, err := verifyInvitationTx(ctx, tx, secret, email, now)
	if err != nil {
		return Invitation{}, err
	}
	return consumeVerifiedInvitationTx(ctx, tx, invitation, now)
}

// Caller must have checked this invitation inside the same immediate transaction.
func consumeVerifiedInvitationTx(ctx context.Context, tx *sql.Tx, invitation Invitation, now time.Time) (Invitation, error) {
	result, err := tx.ExecContext(ctx, `UPDATE invitations SET consumed_at_ms=?
		WHERE invitation_id=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL AND expires_at_ms>?`, now.UnixMilli(), invitation.ID[:], now.UnixMilli())
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return Invitation{}, ErrUnavailable
	}
	if changed != 1 {
		return Invitation{}, ErrInvalidInvitation
	}
	if invitation.Scope == "admin" {
		if _, err := tx.ExecContext(ctx, "UPDATE instance SET bootstrap_closed=1 WHERE singleton=1"); err != nil {
			return Invitation{}, ErrUnavailable
		}
		if _, err := tx.ExecContext(ctx, `UPDATE invitations SET revoked_at_ms=max(?,created_at_ms)
			WHERE scope='admin' AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL`, now.UnixMilli()); err != nil {
			return Invitation{}, ErrUnavailable
		}
	}
	invitation.Status = "consumed"
	return invitation, nil
}

// ListInvitations is for the trusted local operator. Public administration
// will require authentication and current administrator scope before calling
// storage. Pagination is by opaque ID; no token digest is selected or returned.
func (s *Store) ListInvitations(ctx context.Context, after protocol.ID, limit int) ([]Invitation, *protocol.ID, error) {
	if limit < 1 || limit > 100 {
		return nil, nil, ErrInvalidInvitationOptions
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+invitationColumns+" FROM invitations WHERE invitation_id>? ORDER BY invitation_id LIMIT ?", after[:], limit+1)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer rows.Close()
	items := make([]Invitation, 0, limit)
	now := s.now().UTC()
	for rows.Next() {
		invitation, err := scanInvitation(rows, now)
		if err != nil {
			return nil, nil, ErrSchemaMismatch
		}
		if len(items) == limit {
			next := items[len(items)-1].ID
			return items, &next, nil
		}
		items = append(items, invitation)
	}
	if rows.Err() != nil {
		return nil, nil, ErrUnavailable
	}
	return items, nil, nil
}

// Revocation is idempotent and never changes an already-consumed invitation.
func (s *Store) RevokeInvitation(ctx context.Context, id protocol.ID) error {
	if id.IsZero() {
		return ErrInvalidInvitationOptions
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `UPDATE invitations SET revoked_at_ms=max(?,created_at_ms)
		WHERE invitation_id=? AND consumed_at_ms IS NULL AND revoked_at_ms IS NULL`, s.now().UTC().UnixMilli(), id[:])
	if err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM email_verifications WHERE registration_id IN
		(SELECT registration_id FROM registrations WHERE invitation_id=? AND status!='verified')`, id[:]); err != nil {
		return ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM registrations WHERE invitation_id=? AND status!='verified'", id[:]); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}

type invitationScanner interface{ Scan(...any) error }

func scanInvitation(row invitationScanner, now time.Time) (Invitation, error) {
	var raw []byte
	var recipient sql.NullString
	var scope string
	var created, expires int64
	var consumed, revoked sql.NullInt64
	if err := row.Scan(&raw, &recipient, &scope, &created, &expires, &consumed, &revoked); err != nil {
		return Invitation{}, err
	}
	if len(raw) != 16 || (scope != "admin" && scope != "user") || created < 0 || expires <= created {
		return Invitation{}, ErrSchemaMismatch
	}
	invitation := Invitation{Scope: scope, CreatedAt: time.UnixMilli(created).UTC(), ExpiresAt: time.UnixMilli(expires).UTC(), Status: "active"}
	copy(invitation.ID[:], raw)
	if invitation.ID.IsZero() {
		return Invitation{}, ErrSchemaMismatch
	}
	if _, err := protocol.NewTimestamp(invitation.ExpiresAt); err != nil {
		return Invitation{}, ErrSchemaMismatch
	}
	if recipient.Valid {
		email, err := protocol.ParseEmail(recipient.String)
		if err != nil || email.String() != recipient.String {
			return Invitation{}, ErrSchemaMismatch
		}
		invitation.Email = &email
	}
	switch {
	case consumed.Valid:
		invitation.Status = "consumed"
	case revoked.Valid:
		invitation.Status = "revoked"
	case !now.Before(invitation.ExpiresAt):
		invitation.Status = "expired"
	}
	return invitation, nil
}
