package storage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

var (
	ErrAuthentication  = errors.New("storage: invalid credentials")
	ErrSessionLimit    = errors.New("storage: active session limit reached")
	ErrAuthRate        = errors.New("storage: authentication rate limit reached")
	ErrSessionNotFound = errors.New("storage: session not found")
	ErrInvalidLogin    = errors.New("storage: invalid login request")
)

type Sessions struct {
	store                 *Store
	engine                *auth.Engine
	preloginKey, quotaKey protocol.Secret
}

func NewSessions(s *Store, e *auth.Engine, preloginKey, quotaKey protocol.Secret) (*Sessions, error) {
	if s == nil || e == nil || !preloginKey.Valid() || !quotaKey.Valid() || preloginKey.Equal(quotaKey) {
		return nil, ErrInvalidLogin
	}
	return &Sessions{store: s, engine: e, preloginKey: preloginKey, quotaKey: quotaKey}, nil
}

type Prelogin struct {
	AccountID, VaultID protocol.ID
	Descriptor         protocol.PasswordDescriptor
	Generation         protocol.Counter
}
type LoginRequest struct {
	Email                        protocol.Email
	AccountID, VaultID, DeviceID protocol.ID
	Generation                   protocol.Counter
	AuthSecret                   protocol.Secret
	DeviceName, Platform         string
}
type SessionGrant struct {
	AccountID, VaultID, SessionID                       protocol.ID
	AccessToken, RefreshToken                           protocol.Secret
	AccessExpiresAt, RefreshExpiresAt, SessionExpiresAt time.Time
}
type SessionInfo struct {
	SessionID, DeviceID                     protocol.ID
	DeviceName, Platform                    string
	CreatedAt, LastUsedAt, SessionExpiresAt time.Time
	Current                                 bool
}
type AccountMaterial struct {
	AccountID, VaultID, EpochID    protocol.ID
	Email                          protocol.Email
	Role                           string
	Generation, RecoveryGeneration protocol.Counter
	Descriptor                     protocol.PasswordDescriptor
	Envelope                       *protocol.Envelope
}
type accountRecord struct {
	AccountMaterial
	verifier []byte
	status   string
}

func (s *Sessions) account(ctx context.Context, query interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, email protocol.Email) (accountRecord, error) {
	var a accountRecord
	var id, vault, epoch, descriptor, envelope []byte
	var generation, recovery string
	err := query.QueryRowContext(ctx, `SELECT account_id,vault_id,epoch_id,descriptor,verifier,password_envelope,credential_generation,recovery_generation,role,status
		FROM accounts WHERE email=?`, email.String()).Scan(&id, &vault, &epoch, &descriptor, &a.verifier, &envelope, &generation, &recovery, &a.Role, &a.status)
	if err != nil {
		return a, err
	}
	if len(id) != 16 || len(vault) != 16 || len(epoch) != 16 {
		return a, ErrUnavailable
	}
	copy(a.AccountID[:], id)
	copy(a.VaultID[:], vault)
	copy(a.EpochID[:], epoch)
	a.Email = email
	a.Generation, err = protocol.ParseCounter(generation)
	if err != nil || a.Generation == 0 {
		return a, ErrUnavailable
	}
	a.RecoveryGeneration, err = protocol.ParseCounter(recovery)
	if err != nil {
		return a, ErrUnavailable
	}
	a.Descriptor, err = protocol.ParsePasswordDescriptor(base64.RawURLEncoding.EncodeToString(descriptor))
	if err != nil {
		return a, ErrUnavailable
	}
	a.Envelope, err = protocol.ParseEnvelope(base64.RawURLEncoding.EncodeToString(envelope))
	if err != nil {
		return a, ErrUnavailable
	}
	if a.Envelope.MatchServerContext(protocol.ServerContext{Kind: protocol.KindPassword, ServerID: s.store.Instance().ServerID, AccountID: a.AccountID, VaultID: a.VaultID, EpochID: a.EpochID, Generation: uint64(a.Generation), PasswordDescriptor: &a.Descriptor}) != nil {
		return a, ErrUnavailable
	}
	return a, nil
}

func (s *Sessions) Prelogin(ctx context.Context, email protocol.Email) (Prelogin, error) {
	if !email.Valid() {
		return Prelogin{}, ErrInvalidLogin
	}
	a, err := s.account(ctx, s.store.db, email)
	if err == nil && a.status == "active" {
		return Prelogin{a.AccountID, a.VaultID, a.Descriptor, a.Generation}, nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Prelogin{}, ErrUnavailable
	}
	raw, _ := s.preloginKey.Bytes()
	defer clear(raw[:])
	derive := func(domain string) protocol.ID {
		mac := hmac.New(sha256.New, raw[:])
		_, _ = mac.Write([]byte(domain + "\x00" + email.String()))
		var id protocol.ID
		copy(id[:], mac.Sum(nil))
		if id.IsZero() {
			id[15] = 1
		}
		return id
	}
	return Prelogin{AccountID: derive("PM-prelogin-account-v1"), VaultID: derive("PM-prelogin-vault-v1"), Generation: 1,
		Descriptor: protocol.PasswordDescriptor{Algorithm: 1, Version: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: [16]byte(derive("PM-prelogin-salt-v1"))}}, nil
}

func validLogin(r LoginRequest) bool {
	if !r.Email.Valid() || r.AccountID.IsZero() || r.VaultID.IsZero() || r.DeviceID.IsZero() || r.Generation == 0 || !r.AuthSecret.Valid() ||
		(r.Platform != "android" && r.Platform != "windows") || !utf8.ValidString(r.DeviceName) || strings.TrimSpace(r.DeviceName) == "" || utf8.RuneCountInString(r.DeviceName) > 80 {
		return false
	}
	for _, c := range r.DeviceName {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (s *Sessions) Login(ctx context.Context, request LoginRequest, remote netip.Addr) (SessionGrant, error) {
	var empty SessionGrant
	if !validLogin(request) || !remote.IsValid() {
		return empty, ErrInvalidLogin
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	err = s.rateTx(ctx, tx, "login", request.Email.String(), remote.Unmap(), 5, 10)
	if err != nil {
		_ = tx.Rollback()
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	a, err := s.account(ctx, s.store.db, request.Email)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && a.status != "active") {
		if err := s.engine.DummyVerify(ctx, request.AuthSecret); err != nil {
			return empty, err
		}
		return empty, ErrAuthentication
	}
	if err != nil {
		return empty, ErrUnavailable
	}
	verifier, err := auth.ParseVerifier(a.verifier)
	if err != nil {
		return empty, ErrUnavailable
	}
	matched, err := s.engine.Verify(ctx, request.AuthSecret, verifier)
	if err != nil {
		return empty, err
	}
	if !matched || a.AccountID != request.AccountID || a.VaultID != request.VaultID || a.Generation != request.Generation {
		return empty, ErrAuthentication
	}
	tx, err = s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	current, err := s.account(ctx, tx, request.Email)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrAuthentication
	}
	if err != nil {
		return empty, ErrUnavailable
	}
	if current.status != "active" || current.AccountID != a.AccountID || current.VaultID != a.VaultID || current.Generation != a.Generation || !bytes.Equal(current.verifier, a.verifier) {
		return empty, ErrAuthentication
	}
	now := s.store.now().UTC().Truncate(time.Millisecond)
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE session_expires_at_ms<=?", now.UnixMilli()); err != nil {
		return empty, ErrUnavailable
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE account_id=? AND revoked_at_ms IS NULL AND refresh_expires_at_ms>? AND session_expires_at_ms>? AND credential_generation=?`, a.AccountID[:], now.UnixMilli(), now.UnixMilli(), a.Generation.String()).Scan(&active); err != nil {
		return empty, ErrUnavailable
	}
	if active >= 10 {
		// Only after full credential verification, retire the least recently
		// used active family. App termination (including provider activities)
		// cannot reliably send logout, and must not permanently lock users out.
		// The transaction still guarantees a maximum of ten active sessions.
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE session_id IN (
			SELECT session_id FROM sessions WHERE account_id=? AND revoked_at_ms IS NULL
			AND refresh_expires_at_ms>? AND session_expires_at_ms>? AND credential_generation=?
			ORDER BY last_used_at_ms,created_at_ms,session_id LIMIT ?
		)`, a.AccountID[:], now.UnixMilli(), now.UnixMilli(), a.Generation.String(), active-9); err != nil {
			return empty, ErrUnavailable
		}
	}
	if err := refreshCapacityTx(ctx, tx); err != nil {
		return empty, err
	}
	g := newSessionGrant(a.AccountID, a.VaultID, randomEmailID(), now, now.Add(30*24*time.Hour))
	access, _ := invitationDigest(g.AccessToken)
	refresh, _ := invitationDigest(g.RefreshToken)
	if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(session_id,account_id,credential_generation,device_id,device_name,platform,created_at_ms,last_used_at_ms,session_expires_at_ms,refresh_expires_at_ms,access_digest,access_expires_at_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, g.SessionID[:], a.AccountID[:], a.Generation.String(), request.DeviceID[:], request.DeviceName, request.Platform, now.UnixMilli(), now.UnixMilli(), g.SessionExpiresAt.UnixMilli(), g.RefreshExpiresAt.UnixMilli(), access[:], g.AccessExpiresAt.UnixMilli()); err != nil {
		return empty, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_tokens(digest,session_id) VALUES(?,?)", refresh[:], g.SessionID[:]); err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	return g, nil
}

func newSessionGrant(account, vault, session protocol.ID, now, absolute time.Time) SessionGrant {
	access, refresh := now.Add(15*time.Minute), now.Add(7*24*time.Hour)
	if access.After(absolute) {
		access = absolute
	}
	if refresh.After(absolute) {
		refresh = absolute
	}
	return SessionGrant{account, vault, session, protocol.NewSecret(), protocol.NewSecret(), access, refresh, absolute}
}

func refreshCapacityTx(ctx context.Context, tx *sql.Tx) error {
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM refresh_tokens").Scan(&count); err != nil {
		return ErrUnavailable
	}
	if count >= 100000 {
		return ErrAuthRate
	}
	return nil
}

func (s *Sessions) rateTx(ctx context.Context, tx *sql.Tx, kind, principal string, ip netip.Addr, principalLimit, ipLimit int) error {
	now := s.store.now().UTC()
	if _, err := tx.ExecContext(ctx, "DELETE FROM auth_rate_events WHERE created_at_ms<=?", now.Add(-time.Minute).UnixMilli()); err != nil {
		return ErrUnavailable
	}
	raw, _ := s.quotaKey.Bytes()
	defer clear(raw[:])
	digest := func(domain, value string) []byte {
		mac := hmac.New(sha256.New, raw[:])
		_, _ = mac.Write([]byte(domain + "\x00" + value))
		return mac.Sum(nil)
	}
	p, i := digest("PM-auth-"+kind+"-principal-v1", principal), digest("PM-auth-"+kind+"-ip-v1", ip.String())
	var total, principals, ips int
	if err := tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(kind=? AND principal_digest=?),0),coalesce(sum(kind=? AND ip_digest=?),0) FROM auth_rate_events`, kind, p, kind, i).Scan(&total, &principals, &ips); err != nil {
		return ErrUnavailable
	}
	if total >= 10000 || principals >= principalLimit || ips >= ipLimit {
		return ErrAuthRate
	}
	id := randomEmailID()
	if _, err := tx.ExecContext(ctx, "INSERT INTO auth_rate_events VALUES(?,?,?,?,?)", id[:], kind, p, i, now.UnixMilli()); err != nil {
		return ErrUnavailable
	}
	return nil
}

type family struct {
	account, vault, session protocol.ID
	email                   protocol.Email
	generation              protocol.Counter
	absolute, idle          int64
	active                  bool
}

func (s *Sessions) familyTx(ctx context.Context, tx *sql.Tx, where string, arg any) (family, error) {
	var f family
	var account, vault, session []byte
	var email, generation, current, status string
	var revoked sql.NullInt64
	err := tx.QueryRowContext(ctx, `SELECT a.account_id,a.vault_id,s.session_id,a.email,s.credential_generation,a.credential_generation,a.status,s.session_expires_at_ms,s.refresh_expires_at_ms,s.revoked_at_ms
		FROM sessions s JOIN accounts a ON a.account_id=s.account_id WHERE `+where, arg).Scan(&account, &vault, &session, &email, &generation, &current, &status, &f.absolute, &f.idle, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrAuthentication
	}
	if err != nil || len(account) != 16 || len(vault) != 16 || len(session) != 16 {
		return f, ErrUnavailable
	}
	copy(f.account[:], account)
	copy(f.vault[:], vault)
	copy(f.session[:], session)
	f.email, err = protocol.ParseEmail(email)
	if err != nil {
		return f, ErrUnavailable
	}
	f.generation, err = protocol.ParseCounter(generation)
	if err != nil {
		return f, ErrUnavailable
	}
	now := s.store.now().UTC().UnixMilli()
	f.active = !revoked.Valid && status == "active" && generation == current && f.absolute > now && f.idle > now
	return f, nil
}

func (s *Sessions) Refresh(ctx context.Context, token protocol.Secret, remote netip.Addr) (SessionGrant, error) {
	var empty SessionGrant
	digest, err := invitationDigest(token)
	if err != nil || !remote.IsValid() {
		return empty, ErrAuthentication
	}
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	var session []byte
	var consumed int
	err = tx.QueryRowContext(ctx, "SELECT session_id,consumed FROM refresh_tokens WHERE digest=?", digest[:]).Scan(&session, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return empty, ErrAuthentication
	}
	if err != nil {
		return empty, ErrUnavailable
	}
	f, err := s.familyTx(ctx, tx, "s.session_id=?", session)
	if err != nil {
		return empty, err
	}
	// A known replay always revokes before rate limiting can obscure it.
	if consumed != 0 {
		if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at_ms=? WHERE session_id=?", s.store.now().UTC().UnixMilli(), f.session[:]); err != nil {
			return empty, ErrUnavailable
		}
		if err := tx.Commit(); err != nil {
			return empty, ErrUnavailable
		}
		return empty, ErrAuthentication
	}
	if err := s.rateTx(ctx, tx, "refresh", f.session.String(), remote.Unmap(), 30, 60); err != nil {
		return empty, err
	}
	if !f.active {
		if err := tx.Commit(); err != nil {
			return empty, ErrUnavailable
		}
		return empty, ErrAuthentication
	}
	// Retain replay history until the absolute deadline, then reclaim it.
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE session_expires_at_ms<=?", s.store.now().UTC().UnixMilli()); err != nil {
		return empty, ErrUnavailable
	}
	if err := refreshCapacityTx(ctx, tx); err != nil {
		return empty, err
	}
	now := s.store.now().UTC().Truncate(time.Millisecond)
	g := newSessionGrant(f.account, f.vault, f.session, now, time.UnixMilli(f.absolute).UTC())
	access, _ := invitationDigest(g.AccessToken)
	refresh, _ := invitationDigest(g.RefreshToken)
	if _, err := tx.ExecContext(ctx, "UPDATE refresh_tokens SET consumed=1 WHERE digest=?", digest[:]); err != nil {
		return empty, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sessions SET access_digest=?,access_expires_at_ms=?,refresh_expires_at_ms=?,last_used_at_ms=? WHERE session_id=?`, access[:], g.AccessExpiresAt.UnixMilli(), g.RefreshExpiresAt.UnixMilli(), now.UnixMilli(), f.session[:]); err != nil {
		return empty, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO refresh_tokens(digest,session_id) VALUES(?,?)", refresh[:], f.session[:]); err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	return g, nil
}

func (s *Sessions) authenticateTx(ctx context.Context, tx *sql.Tx, token protocol.Secret) (family, error) {
	digest, err := invitationDigest(token)
	if err != nil {
		return family{}, ErrAuthentication
	}
	f, err := s.familyTx(ctx, tx, "s.access_digest=?", digest[:])
	if err != nil {
		return f, err
	}
	var expires int64
	if err := tx.QueryRowContext(ctx, "SELECT access_expires_at_ms FROM sessions WHERE session_id=?", f.session[:]).Scan(&expires); err != nil {
		return f, ErrUnavailable
	}
	if !f.active || expires <= s.store.now().UTC().UnixMilli() {
		return f, ErrAuthentication
	}
	// Coalesce activity writes to at most one per minute per family.
	now := s.store.now().UTC().UnixMilli()
	if _, err := tx.ExecContext(ctx, "UPDATE sessions SET last_used_at_ms=? WHERE session_id=? AND last_used_at_ms<=?", now, f.session[:], now-time.Minute.Milliseconds()); err != nil {
		return f, ErrUnavailable
	}
	return f, nil
}

func (s *Sessions) Material(ctx context.Context, token protocol.Secret) (AccountMaterial, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountMaterial{}, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return AccountMaterial{}, err
	}
	a, err := s.account(ctx, tx, f.email)
	if err != nil {
		return AccountMaterial{}, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return AccountMaterial{}, ErrUnavailable
	}
	return a.AccountMaterial, nil
}

func (s *Sessions) List(ctx context.Context, token protocol.Secret) ([]SessionInfo, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return nil, err
	}
	now := s.store.now().UTC().UnixMilli()
	rows, err := tx.QueryContext(ctx, `SELECT session_id,device_id,device_name,platform,created_at_ms,last_used_at_ms,session_expires_at_ms FROM sessions
		WHERE account_id=? AND credential_generation=? AND revoked_at_ms IS NULL AND refresh_expires_at_ms>? AND session_expires_at_ms>? ORDER BY created_at_ms,session_id LIMIT 10`, f.account[:], f.generation.String(), now, now)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	items := make([]SessionInfo, 0)
	for rows.Next() {
		var item SessionInfo
		var id, device []byte
		var created, used, absolute int64
		if err := rows.Scan(&id, &device, &item.DeviceName, &item.Platform, &created, &used, &absolute); err != nil || len(id) != 16 || len(device) != 16 {
			return nil, ErrUnavailable
		}
		copy(item.SessionID[:], id)
		copy(item.DeviceID[:], device)
		item.Current = item.SessionID == f.session
		item.CreatedAt = time.UnixMilli(created).UTC()
		item.LastUsedAt = time.UnixMilli(used).UTC()
		item.SessionExpiresAt = time.UnixMilli(absolute).UTC()
		items = append(items, item)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return nil, ErrUnavailable
	}
	return items, nil
}

func (s *Sessions) Logout(ctx context.Context, token protocol.Secret) error {
	return s.revoke(ctx, token, protocol.ID{}, true)
}
func (s *Sessions) Revoke(ctx context.Context, token protocol.Secret, id protocol.ID) error {
	return s.revoke(ctx, token, id, false)
}
func (s *Sessions) revoke(ctx context.Context, token protocol.Secret, id protocol.ID, current bool) error {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return err
	}
	if current {
		id = f.session
	}
	var count int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM sessions WHERE session_id=? AND account_id=?", id[:], f.account[:]).Scan(&count); err != nil {
		return ErrUnavailable
	}
	if count == 0 {
		return ErrSessionNotFound
	}
	if _, err := tx.ExecContext(ctx, "UPDATE sessions SET revoked_at_ms=coalesce(revoked_at_ms,?) WHERE session_id=? AND account_id=?", s.store.now().UTC().UnixMilli(), id[:], f.account[:]); err != nil {
		return ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return ErrUnavailable
	}
	return nil
}
