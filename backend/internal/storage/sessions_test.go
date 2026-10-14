package storage

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

var sessionTestIP = netip.MustParseAddr("192.0.2.10")

func sessionFixture(t *testing.T) (*Sessions, LoginRequest, *time.Time) {
	t.Helper()
	r, invite, now := registrationFixture(t)
	g := createRegistrationTest(t, r, invite, "session@example.test", 71)
	material := registrationMaterialTest(t, r, g)
	ctx := context.Background()
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, material); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, queuedRegistrationCode(t, r, g.Registration.ID)); err != nil {
		t.Fatal(err)
	}
	s, err := NewSessions(r.store, r.engine, protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	return s, LoginRequest{Email: invitationEmail(t, "session@example.test"), AccountID: g.Registration.AccountID, VaultID: g.Registration.VaultID, Generation: 1, AuthSecret: material.AuthSecret, DeviceID: protocol.ID{5}, DeviceName: "Windows test", Platform: "windows"}, now
}
func sessionLogin(t *testing.T, s *Sessions, r LoginRequest) SessionGrant {
	t.Helper()
	g, err := s.Login(context.Background(), r, sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func requireAccessRejected(t *testing.T, s *Sessions, token protocol.Secret) {
	t.Helper()
	if _, err := s.Material(context.Background(), token); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("invalid access accepted: %v", err)
	}
}
func TestSessionsRestartRetainsRotationAndQuotas(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	rotated, err := s.Refresh(ctx, g.RefreshToken, sessionTestIP)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	if err := s.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.now = func() time.Time { return *now }
	next, err := NewSessions(reopened, s.engine, s.preloginKey, s.quotaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.Material(ctx, rotated.AccessToken); err != nil {
		t.Fatal("restart lost active access")
	}
	if _, err := next.Refresh(ctx, g.RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("restart forgot consumed token")
	}
	requireAccessRejected(t, next, rotated.AccessToken)
	for i := 0; i < 4; i++ {
		sessionLogin(t, next, r)
	}
	if _, err := next.Login(ctx, r, sessionTestIP); !errors.Is(err, ErrAuthRate) {
		t.Fatal("restart forgot login attempts")
	}
}
func TestSessionsMigrationPreservesActivatedAccounts(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	var path string
	if err := s.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	// Reconstruct released schema 6 with the real activated account still present.
	for _, q := range []string{"DROP TABLE admin_panel_key", "DROP TABLE vault_writes", "DROP TABLE vault_objects", "DROP TABLE vault_state", "DROP TABLE auth_rate_events", "DROP TABLE refresh_tokens", "DROP TABLE sessions", "ALTER TABLE accounts DROP COLUMN status", "DELETE FROM schema_migrations WHERE version>=7"} {
		if _, err := s.store.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	next, err := NewSessions(reopened, s.engine, s.preloginKey, s.quotaKey)
	if err != nil {
		t.Fatal(err)
	}
	g := sessionLogin(t, next, r)
	if _, err := next.Material(ctx, g.AccessToken); err != nil {
		t.Fatal("migration damaged existing account")
	}
}
func TestSessionsActivityAndOwnedSessionBoundary(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	*now = now.Add(2 * time.Minute)
	if _, err := s.Material(ctx, g.AccessToken); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, g.AccessToken)
	if err != nil || len(list) != 1 || !list[0].LastUsedAt.Equal(*now) {
		t.Fatal("activity not recorded")
	}
	// A second account with structurally valid, distinct key context.
	var descriptor, envelope, verifier []byte
	if err := s.store.db.QueryRow("SELECT descriptor,password_envelope,verifier FROM accounts").Scan(&descriptor, &envelope, &verifier); err != nil {
		t.Fatal(err)
	}
	otherAccount, otherVault, epoch := protocol.ID{81}, protocol.ID{82}, protocol.ID{9}
	copy(envelope[24:40], otherAccount[:])
	copy(envelope[40:56], otherVault[:])
	if _, err := s.store.db.Exec("INSERT INTO accounts(account_id,email,role,vault_id,epoch_id,descriptor,verifier,password_envelope,created_at_ms) VALUES(?,?,'user',?,?,?,?,?,?)", otherAccount[:], "other@example.test", otherVault[:], epoch[:], descriptor, verifier, envelope, now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	other := r
	other.Email = invitationEmail(t, "other@example.test")
	other.AccountID = otherAccount
	other.VaultID = otherVault
	foreign := sessionLogin(t, s, other)
	if err := s.Revoke(ctx, g.AccessToken, foreign.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("cross-account revocation accepted")
	}
	if _, err := s.Material(ctx, foreign.AccessToken); err != nil {
		t.Fatal("cross-account operation changed victim session")
	}
}

func TestSessionsLoginRotationReplayAndLogout(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	p, err := s.Prelogin(ctx, r.Email)
	if err != nil || p.AccountID != r.AccountID || p.VaultID != r.VaultID || p.Generation != r.Generation {
		t.Fatal("prelogin mismatch")
	}
	a := sessionLogin(t, s, r)
	material, err := s.Material(ctx, a.AccessToken)
	if err != nil || material.Role != "admin" || material.AccountID != r.AccountID || material.Envelope == nil {
		t.Fatal("missing account material")
	}
	if a.AccessExpiresAt.Sub(s.store.now()) != 15*time.Minute || a.RefreshExpiresAt.Sub(s.store.now()) != 7*24*time.Hour || a.SessionExpiresAt.Sub(s.store.now()) != 30*24*time.Hour {
		t.Fatal("incorrect lifetimes")
	}
	b, err := s.Refresh(ctx, a.RefreshToken, sessionTestIP)
	if err != nil || b.SessionID != a.SessionID || b.AccessToken.Equal(a.AccessToken) || b.RefreshToken.Equal(a.RefreshToken) {
		t.Fatal("rotation failed")
	}
	requireAccessRejected(t, s, a.AccessToken)
	if _, err := s.Material(ctx, b.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(ctx, a.RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("consumed refresh accepted")
	}
	requireAccessRejected(t, s, b.AccessToken)
	if _, err := s.Refresh(ctx, b.RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("replay did not revoke family")
	}
	c := sessionLogin(t, s, r)
	if err := s.Logout(ctx, c.AccessToken); err != nil {
		t.Fatal(err)
	}
	requireAccessRejected(t, s, c.AccessToken)
	if _, err := s.Refresh(ctx, c.RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("logout left refresh usable")
	}
	if err := s.Logout(ctx, c.AccessToken); !errors.Is(err, ErrAuthentication) {
		t.Fatal("invalid logout accepted")
	}
}
func TestSessionsSyntheticPreloginAndUniformFailures(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	unknown := invitationEmail(t, "unknown@example.test")
	a, err := s.Prelogin(ctx, unknown)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Prelogin(ctx, invitationEmail(t, " UNKNOWN@EXAMPLE.TEST "))
	if err != nil || a != b || a.AccountID == a.VaultID || a.AccountID == r.AccountID {
		t.Fatal("synthetic identity is not stable or separated")
	}
	c, _ := s.Prelogin(ctx, invitationEmail(t, "other@example.test"))
	if c.AccountID == a.AccountID || c.Descriptor.Salt == a.Descriptor.Salt {
		t.Fatal("different unknown emails collide")
	}
	var count int
	if err := s.store.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 1 {
		t.Fatal("prelogin allocated an account")
	}
	for _, mutate := range []func(*LoginRequest){
		func(q *LoginRequest) { q.AuthSecret = protocol.NewSecret() },
		func(q *LoginRequest) { q.AccountID = protocol.ID{42} },
		func(q *LoginRequest) { q.VaultID = protocol.ID{43} },
		func(q *LoginRequest) { q.Generation = 2 },
	} {
		q := r
		mutate(&q)
		if _, err := s.Login(ctx, q, sessionTestIP); !errors.Is(err, ErrAuthentication) {
			t.Fatalf("nonuniform failure: %v", err)
		}
	}
	if _, err := s.Login(ctx, r, sessionTestIP); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Login(ctx, r, sessionTestIP); !errors.Is(err, ErrAuthRate) {
		t.Fatal("login quota missing")
	}
	*now = now.Add(time.Minute)
	q := r
	q.Email = unknown
	q.AccountID = a.AccountID
	q.VaultID = a.VaultID
	if _, err := s.Login(ctx, q, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("unknown account accepted")
	}
	if _, err := s.store.db.Exec("UPDATE accounts SET status='disabled'"); err != nil {
		t.Fatal(err)
	}
	disabled, _ := s.Prelogin(ctx, r.Email)
	if disabled.AccountID == r.AccountID {
		t.Fatal("disabled account exposed real material")
	}
	if _, err := s.Login(ctx, r, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("disabled account accepted")
	}
}
func TestSessionsDevicesQuotaOwnershipAndRevocation(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	grants := make([]SessionGrant, 0, 10)
	for i := 0; i < 10; i++ {
		*now = now.Add(time.Minute)
		grants = append(grants, sessionLogin(t, s, r))
	}
	*now = now.Add(time.Minute)
	wrong := r
	wrong.AuthSecret = protocol.NewSecret()
	if _, err := s.Login(ctx, wrong, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong credentials accepted: %v", err)
	}
	wrong.AuthSecret.Clear()
	// A failed login must never evict another session, even at the quota.
	if _, err := s.Material(ctx, grants[0].AccessToken); err != nil {
		t.Fatal("failed login evicted session")
	}
	*now = now.Add(time.Minute)
	replacement := sessionLogin(t, s, r)
	// The previous call touched session 0; session 1 is now least recently used.
	requireAccessRejected(t, s, grants[1].AccessToken)
	if _, err := s.Refresh(ctx, grants[1].RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("retired family refreshed")
	}
	items, err := s.List(ctx, replacement.AccessToken)
	if err != nil || len(items) != 10 {
		t.Fatal("session list incomplete")
	}
	current := 0
	for _, item := range items {
		if item.DeviceID != r.DeviceID {
			t.Fatal("device mismatch")
		}
		if item.Current {
			current++
		}
	}
	if current != 1 || grants[0].SessionID == grants[1].SessionID {
		t.Fatal("device ID improperly reused session")
	}
	if err := s.Revoke(ctx, replacement.AccessToken, protocol.ID{98}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatal("foreign/unknown session accepted")
	}
	for i := 0; i < 2; i++ {
		if err := s.Revoke(ctx, replacement.AccessToken, grants[0].SessionID); err != nil {
			t.Fatal("revoke retry failed")
		}
	}
	requireAccessRejected(t, s, grants[0].AccessToken)
	if _, err := s.Refresh(ctx, grants[0].RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("revoked refresh accepted")
	}
	sessionLogin(t, s, r)
}
func TestSessionsExpirationAndAccountState(t *testing.T) {
	for _, test := range []string{"access", "idle", "absolute", "generation", "disabled"} {
		t.Run(test, func(t *testing.T) {
			s, r, now := sessionFixture(t)
			ctx := context.Background()
			g := sessionLogin(t, s, r)
			switch test {
			case "access":
				*now = now.Add(15 * time.Minute)
			case "idle":
				*now = now.Add(7 * 24 * time.Hour)
			case "absolute":
				for i := 0; i < 4; i++ {
					*now = now.Add(6 * 24 * time.Hour)
					var err error
					g, err = s.Refresh(ctx, g.RefreshToken, sessionTestIP)
					if err != nil {
						t.Fatal(err)
					}
				}
				*now = now.Add(5 * 24 * time.Hour)
				var err error
				g, err = s.Refresh(ctx, g.RefreshToken, sessionTestIP)
				if err != nil || !g.RefreshExpiresAt.Equal(g.SessionExpiresAt) || !g.AccessExpiresAt.Equal(now.Add(15*time.Minute)) {
					t.Fatal("absolute clamp missing")
				}
				*now = now.Add(24 * time.Hour)
			case "generation":
				if _, err := s.store.db.Exec("UPDATE accounts SET credential_generation='2'"); err != nil {
					t.Fatal(err)
				}
			case "disabled":
				if _, err := s.store.db.Exec("UPDATE accounts SET status='disabled'"); err != nil {
					t.Fatal(err)
				}
			}
			requireAccessRejected(t, s, g.AccessToken)
			_, err := s.Refresh(ctx, g.RefreshToken, sessionTestIP)
			if test == "access" {
				if err != nil {
					t.Fatal("access expiry prevented refresh")
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("expired/invalid family refreshed: %v", err)
			}
		})
	}
}
func TestSessionsConcurrentRefreshRevokesWinner(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	var wg sync.WaitGroup
	grants := make(chan SessionGrant, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Go(func() {
			next, err := s.Refresh(ctx, g.RefreshToken, sessionTestIP)
			if err != nil {
				errs <- err
			} else {
				grants <- next
			}
		})
	}
	wg.Wait()
	close(grants)
	close(errs)
	if len(grants) != 1 || len(errs) != 1 {
		t.Fatal("concurrent refresh did not serialize")
	}
	for err := range errs {
		if !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	for winner := range grants {
		requireAccessRejected(t, s, winner.AccessToken)
	}
}
func TestSessionsPersistedDigestsAndRollback(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	access, _ := g.AccessToken.Bytes()
	refresh, _ := g.RefreshToken.Bytes()
	var savedAccess, savedRefresh []byte
	if err := s.store.db.QueryRow("SELECT access_digest FROM sessions").Scan(&savedAccess); err != nil {
		t.Fatal(err)
	}
	if err := s.store.db.QueryRow("SELECT digest FROM refresh_tokens").Scan(&savedRefresh); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(access[:], savedAccess) || bytes.Equal(refresh[:], savedRefresh) || len(savedAccess) != 32 || len(savedRefresh) != 32 {
		t.Fatal("raw credentials persisted")
	}
	recreated, err := NewSessions(s.store, s.engine, s.preloginKey, s.quotaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recreated.Material(ctx, g.AccessToken); err != nil {
		t.Fatal("session lost across service recreation")
	}
	if _, err := s.store.db.Exec("CREATE TRIGGER fail_refresh BEFORE INSERT ON refresh_tokens BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(ctx, g.RefreshToken, sessionTestIP); !errors.Is(err, ErrUnavailable) {
		t.Fatal("injected failure ignored")
	}
	if _, err := s.Material(ctx, g.AccessToken); err != nil {
		t.Fatal("failed refresh invalidated old access")
	}
	if _, err := s.store.db.Exec("DROP TRIGGER fail_refresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Refresh(ctx, g.RefreshToken, sessionTestIP); err != nil {
		t.Fatal("failed transaction consumed token")
	}
}
