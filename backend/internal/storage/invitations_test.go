package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

func invitationStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	store, err := Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	return store, &now
}

func invitationEmail(t *testing.T, value string) protocol.Email {
	t.Helper()
	email, err := protocol.ParseEmail(value)
	if err != nil {
		t.Fatal(err)
	}
	return email
}

func TestInvitationLifecycle(t *testing.T) {
	ctx := context.Background()
	store, now := invitationStore(t)
	email := invitationEmail(t, " Marco@Example.com ")
	grant, err := store.CreateBootstrapInvitation(ctx, &email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Invitation.Scope != "admin" || grant.Invitation.Status != "active" || grant.Invitation.ExpiresAt.Sub(*now) != time.Hour {
		t.Fatal("invalid invitation metadata")
	}
	var saved []byte
	if err := store.db.QueryRow("SELECT secret_digest FROM invitations WHERE invitation_id=?", grant.Invitation.ID[:]).Scan(&saved); err != nil {
		t.Fatal(err)
	}
	raw, err := grant.Secret.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(raw[:])
	if !bytes.Equal(saved, expected[:]) || bytes.Equal(saved, raw[:]) {
		t.Fatal("credential not stored as digest")
	}
	clear(raw[:])
	verified, err := store.VerifyInvitation(ctx, grant.Secret, email)
	if err != nil || verified.ID != grant.Invitation.ID {
		t.Fatal("valid invitation rejected")
	}
	wrongEmail := invitationEmail(t, "other@example.com")
	for _, test := range []struct {
		secret protocol.Secret
		email  protocol.Email
	}{{protocol.NewSecret(), email}, {grant.Secret, wrongEmail}, {protocol.Secret{}, email}, {grant.Secret, protocol.Email{}}} {
		if _, err := store.VerifyInvitation(ctx, test.secret, test.email); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatal("invalid invitation accepted")
		}
	}
	if err := store.RevokeInvitation(ctx, grant.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeInvitation(ctx, grant.Invitation.ID); err != nil {
		t.Fatal("revoke not idempotent")
	}
	if _, err := store.VerifyInvitation(ctx, grant.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("revoked invitation accepted")
	}
	items, _, err := store.ListInvitations(ctx, protocol.ID{}, 100)
	if err != nil || len(items) != 1 || items[0].Status != "revoked" {
		t.Fatal("revoked status not listed")
	}
}

func TestInvitationExpiryAndRollback(t *testing.T) {
	ctx := context.Background()
	store, now := invitationStore(t)
	email := invitationEmail(t, "a@example.com")
	grant, err := store.CreateBootstrapInvitation(ctx, nil, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	*now = now.Add(5 * time.Minute)
	if _, err := store.VerifyInvitation(ctx, grant.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("expiry boundary accepted")
	}
	items, _, err := store.ListInvitations(ctx, protocol.ID{}, 100)
	if err != nil || len(items) != 1 || items[0].Status != "expired" {
		t.Fatal("expired status not listed")
	}
	*now = now.Add(-time.Minute)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumeInvitationTx(ctx, tx, grant.Secret, email, *now); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.VerifyInvitation(ctx, grant.Secret, email); err != nil {
		t.Fatal("rollback consumed invitation")
	}
	other, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal("rollback permanently closed bootstrap")
	}
	tx, err = store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := consumeInvitationTx(ctx, tx, grant.Secret, email, *now); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []protocol.Secret{grant.Secret, other.Secret} {
		if _, err := store.VerifyInvitation(ctx, secret, email); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatal("consumed or superseded admin invitation accepted")
		}
	}
	if _, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatal("bootstrap reopened")
	}
	// Closing/reopening the process must not restore the right to bootstrap.
	var sequence int
	var name, path string
	if err := store.db.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.CreateBootstrapInvitation(ctx, nil, time.Hour); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatal("restart reopened bootstrap")
	}
}

func TestInvitationConcurrentConsumption(t *testing.T) {
	ctx := context.Background()
	store, now := invitationStore(t)
	email := invitationEmail(t, "a@example.com")
	grant, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			tx, err := store.db.BeginTx(ctx, nil)
			if err != nil {
				results <- err
				return
			}
			defer tx.Rollback()
			_, err = consumeInvitationTx(ctx, tx, grant.Secret, email, *now)
			if err == nil {
				err = tx.Commit()
			}
			results <- err
		}()
	}
	group.Wait()
	close(results)
	successes, failures := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrInvalidInvitation) {
			failures++
		} else {
			t.Fatal(err)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatal("invitation consumed more than once")
	}
}

func TestInvitationPaginationAndOptions(t *testing.T) {
	ctx := context.Background()
	store, _ := invitationStore(t)
	for i := 0; i < 5; i++ {
		if _, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[protocol.ID]bool{}
	var after protocol.ID
	for {
		items, next, err := store.ListInvitations(ctx, after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range items {
			if seen[item.ID] {
				t.Fatal("duplicate page item")
			}
			seen[item.ID] = true
		}
		if next == nil {
			break
		}
		after = *next
	}
	if len(seen) != 5 {
		t.Fatal("pagination lost invitations")
	}
	for _, ttl := range []time.Duration{0, time.Minute, DefaultInvitationTTL + time.Second, time.Hour + time.Nanosecond} {
		if _, err := store.CreateBootstrapInvitation(ctx, nil, ttl); !errors.Is(err, ErrInvalidInvitationOptions) {
			t.Fatal("invalid lifetime accepted")
		}
	}
	invalidEmail := protocol.Email{}
	if _, err := store.CreateBootstrapInvitation(ctx, &invalidEmail, time.Hour); !errors.Is(err, ErrInvalidInvitationOptions) {
		t.Fatal("invalid recipient accepted")
	}
	if err := store.RevokeInvitation(ctx, protocol.ID{}); !errors.Is(err, ErrInvalidInvitationOptions) {
		t.Fatal("zero ID accepted")
	}
	if _, _, err := store.ListInvitations(ctx, protocol.ID{}, 0); !errors.Is(err, ErrInvalidInvitationOptions) {
		t.Fatal("invalid page limit accepted")
	}
}

func TestInvitationQuota(t *testing.T) {
	ctx := context.Background()
	store, now := invitationStore(t)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	var first protocol.ID
	for i := 1; i <= MaxLiveInvitations; i++ {
		var id protocol.ID
		id[0] = byte(i >> 8)
		id[1] = byte(i)
		digest := sha256.Sum256(id[:])
		if _, err := tx.ExecContext(ctx, `INSERT INTO invitations(invitation_id,secret_digest,scope,created_at_ms,expires_at_ms) VALUES(?,?,'admin',?,?)`, id[:], digest[:], now.UnixMilli(), now.Add(time.Hour).UnixMilli()); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			first = id
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour); !errors.Is(err, ErrInvitationLimit) {
		t.Fatal("invitation quota not enforced")
	}
	if err := store.RevokeInvitation(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour); err != nil {
		t.Fatal("revoked invitation did not release quota")
	}
}

func TestUpgradeFromInstanceSchema(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(directory, "passwordmanager.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(instanceMigration); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL) STRICT"); err != nil {
		t.Fatal(err)
	}
	var original protocol.ID
	original[0] = 42
	if _, err := db.Exec("INSERT INTO instance(singleton,server_id,created_at_ms) VALUES(1,?,0)", original[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO schema_migrations VALUES(1,?)", migrationChecksum(instanceMigration)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if store.Instance().ServerID != original {
		t.Fatal("migration changed server identity")
	}
	if _, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour); err != nil {
		t.Fatal("new schema unavailable after upgrade")
	}
	if migrationChecksum(instanceMigration) != migrationChecksum(bytesToCRLF(instanceMigration)) {
		t.Fatal("line endings changed checksum")
	}
}

func bytesToCRLF(value string) string {
	var result []byte
	for _, c := range []byte(value) {
		if c == '\n' {
			result = append(result, '\r')
		}
		result = append(result, c)
	}
	return string(result)
}
