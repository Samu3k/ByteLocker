package storage

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

func emailTestTx(t *testing.T, s *Store, run func(*sql.Tx)) {
	t.Helper()
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	run(tx)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func issueTestCode(t *testing.T, s *Store, key protocol.Secret, id protocol.ID, deadline time.Time) (auth.EmailCode, time.Time, error) {
	t.Helper()
	var code auth.EmailCode
	var expires time.Time
	var result error
	emailTestTx(t, s, func(tx *sql.Tx) {
		code, expires, result = s.issueEmailCodeTx(context.Background(), tx, key, id, deadline)
	})
	return code, expires, result
}

func verifyTestCode(t *testing.T, s *Store, key protocol.Secret, id protocol.ID, input string) emailVerdict {
	t.Helper()
	var result emailVerdict
	emailTestTx(t, s, func(tx *sql.Tx) {
		var err error
		result, err = s.verifyEmailCodeTx(context.Background(), tx, key, id, input)
		if err != nil {
			t.Fatal(err)
		}
	})
	return result
}

func TestEmailVerificationPersistsAndIsSingleUse(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	key := protocol.NewSecret()
	id := protocol.ID{1}
	code, expires, err := issueTestCode(t, s, key, id, now.Add(time.Hour))
	if err != nil || !expires.Equal(now.Add(10*time.Minute)) {
		t.Fatal("issuance failed")
	}
	defer code.Clear()
	text, _ := code.DeliveryValue()
	var stored []byte
	if err := s.db.QueryRow("SELECT code_mac FROM email_verifications").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	expected, _ := auth.EmailCodeMAC(key, id, code)
	if string(stored) != string(expected[:]) || string(stored) == text {
		t.Fatal("incorrect code storage")
	}
	for i := 0; i < 4; i++ {
		if got := verifyTestCode(t, s, key, id, "malformed"); got != emailInvalid {
			t.Fatal("malformed input accepted")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.now = func() time.Time { return now }
	var attempts int
	if err := s.db.QueryRow("SELECT attempts FROM email_verifications").Scan(&attempts); err != nil || attempts != 4 {
		t.Fatal("restart reset failed attempts")
	}
	if got := verifyTestCode(t, s, key, id, text); got != emailAccepted {
		t.Fatal("fifth valid attempt rejected after restart")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.now = func() time.Time { return now }
	if got := verifyTestCode(t, s, key, id, text); got != emailInvalid {
		t.Fatal("replayed code accepted")
	}
	if _, _, err := issueTestCode(t, s, key, id, now.Add(time.Hour)); !errors.Is(err, errEmailState) {
		t.Fatal("consumed registration reissued")
	}
	if err := s.db.QueryRow("SELECT code_mac FROM email_verifications").Scan(&stored); err != nil || stored != nil {
		t.Fatal("consumed MAC retained")
	}
}

func TestEmailAttemptLimitAndResend(t *testing.T) {
	s, now := invitationStore(t)
	clock := *now
	s.now = func() time.Time { return clock }
	key := protocol.NewSecret()
	id := protocol.ID{2}
	old, _, err := issueTestCode(t, s, key, id, now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	oldText, _ := old.DeliveryValue()
	for i := 0; i < 5; i++ {
		if got := verifyTestCode(t, s, key, id, ""); got != emailInvalid {
			t.Fatal("invalid attempt result")
		}
	}
	if got := verifyTestCode(t, s, key, id, oldText); got != emailAttemptsExhausted {
		t.Fatal("attempt limit bypassed")
	}
	clock = now.Add(time.Minute - time.Millisecond)
	if _, _, err := issueTestCode(t, s, key, id, now.Add(2*time.Hour)); !errors.Is(err, errEmailLimit) {
		t.Fatal("cooldown bypassed")
	}
	clock = now.Add(time.Minute)
	newCode, _, err := issueTestCode(t, s, key, id, now.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	newText, _ := newCode.DeliveryValue()
	// Eight decimal digits can collide by chance. Check the stored replacement
	// directly rather than making a probabilistic assertion about distinct codes.
	var actual []byte
	var attempts int
	var deadline int64
	if err := s.db.QueryRow("SELECT code_mac,attempts,deadline_ms FROM email_verifications").Scan(&actual, &attempts, &deadline); err != nil {
		t.Fatal(err)
	}
	expected, _ := auth.EmailCodeMAC(key, id, newCode)
	if string(actual) != string(expected[:]) || attempts != 0 || deadline != now.Add(2*time.Hour).UnixMilli() {
		t.Fatal("resend failed to replace code or extended deadline")
	}
	if newText != oldText && verifyTestCode(t, s, key, id, oldText) != emailInvalid {
		t.Fatal("previous code accepted")
	}
	if verifyTestCode(t, s, key, id, newText) != emailAccepted {
		t.Fatal("new code rejected")
	}
}

func TestEmailExpiryAndRegistrationBinding(t *testing.T) {
	for _, ttl := range []time.Duration{time.Hour, 2 * time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			s, now := invitationStore(t)
			clock := *now
			s.now = func() time.Time { return clock }
			key := protocol.NewSecret()
			id := protocol.ID{3}
			code, expires, err := issueTestCode(t, s, key, id, now.Add(ttl))
			if err != nil {
				t.Fatal(err)
			}
			text, _ := code.DeliveryValue()
			if expires.After(now.Add(ttl)) {
				t.Fatal("code outlives registration")
			}
			if verifyTestCode(t, s, key, protocol.ID{4}, text) != emailInvalid {
				t.Fatal("cross-registration accepted")
			}
			if verifyTestCode(t, s, protocol.NewSecret(), id, text) != emailInvalid {
				t.Fatal("wrong HMAC key accepted")
			}
			clock = expires
			if verifyTestCode(t, s, key, id, text) != emailInvalid {
				t.Fatal("expiry boundary accepted")
			}
		})
	}
}

func TestEmailRollingAndLifetimeQuotas(t *testing.T) {
	s, now := invitationStore(t)
	clock := *now
	s.now = func() time.Time { return clock }
	key := protocol.NewSecret()
	id := protocol.ID{5}
	deadline := now.Add(24 * time.Hour)
	for i := 0; i < 5; i++ {
		clock = now.Add(time.Duration(i) * time.Minute)
		if _, _, err := issueTestCode(t, s, key, id, deadline); err != nil {
			t.Fatal(err)
		}
	}
	clock = now.Add(59 * time.Minute)
	if _, _, err := issueTestCode(t, s, key, id, deadline); !errors.Is(err, errEmailLimit) {
		t.Fatal("rolling hour quota bypassed")
	}
	for i := 0; i < 5; i++ {
		clock = now.Add(time.Hour + time.Duration(i)*time.Minute)
		if _, _, err := issueTestCode(t, s, key, id, deadline); err != nil {
			t.Fatal("sliding boundary did not release quota")
		}
	}
	clock = now.Add(2 * time.Hour)
	if _, _, err := issueTestCode(t, s, key, id, deadline); !errors.Is(err, errEmailLimit) {
		t.Fatal("lifetime quota bypassed")
	}
}

func TestEmailVerificationRollback(t *testing.T) {
	s, now := invitationStore(t)
	key := protocol.NewSecret()
	id := protocol.ID{6}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.issueEmailCodeTx(ctx, tx, key, id, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM email_verifications").Scan(&count); err != nil || count != 0 {
		t.Fatal("rolled back issuance persisted")
	}
	code, _, err := issueTestCode(t, s, key, id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := code.DeliveryValue()
	tx, err = s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verdict, err := s.verifyEmailCodeTx(ctx, tx, key, id, text); err != nil || verdict != emailAccepted {
		t.Fatal("verification failed")
	}
	// Simulates account insertion or invitation consumption failing afterwards.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if verifyTestCode(t, s, key, id, text) != emailAccepted {
		t.Fatal("rollback consumed code")
	}
}

func TestEmailConcurrentVerification(t *testing.T) {
	s, now := invitationStore(t)
	key := protocol.NewSecret()
	id := protocol.ID{7}
	code, _, err := issueTestCode(t, s, key, id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := code.DeliveryValue()
	var results [2]emailVerdict
	var failures [2]error
	var group sync.WaitGroup
	for i := range results {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				failures[i] = err
				return
			}
			defer tx.Rollback()
			results[i], failures[i] = s.verifyEmailCodeTx(context.Background(), tx, key, id, text)
			if failures[i] == nil {
				failures[i] = tx.Commit()
			}
		}(i)
	}
	group.Wait()
	accepted := 0
	for i, result := range results {
		if failures[i] != nil {
			t.Fatal(failures[i])
		}
		if result == emailAccepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("concurrent code reuse")
	}
}

func TestEmailConcurrentIssuanceAcrossConnections(t *testing.T) {
	dir := t.TempDir()
	first, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	first.now = func() time.Time { return now }
	second.now = first.now
	key := protocol.NewSecret()
	id := protocol.ID{8}
	var failures [2]error
	var group sync.WaitGroup
	for i, s := range []*Store{first, second} {
		group.Add(1)
		go func(i int, s *Store) {
			defer group.Done()
			tx, err := s.db.BeginTx(context.Background(), nil)
			if err != nil {
				failures[i] = err
				return
			}
			defer tx.Rollback()
			_, _, failures[i] = s.issueEmailCodeTx(context.Background(), tx, key, id, now.Add(time.Hour))
			if failures[i] == nil {
				failures[i] = tx.Commit()
			}
		}(i, s)
	}
	group.Wait()
	winners, limited := 0, 0
	for _, err := range failures {
		if err == nil {
			winners++
		} else if errors.Is(err, errEmailLimit) {
			limited++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || limited != 1 {
		t.Fatal("concurrent issuance bypassed cooldown")
	}
}

func TestEmailMigrationPreservesInvitations(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	identity := s.Instance()
	grant, err := s.CreateBootstrapInvitation(context.Background(), nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Reconstruct schema 2 without altering either released migration.
	for _, query := range []string{
		"DROP TABLE admin_panel_key", "DROP TABLE vault_writes", "DROP TABLE vault_objects", "DROP TABLE vault_state", "DROP TABLE auth_rate_events",
		"DROP TABLE refresh_tokens",
		"DROP TABLE sessions",
		"DROP TABLE registration_attempts",
		"DROP TABLE registrations",
		"DROP TABLE accounts",
		"DROP TABLE operational_key_binding",
		"DROP TABLE email_delivery_emissions",
		"DROP TABLE email_outbox",
		"DROP TABLE email_verification_emissions",
		"DROP TABLE email_verifications",
		"DELETE FROM schema_migrations WHERE version>=3",
	} {
		if _, err := s.db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Instance() != identity {
		t.Fatal("upgrade changed identity")
	}
	var stored []byte
	if err := s.db.QueryRow("SELECT invitation_id FROM invitations").Scan(&stored); err != nil || string(stored) != string(grant.Invitation.ID[:]) {
		t.Fatal("upgrade lost invitation")
	}
	if _, _, err := issueTestCode(t, s, protocol.NewSecret(), protocol.ID{9}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal("upgraded schema unavailable")
	}
}

func TestEmailRejectInvalidIssuance(t *testing.T) {
	s, now := invitationStore(t)
	key := protocol.NewSecret()
	for _, test := range []struct {
		id       protocol.ID
		key      protocol.Secret
		deadline time.Time
	}{
		{protocol.ID{}, key, now.Add(time.Hour)},
		{protocol.ID{1}, protocol.Secret{}, now.Add(time.Hour)},
		{protocol.ID{1}, key, *now},
		{protocol.ID{1}, key, now.Add(24*time.Hour + time.Millisecond)},
	} {
		if _, _, err := issueTestCode(t, s, test.key, test.id, test.deadline); !errors.Is(err, errEmailState) {
			t.Fatal("invalid issuance accepted")
		}
	}
}
