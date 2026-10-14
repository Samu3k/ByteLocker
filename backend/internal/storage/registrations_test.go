package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
)

func registrationFixture(t *testing.T) (*Registrations, InvitationGrant, *time.Time) {
	t.Helper()
	q, now := outboxFixture(t)
	invite, err := q.store.CreateBootstrapInvitation(context.Background(), nil, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRegistrations(q.store, q, auth.NewEngine())
	if err != nil {
		t.Fatal(err)
	}
	return r, invite, now
}

func createRegistrationTest(t *testing.T, r *Registrations, invite InvitationGrant, email string, vault byte) RegistrationGrant {
	t.Helper()
	grant, err := r.Create(context.Background(), invite.Secret, invitationEmail(t, email), protocol.ID{vault}, netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// Synthetic format fixture. No Master Password or real vault is used. The
// server deliberately cannot authenticate the GCM tag without the client key.
func registrationMaterialTest(t *testing.T, r *Registrations, g RegistrationGrant) RegistrationMaterial {
	t.Helper()
	d := protocol.PasswordDescriptor{Algorithm: 1, Version: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: [16]byte{1}}
	epoch := protocol.ID{9}
	raw := make([]byte, 226)
	copy(raw, "PME1")
	raw[4] = 1
	binary.BigEndian.PutUint16(raw[6:8], 1)
	server := r.store.Instance().ServerID
	copy(raw[8:24], server[:])
	copy(raw[24:40], g.Registration.AccountID[:])
	copy(raw[40:56], g.Registration.VaultID[:])
	copy(raw[56:72], epoch[:])
	binary.BigEndian.PutUint64(raw[88:96], 1)
	binary.BigEndian.PutUint32(raw[96:100], 32)
	binary.BigEndian.PutUint32(raw[144:148], 30)
	descriptor := d.Bytes()
	copy(raw[148:178], descriptor[:])
	envelope, err := protocol.ParseEnvelope(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return RegistrationMaterial{EpochID: epoch, Descriptor: d, AuthSecret: protocol.NewSecret(), Envelope: envelope}
}

func queuedRegistrationCode(t *testing.T, r *Registrations, id protocol.ID) string {
	t.Helper()
	var message, payload []byte
	var emission int
	var expires int64
	if err := r.store.db.QueryRow("SELECT message_id,emission,expires_at_ms,payload FROM email_outbox WHERE registration_id=?", id[:]).Scan(&message, &emission, &expires, &payload); err != nil {
		t.Fatal(err)
	}
	var messageID protocol.ID
	copy(messageID[:], message)
	plain, err := r.queue.seal.Open(nil, nil, payload, r.queue.aad(id, messageID, emission, expires))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	return string(plain[len(plain)-8:])
}

func TestRegistrationCompleteFlowAndRetry(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "first@example.test", 1)
	if _, err := r.store.VerifyInvitation(ctx, invite.Secret, invitationEmail(t, "first@example.test")); err != nil {
		t.Fatal("creation consumed invitation")
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, "12345678"); !errors.Is(err, ErrRegistrationConflict) {
		t.Fatal("verification before material accepted")
	}
	m := registrationMaterialTest(t, r, g)
	if state, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, m); err != nil || state.Status != "verification_pending" {
		t.Fatal("material rejected")
	}
	code := queuedRegistrationCode(t, r, g.Registration.ID)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, m); err != nil {
		t.Fatal("identical retry rejected")
	}
	if code != queuedRegistrationCode(t, r, g.Registration.ID) {
		t.Fatal("material retry reissued email")
	}
	changed := m
	changed.AuthSecret = protocol.NewSecret()
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, changed); !errors.Is(err, ErrRegistrationConflict) {
		t.Fatal("changed credential accepted")
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); err != nil {
		t.Fatal("valid verification failed")
	}
	var role, email string
	var verifier, envelope []byte
	if err := r.store.db.QueryRow("SELECT role,email,verifier,password_envelope FROM accounts").Scan(&role, &email, &verifier, &envelope); err != nil {
		t.Fatal(err)
	}
	if role != "admin" || email != "first@example.test" || !bytes.Equal(envelope, m.Envelope.Bytes()) {
		t.Fatal("incorrect account activation")
	}
	v, err := auth.ParseVerifier(verifier)
	if err != nil {
		t.Fatal(err)
	}
	if matched, err := r.engine.Verify(ctx, m.AuthSecret, v); err != nil || !matched {
		t.Fatal("stored account verifier mismatch")
	}
	if outboxCount(t, r.queue) != 0 {
		t.Fatal("verification left email payload")
	}
	if _, err := r.store.VerifyInvitation(ctx, invite.Secret, invitationEmail(t, email)); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("invitation was not consumed")
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, "00000000"); err != nil {
		t.Fatal("lost response retry rejected")
	}
	if state, err := r.Get(ctx, g.Registration.ID, g.Token); err != nil || state.Status != "verified" {
		t.Fatal("verified state unavailable")
	}
	if _, err := r.Resend(ctx, g.Registration.ID, g.Token); !errors.Is(err, ErrRegistrationConflict) {
		t.Fatal("verified capability could send email")
	}
	*now = now.Add(10 * time.Minute)
	if _, err := r.Get(ctx, g.Registration.ID, g.Token); !errors.Is(err, ErrRegistrationExpired) {
		t.Fatal("verified capability did not expire")
	}
}

func TestRegistrationWrongCodesPersistAndResend(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "attempts@example.test", 2)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := r.Verify(ctx, g.Registration.ID, g.Token, "bad"); !errors.Is(err, ErrVerificationCode) {
			t.Fatal("failed attempt not recorded")
		}
	}
	code := queuedRegistrationCode(t, r, g.Registration.ID)
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); !errors.Is(err, errEmailLimit) {
		t.Fatal("attempt limit bypassed")
	}
	if _, err := r.Resend(ctx, g.Registration.ID, g.Token); !errors.Is(err, errEmailLimit) {
		t.Fatal("cooldown bypassed")
	}
	*now = now.Add(time.Minute)
	if _, err := r.Resend(ctx, g.Registration.ID, g.Token); err != nil {
		t.Fatal(err)
	}
	newCode := queuedRegistrationCode(t, r, g.Registration.ID)
	if newCode != code {
		if err := r.Verify(ctx, g.Registration.ID, g.Token, code); !errors.Is(err, ErrVerificationCode) {
			t.Fatal("previous code accepted")
		}
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, newCode); err != nil {
		t.Fatal("resend failed to unlock attempts")
	}
}

func TestRegistrationActivationRollsBackAsUnit(t *testing.T) {
	r, invite, _ := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "rollback@example.test", 3)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
		t.Fatal(err)
	}
	code := queuedRegistrationCode(t, r, g.Registration.ID)
	if _, err := r.store.db.Exec(`CREATE TRIGGER reject_activation BEFORE INSERT ON accounts BEGIN SELECT RAISE(ABORT,'test failure');END`); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); !errors.Is(err, ErrUnavailable) {
		t.Fatal("insertion failure ignored")
	}
	if outboxCount(t, r.queue) != 1 {
		t.Fatal("rollback lost queued code")
	}
	if _, err := r.store.VerifyInvitation(ctx, invite.Secret, invitationEmail(t, "rollback@example.test")); err != nil {
		t.Fatal("rollback consumed invitation")
	}
	if _, err := r.store.db.Exec("DROP TRIGGER reject_activation"); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); err != nil {
		t.Fatal("rollback consumed verification code")
	}
}

func TestRegistrationBootstrapCompetition(t *testing.T) {
	r, first, _ := registrationFixture(t)
	ctx := context.Background()
	second, err := r.store.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	one := createRegistrationTest(t, r, first, "one@example.test", 4)
	two := createRegistrationTest(t, r, second, "two@example.test", 5)
	for _, g := range []RegistrationGrant{one, two} {
		if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
			t.Fatal(err)
		}
	}
	codes := []string{queuedRegistrationCode(t, r, one.Registration.ID), queuedRegistrationCode(t, r, two.Registration.ID)}
	grants := []RegistrationGrant{one, two}
	var failures [2]error
	var group sync.WaitGroup
	for i, g := range grants {
		group.Add(1)
		go func(i int, g RegistrationGrant) {
			defer group.Done()
			failures[i] = r.Verify(ctx, g.Registration.ID, g.Token, codes[i])
		}(i, g)
	}
	group.Wait()
	success := 0
	for _, err := range failures {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrRegistrationToken) {
			t.Fatal("unexpected competing result")
		}
	}
	if success != 1 {
		t.Fatal("multiple bootstrap admins activated")
	}
	var accounts, pendings int
	if err := r.store.db.QueryRow("SELECT count(*) FROM accounts").Scan(&accounts); err != nil || accounts != 1 {
		t.Fatal("wrong account count")
	}
	if err := r.store.db.QueryRow("SELECT count(*) FROM registrations WHERE status!='verified'").Scan(&pendings); err != nil || pendings != 0 {
		t.Fatal("competing administrator not invalidated")
	}
	if outboxCount(t, r.queue) != 0 {
		t.Fatal("competing administrator email retained")
	}
}

func TestRegistrationRevocationAndCancellation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		r, invite, _ := registrationFixture(t)
		ctx := context.Background()
		g := createRegistrationTest(t, r, invite, "cancel@example.test", 6)
		if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
			t.Fatal(err)
		}
		if revoke {
			if err := r.store.RevokeInvitation(ctx, invite.Invitation.ID); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := r.Cancel(ctx, g.Registration.ID, g.Token); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := r.Get(ctx, g.Registration.ID, g.Token); !errors.Is(err, ErrRegistrationToken) {
			t.Fatal("cancelled capability remained valid")
		}
		if outboxCount(t, r.queue) != 0 {
			t.Fatal("cancelled registration email retained")
		}
		if !revoke {
			if _, err := r.store.VerifyInvitation(ctx, invite.Secret, invitationEmail(t, "cancel@example.test")); err != nil {
				t.Fatal("cancellation consumed invite")
			}
		}
	}
}

func TestRegistrationTokenContextAndExpiry(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "context@example.test", 7)
	if _, err := r.Get(ctx, g.Registration.ID, protocol.NewSecret()); !errors.Is(err, ErrRegistrationToken) {
		t.Fatal("wrong capability accepted")
	}
	m := registrationMaterialTest(t, r, g)
	m.EpochID = protocol.ID{8}
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, m); !errors.Is(err, ErrRegistrationMaterial) {
		t.Fatal("mismatched envelope accepted")
	}
	*now = g.Registration.ExpiresAt
	if _, err := r.Get(ctx, g.Registration.ID, g.Token); !errors.Is(err, ErrRegistrationExpired) {
		t.Fatal("expired registration accepted")
	}
}

func TestRegistrationAnonymousQuotasIncludeInvalidInvites(t *testing.T) {
	r, invite, _ := registrationFixture(t)
	ctx := context.Background()
	ip := netip.MustParseAddr("127.0.0.1")
	email := invitationEmail(t, "quota@example.test")
	for i := 0; i < 3; i++ {
		if _, err := r.Create(ctx, protocol.NewSecret(), email, protocol.ID{1}, ip); !errors.Is(err, ErrInvalidInvitation) {
			t.Fatal("bad invite response changed")
		}
	}
	if _, err := r.Create(ctx, invite.Secret, email, protocol.ID{1}, ip); !errors.Is(err, ErrRegistrationLimit) {
		t.Fatal("invalid invites bypassed email quota")
	}
}

func insertUserInvitationTest(t *testing.T, r *Registrations) InvitationGrant {
	t.Helper()
	id := randomEmailID()
	secret := protocol.NewSecret()
	digest, _ := invitationDigest(secret)
	now := r.store.now().UTC()
	if _, err := r.store.db.Exec(`INSERT INTO invitations(invitation_id,secret_digest,scope,created_at_ms,expires_at_ms) VALUES(?,?,'user',?,?)`, id[:], digest[:], now.UnixMilli(), now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	return InvitationGrant{Invitation: Invitation{ID: id, Scope: "user", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Status: "active"}, Secret: secret}
}

func TestRegistrationExistingEmailDoesNotSendOrCreateAccount(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "existing@example.test", 10)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, queuedRegistrationCode(t, r, g.Registration.ID)); err != nil {
		t.Fatal(err)
	}
	second := createRegistrationTest(t, r, insertUserInvitationTest(t, r), "existing@example.test", 11)
	if state, err := r.PutMaterial(ctx, second.Registration.ID, second.Token, registrationMaterialTest(t, r, second)); err != nil || state.Status != "verification_pending" {
		t.Fatal("existing email exposed through material response")
	}
	if outboxCount(t, r.queue) != 0 {
		t.Fatal("existing account received unsolicited email")
	}
	*now = now.Add(time.Minute)
	if _, err := r.Resend(ctx, second.Registration.ID, second.Token); err != nil {
		t.Fatal("existing email exposed through resend")
	}
	if outboxCount(t, r.queue) != 0 {
		t.Fatal("existing account received resend")
	}
	for i := 0; i < 5; i++ {
		if err := r.Verify(ctx, second.Registration.ID, second.Token, "malformed"); !errors.Is(err, ErrVerificationCode) {
			t.Fatal("existing email exposed through code response")
		}
	}
	if err := r.Verify(ctx, second.Registration.ID, second.Token, "00000000"); !errors.Is(err, errEmailLimit) {
		t.Fatal("suppressed registration bypassed attempt cap")
	}
	var count int
	if err := r.store.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 1 {
		t.Fatal("duplicate account created")
	}
}

func TestRegistrationConcurrentIdenticalMaterialQueuesOnce(t *testing.T) {
	r, invite, _ := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "material-race@example.test", 12)
	m := registrationMaterialTest(t, r, g)
	var failures [2]error
	var group sync.WaitGroup
	for i := range failures {
		group.Add(1)
		go func(i int) { defer group.Done(); _, failures[i] = r.PutMaterial(ctx, g.Registration.ID, g.Token, m) }(i)
	}
	group.Wait()
	for _, err := range failures {
		if err != nil {
			t.Fatal("identical concurrent material rejected")
		}
	}
	var emissions int
	if err := r.store.db.QueryRow("SELECT emissions FROM email_verifications").Scan(&emissions); err != nil || emissions != 1 || outboxCount(t, r.queue) != 1 {
		t.Fatal("concurrent material emitted duplicate code")
	}
}

func TestRegistrationInvitationFailureRollsBackAccount(t *testing.T) {
	r, invite, _ := registrationFixture(t)
	ctx := context.Background()
	g := createRegistrationTest(t, r, invite, "invite-failure@example.test", 13)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
		t.Fatal(err)
	}
	code := queuedRegistrationCode(t, r, g.Registration.ID)
	if _, err := r.store.db.Exec(`CREATE TRIGGER reject_invite BEFORE UPDATE OF consumed_at_ms ON invitations BEGIN SELECT RAISE(ABORT,'test failure');END`); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invitation failure ignored")
	}
	var count int
	if err := r.store.db.QueryRow("SELECT count(*) FROM accounts").Scan(&count); err != nil || count != 0 {
		t.Fatal("failed invite consumption left account")
	}
	if _, err := r.store.db.Exec("DROP TRIGGER reject_invite"); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); err != nil {
		t.Fatal("rollback did not restore code")
	}
}

func TestRegistrationPendingQuotaAndCollection(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	for i := 1; i <= 5; i++ {
		email := invitationEmail(t, fmt.Sprintf("pending%d@example.test", i))
		if _, err := r.Create(ctx, invite.Secret, email, protocol.ID{byte(i)}, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Create(ctx, invite.Secret, invitationEmail(t, "extra@example.test"), protocol.ID{6}, netip.MustParseAddr("192.0.2.6")); !errors.Is(err, ErrRegistrationLimit) {
		t.Fatal("per-invitation quota bypassed")
	}
	*now = now.Add(24 * time.Hour)
	if _, err := r.Create(ctx, invite.Secret, invitationEmail(t, "extra@example.test"), protocol.ID{6}, netip.MustParseAddr("192.0.2.6")); err != nil {
		t.Fatal("expired pending records did not release quota")
	}
	var count int
	if err := r.store.db.QueryRow("SELECT count(*) FROM registrations").Scan(&count); err != nil || count != 1 {
		t.Fatal("expired pending records not collected")
	}
}

func TestRegistrationGlobalPendingQuota(t *testing.T) {
	r, first, _ := registrationFixture(t)
	ctx := context.Background()
	n := 0
	for batch := 0; batch < 20; batch++ {
		invite := first
		if batch > 0 {
			invite = insertUserInvitationTest(t, r)
		}
		for i := 0; i < 5; i++ {
			n++
			email := invitationEmail(t, fmt.Sprintf("global%d@example.test", n))
			if _, err := r.Create(ctx, invite.Secret, email, protocol.ID{byte(n)}, netip.AddrFrom4([4]byte{192, 0, 2, byte(n)})); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := r.Create(ctx, insertUserInvitationTest(t, r).Secret, invitationEmail(t, "global-extra@example.test"), protocol.ID{101}, netip.MustParseAddr("192.0.2.101")); !errors.Is(err, ErrRegistrationLimit) {
		t.Fatal("global pending quota bypassed")
	}
}

func TestRegistrationSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	macKey, encKey, quotaKey := protocol.NewSecret(), protocol.NewSecret(), protocol.NewSecret()
	q, _ := NewEmailQueue(s, macKey, encKey, quotaKey)
	r, _ := NewRegistrations(s, q, auth.NewEngine())
	invite, err := s.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	g := createRegistrationTest(t, r, invite, "restart-flow@example.test", 14)
	m := registrationMaterialTest(t, r, g)
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, m); err != nil {
		t.Fatal(err)
	}
	code := queuedRegistrationCode(t, r, g.Registration.ID)
	if err := r.Verify(ctx, g.Registration.ID, g.Token, "bad"); !errors.Is(err, ErrVerificationCode) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	q, _ = NewEmailQueue(s, macKey, encKey, quotaKey)
	r, _ = NewRegistrations(s, q, auth.NewEngine())
	if state, err := r.Get(ctx, g.Registration.ID, g.Token); err != nil || state.Status != "verification_pending" {
		t.Fatal("restart lost capability or state")
	}
	if _, err := r.PutMaterial(ctx, g.Registration.ID, g.Token, m); err != nil {
		t.Fatal("material retry failed after restart")
	}
	if code != queuedRegistrationCode(t, r, g.Registration.ID) {
		t.Fatal("restart or retry replaced code")
	}
	var attempts int
	if err := s.db.QueryRow("SELECT attempts FROM email_verifications").Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("restart reset attempts")
	}
	if err := r.Verify(ctx, g.Registration.ID, g.Token, code); err != nil {
		t.Fatal("activation failed after restart")
	}
}
