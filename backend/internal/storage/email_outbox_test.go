package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/mailer"
	"passwordmanager/internal/protocol"
)

var _ VerificationSender = (*mailer.Gmail)(nil)

type senderFunc func(context.Context, protocol.Email, auth.EmailCode, time.Time) error

func (f senderFunc) SendVerification(ctx context.Context, to protocol.Email, code auth.EmailCode, expires time.Time) error {
	return f(ctx, to, code, expires)
}

func outboxFixture(t *testing.T) (*EmailQueue, *time.Time) {
	t.Helper()
	s, now := invitationStore(t)
	*now = time.Now().UTC().Truncate(time.Millisecond)
	q, err := NewEmailQueue(s, protocol.NewSecret(), protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	return q, now
}

func enqueueTest(t *testing.T, q *EmailQueue, id protocol.ID, to protocol.Email, deadline time.Time) error {
	t.Helper()
	tx, err := q.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = q.issueTx(context.Background(), tx, id, to, deadline)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func outboxCount(t *testing.T, q *EmailQueue) int {
	t.Helper()
	var count int
	if err := q.store.db.QueryRow("SELECT count(*) FROM email_outbox").Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestOutboxEncryptedDeliveryAndRemoval(t *testing.T) {
	q, now := outboxFixture(t)
	to := invitationEmail(t, "person@example.test")
	id := protocol.ID{1}
	if err := enqueueTest(t, q, id, to, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var payload, mac []byte
	if err := q.store.db.QueryRow("SELECT payload FROM email_outbox").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(payload, []byte(to.String())) {
		t.Fatal("plaintext recipient in outbox")
	}
	if err := q.store.db.QueryRow("SELECT code_mac FROM email_verifications").Scan(&mac); err != nil {
		t.Fatal(err)
	}
	var expected [32]byte
	copy(expected[:], mac)
	calls := 0
	sender := senderFunc(func(ctx context.Context, got protocol.Email, code auth.EmailCode, expires time.Time) error {
		calls++
		if ctx.Err() != nil || got != to || !expires.Equal(now.Add(10*time.Minute)) || !auth.VerifyEmailCode(q.macKey, id, code, expected) {
			t.Fatal("incorrect decrypted delivery")
		}
		text, _ := code.DeliveryValue()
		if bytes.Contains(payload, []byte(text)) {
			t.Fatal("plaintext code in outbox")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 16*time.Second {
			t.Fatal("unbounded send")
		}
		return nil
	})
	if handled, err := q.DeliverNext(context.Background(), sender); !handled || err != nil {
		t.Fatal("delivery failed")
	}
	if outboxCount(t, q) != 0 || calls != 1 {
		t.Fatal("delivered payload retained")
	}
	if handled, err := q.DeliverNext(context.Background(), sender); handled || err != nil {
		t.Fatal("empty queue delivered again")
	}
	// Sending must not consume the verification challenge or release hour quotas.
	var consumed, emissions int
	if err := q.store.db.QueryRow("SELECT consumed FROM email_verifications").Scan(&consumed); err != nil || consumed != 0 {
		t.Fatal("sending activated verification")
	}
	if err := q.store.db.QueryRow("SELECT count(*) FROM email_delivery_emissions").Scan(&emissions); err != nil || emissions != 1 {
		t.Fatal("delivery released quota")
	}
}

func TestOutboxRetryBackoffAndBound(t *testing.T) {
	q, now := outboxFixture(t)
	if err := enqueueTest(t, q, protocol.ID{2}, invitationEmail(t, "retry@example.test"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	calls := 0
	sender := senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error {
		calls++
		return errors.New("sensitive SMTP diagnostic")
	})
	for attempt := 1; attempt <= 5; attempt++ {
		if handled, err := q.DeliverNext(context.Background(), sender); !handled || !errors.Is(err, ErrEmailDelivery) || strings.Contains(err.Error(), "sensitive") {
			t.Fatal("failed delivery leaked error or failed claim")
		}
		if attempt == 5 {
			break
		}
		var available int64
		if err := q.store.db.QueryRow("SELECT available_at_ms FROM email_outbox").Scan(&available); err != nil {
			t.Fatal(err)
		}
		delay := 15 * time.Second * time.Duration(1<<uint(attempt-1))
		if available != now.Add(delay).UnixMilli() {
			t.Fatal("incorrect retry backoff")
		}
		if handled, err := q.DeliverNext(context.Background(), sender); handled || err != nil {
			t.Fatal("retried before scheduled time")
		}
		*now = time.UnixMilli(available).UTC()
	}
	if calls != 5 || outboxCount(t, q) != 0 {
		t.Fatal("unbounded retries or exhausted payload retained")
	}
}

func TestOutboxTamperAndWrongKeyFailClosed(t *testing.T) {
	for _, mutation := range []string{"payload", "message", "key", "instance", "expiry"} {
		t.Run(mutation, func(t *testing.T) {
			q, now := outboxFixture(t)
			id := protocol.ID{3}
			if err := enqueueTest(t, q, id, invitationEmail(t, "tamper@example.test"), now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "payload":
				var value []byte
				if err := q.store.db.QueryRow("SELECT payload FROM email_outbox").Scan(&value); err != nil {
					t.Fatal(err)
				}
				value[len(value)-1] ^= 1
				if _, err := q.store.db.Exec("UPDATE email_outbox SET payload=?", value); err != nil {
					t.Fatal(err)
				}
			case "message":
				newID := randomEmailID()
				if _, err := q.store.db.Exec("UPDATE email_outbox SET message_id=?", newID[:]); err != nil {
					t.Fatal(err)
				}
			case "key":
				var err error
				q, err = NewEmailQueue(q.store, q.macKey, protocol.NewSecret(), q.quotaKey)
				if err != nil {
					t.Fatal(err)
				}
			case "instance":
				q.store.instance.ServerID = protocol.ID{99}
			case "expiry":
				// Change both rows to survive the stale-emission filter; AAD must
				// still reject the changed expiry rather than delivering plaintext.
				if _, err := q.store.db.Exec("UPDATE email_outbox SET expires_at_ms=expires_at_ms+1"); err != nil {
					t.Fatal(err)
				}
				if _, err := q.store.db.Exec("UPDATE email_verifications SET expires_at_ms=expires_at_ms+1"); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			sender := senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error { calls++; return nil })
			if handled, err := q.DeliverNext(context.Background(), sender); !handled || !errors.Is(err, ErrEmailDelivery) {
				t.Fatal("tampered payload not rejected")
			}
			if calls != 0 || outboxCount(t, q) != 0 {
				t.Fatal("tampered message delivered or retained")
			}
		})
	}
}

func TestOutboxAtomicRollback(t *testing.T) {
	q, now := outboxFixture(t)
	tx, err := q.store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.issueTx(context.Background(), tx, protocol.ID{4}, invitationEmail(t, "rollback@example.test"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"email_outbox", "email_verifications", "email_verification_emissions", "email_delivery_emissions"} {
		var count int
		if err := q.store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatal("rollback left code, quota or payload")
		}
	}
}

func TestOutboxLeaseRecoveryAfterRestart(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC().Truncate(time.Millisecond)
	s.now = func() time.Time { return now }
	macKey, encKey, quotaKey := protocol.NewSecret(), protocol.NewSecret(), protocol.NewSecret()
	q, err := NewEmailQueue(s, macKey, encKey, quotaKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := enqueueTest(t, q, protocol.ID{5}, invitationEmail(t, "restart@example.test"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	old, found, err := q.claim(context.Background())
	if err != nil || !found {
		t.Fatal("initial claim failed")
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
	q, err = NewEmailQueue(s, macKey, encKey, quotaKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := q.claim(context.Background()); err != nil || found {
		t.Fatal("live lease reclaimed after restart")
	}
	now = now.Add(time.Minute)
	current, found, err := q.claim(context.Background())
	if err != nil || !found || current.attempts != 2 {
		t.Fatal("expired lease not recovered")
	}
	if err := q.finish(context.Background(), old, true, nil); err != nil {
		t.Fatal(err)
	}
	if outboxCount(t, q) != 1 {
		t.Fatal("stale worker deleted reclaimed job")
	}
	if err := q.finish(context.Background(), current, true, nil); err != nil {
		t.Fatal(err)
	}
	if outboxCount(t, q) != 0 {
		t.Fatal("current lease could not finish")
	}
}

func TestOutboxResendWhileSMTPIsRunning(t *testing.T) {
	q, now := outboxFixture(t)
	id := protocol.ID{6}
	to := invitationEmail(t, "race@example.test")
	deadline := now.Add(time.Hour)
	if err := enqueueTest(t, q, id, to, deadline); err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	sender := senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error {
		close(started)
		<-release
		return nil
	})
	go func() { _, err := q.DeliverNext(context.Background(), sender); done <- err }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("send did not start")
	}
	other := senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error {
		t.Error("concurrent worker sent leased job")
		return nil
	})
	if handled, err := q.DeliverNext(context.Background(), other); handled || err != nil {
		t.Fatal("concurrent claim succeeded")
	}
	// Read now only after the sender starts; it remains blocked until release.
	*now = now.Add(time.Minute)
	if err := enqueueTest(t, q, id, to, deadline); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if outboxCount(t, q) != 1 {
		t.Fatal("old SMTP completion deleted replacement")
	}
	if handled, err := q.DeliverNext(context.Background(), senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error { return nil })); !handled || err != nil {
		t.Fatal("replacement could not be sent")
	}
}

func TestOutboxExpiryAndConsumptionRemovePayload(t *testing.T) {
	for _, action := range []string{"expiry", "verify"} {
		t.Run(action, func(t *testing.T) {
			q, now := outboxFixture(t)
			id := protocol.ID{7}
			if err := enqueueTest(t, q, id, invitationEmail(t, "expire@example.test"), now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if action == "expiry" {
				*now = now.Add(10 * time.Minute)
			} else {
				job, found, err := q.claim(context.Background())
				if err != nil || !found {
					t.Fatal("claim failed")
				}
				plain, err := q.seal.Open(nil, nil, job.payload, q.aad(job.registration, job.message, job.emission, job.expires))
				if err != nil {
					t.Fatal(err)
				}
				defer clear(plain)
				text := string(plain[len(plain)-8:])
				if verifyTestCode(t, q.store, q.macKey, id, text) != emailAccepted {
					t.Fatal("verification failed")
				}
			}
			calls := 0
			if handled, err := q.DeliverNext(context.Background(), senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error { calls++; return nil })); handled || err != nil {
				t.Fatal("obsolete message claimed")
			}
			if outboxCount(t, q) != 0 || calls != 0 {
				t.Fatal("obsolete payload retained or delivered")
			}
		})
	}
}

func TestOutboxRecipientAndGlobalQuotas(t *testing.T) {
	q, now := outboxFixture(t)
	to := invitationEmail(t, "quota@example.test")
	deadline := now.Add(24 * time.Hour)
	for i := 1; i <= 10; i++ {
		if err := enqueueTest(t, q, protocol.ID{byte(i)}, to, deadline); err != nil {
			t.Fatal(err)
		}
	}
	if err := enqueueTest(t, q, protocol.ID{11}, to, deadline); !errors.Is(err, errEmailLimit) {
		t.Fatal("recipient quota bypassed")
	}
	for i := 11; i <= 100; i++ {
		address := invitationEmail(t, fmt.Sprintf("person%d@example.test", i))
		if err := enqueueTest(t, q, protocol.ID{byte(i)}, address, deadline); err != nil {
			t.Fatal(err)
		}
	}
	if err := enqueueTest(t, q, protocol.ID{101}, invitationEmail(t, "extra@example.test"), deadline); !errors.Is(err, errEmailLimit) {
		t.Fatal("global quota bypassed")
	}
	*now = now.Add(time.Hour)
	if err := enqueueTest(t, q, protocol.ID{101}, to, deadline); err != nil {
		t.Fatal("rolling quota did not expire")
	}
	if outboxCount(t, q) != 1 {
		t.Fatal("expired messages not purged")
	}
}

func TestOutboxConfigurationAndRedaction(t *testing.T) {
	q, _ := outboxFixture(t)
	if _, err := NewEmailQueue(q.store, q.macKey, q.macKey, q.quotaKey); !errors.Is(err, ErrEmailQueueConfiguration) {
		t.Fatal("reused keys accepted")
	}
	if _, err := NewEmailQueue(nil, q.macKey, protocol.NewSecret(), q.quotaKey); !errors.Is(err, ErrEmailQueueConfiguration) {
		t.Fatal("nil store accepted")
	}
	if _, err := NewEmailQueue(q.store, protocol.Secret{}, protocol.NewSecret(), q.quotaKey); !errors.Is(err, ErrEmailQueueConfiguration) {
		t.Fatal("invalid key accepted")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, q) != "[REDACTED]" {
			t.Fatal("queue diagnostic leaked")
		}
	}
	data, err := json.Marshal(q)
	if err != nil || string(data) != `"[REDACTED]"` {
		t.Fatal("queue JSON leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.DeliverNext(ctx, senderFunc(func(context.Context, protocol.Email, auth.EmailCode, time.Time) error {
		t.Error("cancelled delivery ran")
		return nil
	})); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled request claimed message")
	}
}

func TestOutboxFailedInsertRollsBackResend(t *testing.T) {
	q, now := outboxFixture(t)
	id := protocol.ID{22}
	to := invitationEmail(t, "rollback-resend@example.test")
	deadline := now.Add(time.Hour)
	if err := enqueueTest(t, q, id, to, deadline); err != nil {
		t.Fatal(err)
	}
	var oldMAC, oldPayload []byte
	if err := q.store.db.QueryRow("SELECT code_mac FROM email_verifications").Scan(&oldMAC); err != nil {
		t.Fatal(err)
	}
	if err := q.store.db.QueryRow("SELECT payload FROM email_outbox").Scan(&oldPayload); err != nil {
		t.Fatal(err)
	}
	if _, err := q.store.db.Exec(`CREATE TRIGGER reject_outbox BEFORE INSERT ON email_outbox BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END`); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(time.Minute)
	if err := enqueueTest(t, q, id, to, deadline); !errors.Is(err, ErrUnavailable) {
		t.Fatal("storage failure was ignored")
	}
	var mac, payload []byte
	var emissions, quota int
	if err := q.store.db.QueryRow("SELECT code_mac,emissions FROM email_verifications").Scan(&mac, &emissions); err != nil {
		t.Fatal(err)
	}
	if err := q.store.db.QueryRow("SELECT payload FROM email_outbox").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if err := q.store.db.QueryRow("SELECT count(*) FROM email_delivery_emissions").Scan(&quota); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mac, oldMAC) || !bytes.Equal(payload, oldPayload) || emissions != 1 || quota != 1 {
		t.Fatal("failed resend changed previous code, payload or quota")
	}
}

func TestOutboxCancelledSendReleasesLease(t *testing.T) {
	q, now := outboxFixture(t)
	if err := enqueueTest(t, q, protocol.ID{23}, invitationEmail(t, "cancel@example.test"), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sender := senderFunc(func(ctx context.Context, _ protocol.Email, _ auth.EmailCode, _ time.Time) error {
		cancel()
		return ctx.Err()
	})
	if handled, err := q.DeliverNext(ctx, sender); !handled || !errors.Is(err, ErrEmailDelivery) {
		t.Fatal("cancelled delivery not recorded")
	}
	var lease []byte
	var available int64
	if err := q.store.db.QueryRow("SELECT lease_token,available_at_ms FROM email_outbox").Scan(&lease, &available); err != nil {
		t.Fatal(err)
	}
	if lease != nil || available != now.Add(15*time.Second).UnixMilli() {
		t.Fatal("cancellation left job locked")
	}
}

func TestOutboxCapacity(t *testing.T) {
	q, now := outboxFixture(t)
	for i := 1; i <= 100; i++ {
		to := invitationEmail(t, fmt.Sprintf("capacity%d@example.test", i))
		if err := enqueueTest(t, q, protocol.ID{byte(i)}, to, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	// Isolate queue capacity from the independent global hourly emission cap.
	if _, err := q.store.db.Exec("DELETE FROM email_delivery_emissions"); err != nil {
		t.Fatal(err)
	}
	if err := enqueueTest(t, q, protocol.ID{101}, invitationEmail(t, "over-capacity@example.test"), now.Add(time.Hour)); !errors.Is(err, ErrEmailQueueFull) {
		t.Fatal("queue capacity bypassed")
	}
	if outboxCount(t, q) != 100 {
		t.Fatal("queue grew past capacity")
	}
}

func TestOutboxMigrationPreservesPendingCode(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	identity := s.Instance()
	now := time.Now().UTC().Truncate(time.Millisecond)
	s.now = func() time.Time { return now }
	key := protocol.NewSecret()
	id := protocol.ID{24}
	code, _, err := issueTestCode(t, s, key, id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	text, _ := code.DeliveryValue()
	for _, query := range []string{"DROP TABLE admin_panel_key", "DROP TABLE vault_writes", "DROP TABLE vault_objects", "DROP TABLE vault_state", "DROP TABLE auth_rate_events", "DROP TABLE refresh_tokens", "DROP TABLE sessions", "DROP TABLE registration_attempts", "DROP TABLE registrations", "DROP TABLE accounts", "DROP TABLE operational_key_binding", "DROP TABLE email_delivery_emissions", "DROP TABLE email_outbox", "DELETE FROM schema_migrations WHERE version>=4"} {
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
	s.now = func() time.Time { return now }
	if s.Instance() != identity {
		t.Fatal("upgrade changed identity")
	}
	if verifyTestCode(t, s, key, id, text) != emailAccepted {
		t.Fatal("upgrade lost pending verification")
	}
}
