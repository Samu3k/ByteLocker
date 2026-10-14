package storage

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

func vaultEnvelopeTest(t *testing.T, s *Sessions, r LoginRequest, id protocol.ID, generation uint64, payload int) *protocol.Envelope {
	t.Helper()
	raw := make([]byte, 148+payload+16)
	copy(raw, "PME1")
	raw[4] = 3
	binary.BigEndian.PutUint16(raw[6:8], 1)
	server := s.store.Instance().ServerID
	copy(raw[8:24], server[:])
	copy(raw[24:40], r.AccountID[:])
	copy(raw[40:56], r.VaultID[:])
	epoch := protocol.ID{9}
	copy(raw[56:72], epoch[:])
	copy(raw[72:88], id[:])
	binary.BigEndian.PutUint64(raw[88:96], generation)
	binary.BigEndian.PutUint32(raw[96:100], uint32(payload))
	// Synthetic ciphertext and tag only; the server cannot validate a GCM tag.
	for i := 148; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	e, err := protocol.ParseEnvelope(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func vaultWriteTest(t *testing.T, s *Sessions, r LoginRequest, id, operation protocol.ID, generation uint64, payload int) VaultWrite {
	t.Helper()
	e := vaultEnvelopeTest(t, s, r, id, generation, payload)
	epoch := protocol.ID{9}
	request := VaultWrite{OperationID: operation, EpochID: epoch, ObjectID: id, Envelope: e}
	method, path, condition := "POST", "/api/v1/vault/objects", ""
	if generation > 1 {
		tag := protocol.ObjectETag{EpochID: epoch, Revision: protocol.Counter(generation - 1)}
		request.Base = &tag
		method = "PUT"
		path += "/" + id.String()
		condition = tag.String()
	}
	request.Fingerprint = VaultFingerprint(method, path, condition, []byte(e.Base64URL()))
	return request
}
func TestVaultCRUDIdempotencyAndSnapshot(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	state, err := s.VaultState(ctx, g.AccessToken)
	if err != nil || state.Revision != 0 || state.ObjectCount != 0 || state.StoredBytes != 0 {
		t.Fatal("nonempty initial vault")
	}
	first := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{101}, 1, 32)
	saved, err := s.WriteVault(ctx, g.AccessToken, first)
	if err != nil || saved.Revision != 1 || saved.Sequence != 1 {
		t.Fatal("create failed")
	}
	again, err := s.WriteVault(ctx, g.AccessToken, first)
	if err != nil || again != saved {
		t.Fatal("identical write not replayed")
	}
	conflict := first
	conflict.Fingerprint[0] ^= 1
	if _, err := s.WriteVault(ctx, g.AccessToken, conflict); !errors.Is(err, ErrVaultIdempotency) {
		t.Fatal("changed retry accepted")
	}
	duplicate := first
	duplicate.OperationID = protocol.ID{102}
	if _, err := s.WriteVault(ctx, g.AccessToken, duplicate); !errors.Is(err, ErrVaultConflict) {
		t.Fatal("duplicate object accepted")
	}
	item, err := s.VaultObject(ctx, g.AccessToken, first.ObjectID)
	if err != nil || item.Envelope != first.Envelope.Base64URL() {
		t.Fatal("ciphertext changed")
	}
	update := vaultWriteTest(t, s, r, first.ObjectID, protocol.ID{103}, 2, 16)
	second, err := s.WriteVault(ctx, g.AccessToken, update)
	if err != nil || second.Revision != 2 || second.Sequence != 2 {
		t.Fatal("update failed")
	}
	stale := update
	stale.OperationID = protocol.ID{104}
	if _, err := s.WriteVault(ctx, g.AccessToken, stale); !errors.Is(err, ErrVaultPrecondition) {
		t.Fatal("lost update accepted")
	}
	again, err = s.WriteVault(ctx, g.AccessToken, first)
	if err != nil || again != saved {
		t.Fatal("historical retry changed response")
	}
	state, err = s.VaultState(ctx, g.AccessToken)
	if err != nil || state.Revision != 2 || state.ObjectCount != 1 || state.StoredBytes != protocol.Counter(len(update.Envelope.Bytes())) {
		t.Fatal("accounting mismatch")
	}
	if _, err := s.SyncVault(ctx, g.AccessToken, VaultSyncRequest{EpochID: state.EpochID, Ceiling: 1, Limit: 50}); !errors.Is(err, ErrVaultSnapshot) {
		t.Fatal("stale snapshot accepted")
	}
	other := state.EpochID
	other[0] ^= 1
	if _, err := s.SyncVault(ctx, g.AccessToken, VaultSyncRequest{EpochID: other, Ceiling: 2, Limit: 50}); !errors.Is(err, ErrVaultEpoch) {
		t.Fatal("wrong epoch accepted")
	}
	page, err := s.SyncVault(ctx, g.AccessToken, VaultSyncRequest{EpochID: state.EpochID, Ceiling: 2, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].Revision != 2 || page.Next != nil {
		t.Fatal("sync did not return current version")
	}
	if _, err := s.VaultObject(ctx, g.AccessToken, protocol.ID{99}); !errors.Is(err, ErrVaultNotFound) {
		t.Fatal("unknown object leaked")
	}
	if err := s.Logout(ctx, g.AccessToken); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteVault(ctx, g.AccessToken, first); !errors.Is(err, ErrAuthentication) {
		t.Fatal("idempotency bypassed authentication")
	}
}
func TestVaultPaginationAndConcurrentWriters(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	for i := 1; i <= 3; i++ {
		if _, err := s.WriteVault(ctx, g.AccessToken, vaultWriteTest(t, s, r, protocol.ID{byte(i)}, protocol.ID{byte(100 + i)}, 1, 32)); err != nil {
			t.Fatal(err)
		}
	}
	query := VaultSyncRequest{EpochID: protocol.ID{9}, Ceiling: 3, Limit: 1}
	for i := 1; i <= 3; i++ {
		page, err := s.SyncVault(ctx, g.AccessToken, query)
		if err != nil || len(page.Items) != 1 || page.Items[0].Sequence != protocol.Counter(i) {
			t.Fatal("pagination skipped/reordered item")
		}
		if i < 3 {
			if page.Next == nil {
				t.Fatal("missing next")
			}
			query.After = *page.Next
		} else if page.Next != nil {
			t.Fatal("nonfinal last page")
		}
	}
	a := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{110}, 2, 33)
	b := a
	b.OperationID = protocol.ID{111}
	b.Fingerprint[0] ^= 1
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, write := range []VaultWrite{a, b} {
		wg.Go(func() { _, err := s.WriteVault(ctx, g.AccessToken, write); results <- err })
	}
	wg.Wait()
	close(results)
	success, stale := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrVaultPrecondition) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatal("concurrent update overwrote data")
	}
	if _, err := s.SyncVault(ctx, g.AccessToken, query); !errors.Is(err, ErrVaultSnapshot) {
		t.Fatal("write between pages not detected")
	}
	state, err := s.VaultState(ctx, g.AccessToken)
	if err != nil || state.Revision != 4 || state.ObjectCount != 3 {
		t.Fatal("concurrent accounting corrupted")
	}
}
func TestVaultContextRollbackAndQuotas(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	first := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{101}, 1, 32)
	for _, field := range []string{"account", "vault", "epoch", "object", "generation"} {
		q := first
		bad := r
		switch field {
		case "account":
			bad.AccountID = protocol.ID{77}
			q.Envelope = vaultEnvelopeTest(t, s, bad, q.ObjectID, 1, 32)
		case "vault":
			bad.VaultID = protocol.ID{78}
			q.Envelope = vaultEnvelopeTest(t, s, bad, q.ObjectID, 1, 32)
		case "epoch":
			q.EpochID = protocol.ID{88}
		case "object":
			q.ObjectID = protocol.ID{44}
		case "generation":
			q.Envelope = vaultEnvelopeTest(t, s, r, q.ObjectID, 2, 32)
		}
		_, err := s.WriteVault(ctx, g.AccessToken, q)
		if !errors.Is(err, ErrInvalidVault) && !errors.Is(err, ErrVaultEpoch) {
			t.Fatalf("invalid context accepted: %s %v", field, err)
		}
	}
	if _, err := s.store.db.Exec("CREATE TRIGGER fail_vault BEFORE INSERT ON vault_writes BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteVault(ctx, g.AccessToken, first); !errors.Is(err, ErrUnavailable) {
		t.Fatal("injected failure ignored")
	}
	state, err := s.VaultState(ctx, g.AccessToken)
	if err != nil || state.Revision != 0 || state.ObjectCount != 0 {
		t.Fatal("partial write committed")
	}
	if _, err := s.VaultObject(ctx, g.AccessToken, first.ObjectID); !errors.Is(err, ErrVaultNotFound) {
		t.Fatal("rollback retained object")
	}
	if _, err := s.store.db.Exec("DROP TRIGGER fail_vault"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WriteVault(ctx, g.AccessToken, first); err != nil {
		t.Fatal(err)
	}
	// Synthetic aggregate values exercise each quota boundary without creating
	// thousands of objects or filling the user's disk.
	for _, assignment := range []string{"object_count=10000", "stored_bytes=67108864", "revision=x'FFFFFFFFFFFFFFFF'"} {
		if _, err := s.store.db.Exec("UPDATE vault_state SET " + assignment); err != nil {
			t.Fatal(err)
		}
		q := vaultWriteTest(t, s, r, protocol.ID{2}, protocol.ID{102}, 1, 32)
		if _, err := s.WriteVault(ctx, g.AccessToken, q); !errors.Is(err, ErrVaultQuota) {
			t.Fatalf("quota bypass: %s", assignment)
		}
		if _, err := s.store.db.Exec("UPDATE vault_state SET object_count=1,stored_bytes=196,revision=?", counterBytes(1)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.store.db.Exec("UPDATE vault_objects SET revision=?", counterBytes(protocol.Counter(math.MaxUint64))); err != nil {
		t.Fatal(err)
	}
	q := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{104}, 2, 32)
	q.Base.Revision = protocol.Counter(math.MaxUint64)
	if _, err := s.WriteVault(ctx, g.AccessToken, q); !errors.Is(err, ErrVaultQuota) {
		t.Fatal("object revision overflow accepted")
	}
}
func TestVaultSyncByteBudget(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	for i := 1; i <= 4; i++ {
		if _, err := s.WriteVault(ctx, g.AccessToken, vaultWriteTest(t, s, r, protocol.ID{byte(i)}, protocol.ID{byte(100 + i)}, 1, protocol.MaxPlaintextSize)); err != nil {
			t.Fatal(err)
		}
	}
	query := VaultSyncRequest{EpochID: protocol.ID{9}, Ceiling: 4, Limit: 100}
	total := 0
	for {
		page, err := s.SyncVault(ctx, g.AccessToken, query)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(page)
		if err != nil || len(encoded) > maxSyncJSONBytes || len(page.Items) == 0 {
			t.Fatal("sync byte budget exceeded/no progress")
		}
		total += len(page.Items)
		if page.Next == nil {
			break
		}
		query.After = *page.Next
	}
	if total != 4 {
		t.Fatal("byte limited pagination lost data")
	}
}

func TestVaultAccountIsolationAndInstanceQuota(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	otherAccount, otherVault := protocol.ID{81}, protocol.ID{82}
	var raw []byte
	if err := s.store.db.QueryRow("SELECT password_envelope FROM accounts").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	copy(raw[24:40], otherAccount[:])
	copy(raw[40:56], otherVault[:])
	if _, err := s.store.db.Exec("INSERT INTO accounts(account_id,email,role,vault_id,epoch_id,descriptor,verifier,password_envelope,created_at_ms) SELECT ?,?,'user',?,epoch_id,descriptor,verifier,?,created_at_ms FROM accounts WHERE account_id=?", otherAccount[:], "other@example.test", otherVault[:], raw, r.AccountID[:]); err != nil {
		t.Fatal(err)
	}
	other := r
	other.AccountID = otherAccount
	other.VaultID = otherVault
	other.Email = invitationEmail(t, "other@example.test")
	foreign := sessionLogin(t, s, other)
	write := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{101}, 1, 32)
	if _, err := s.WriteVault(ctx, g.AccessToken, write); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VaultObject(ctx, foreign.AccessToken, write.ObjectID); !errors.Is(err, ErrVaultNotFound) {
		t.Fatal("cross-account object disclosed")
	}
	if _, err := s.WriteVault(ctx, foreign.AccessToken, write); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("foreign envelope accepted")
	}
	own := vaultWriteTest(t, s, other, protocol.ID{1}, protocol.ID{101}, 1, 32)
	if _, err := s.WriteVault(ctx, foreign.AccessToken, own); err != nil {
		t.Fatal("operation/object ID improperly shared across accounts")
	}
	page, err := s.SyncVault(ctx, foreign.AccessToken, VaultSyncRequest{EpochID: protocol.ID{9}, Ceiling: 1, Limit: 50})
	if err != nil || len(page.Items) != 1 || page.Items[0].Envelope != own.Envelope.Base64URL() {
		t.Fatal("sync disclosed foreign data")
	}
	if _, err := s.store.db.Exec("UPDATE vault_state SET stored_bytes=? WHERE account_id=?", maxInstanceVaultBytes, otherAccount[:]); err != nil {
		t.Fatal(err)
	}
	grow := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{102}, 2, 33)
	if _, err := s.WriteVault(ctx, g.AccessToken, grow); !errors.Is(err, ErrVaultQuota) {
		t.Fatal("global byte quota bypassed")
	}
	shrink := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{103}, 2, 16)
	if _, err := s.WriteVault(ctx, g.AccessToken, shrink); err != nil {
		t.Fatal("shrinking replacement incorrectly refused above quota")
	}
}

func TestVaultUnsignedSequencesAcrossSQLiteIntegerBoundary(t *testing.T) {
	s, r, _ := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	if _, err := s.VaultState(ctx, g.AccessToken); err != nil {
		t.Fatal(err)
	}
	start := protocol.Counter(math.MaxInt64 - 1)
	if _, err := s.store.db.Exec("UPDATE vault_state SET revision=?", counterBytes(start)); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		result, err := s.WriteVault(ctx, g.AccessToken, vaultWriteTest(t, s, r, protocol.ID{byte(i)}, protocol.ID{byte(100 + i)}, 1, 32))
		if err != nil || result.Sequence != start+protocol.Counter(i) {
			t.Fatal("unsigned sequence truncated")
		}
	}
	page, err := s.SyncVault(ctx, g.AccessToken, VaultSyncRequest{EpochID: protocol.ID{9}, Since: start, After: start, Ceiling: start + 2, Limit: 50})
	if err != nil || len(page.Items) != 2 || page.Items[0].Sequence != start+1 || page.Items[1].Sequence != start+2 {
		t.Fatal("unsigned range comparison/order incorrect")
	}
}

func TestVaultWriteRegistrySaturationAndCleanup(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	if _, err := s.store.db.Exec(`WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20000)
 INSERT INTO vault_writes(account_id,operation_id,fingerprint,response,expires_at_ms)
 SELECT ?,CAST(printf('%016d',x) AS BLOB),zeroblob(32),CAST('{}' AS BLOB),? FROM n`, r.AccountID[:], now.Add(48*time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	write := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{101}, 1, 32)
	if _, err := s.WriteVault(ctx, g.AccessToken, write); !errors.Is(err, ErrVaultWriteLimit) {
		t.Fatal("registry capacity bypassed")
	}
	state, err := s.VaultState(ctx, g.AccessToken)
	if err != nil || state.Revision != 0 || state.ObjectCount != 0 {
		t.Fatal("registry failure committed vault data")
	}
	*now = now.Add(48 * time.Hour)
	g = sessionLogin(t, s, r)
	if _, err := s.WriteVault(ctx, g.AccessToken, write); err != nil {
		t.Fatal("expired registry entries not reclaimed")
	}
	var count int
	if err := s.store.db.QueryRow("SELECT count(*) FROM vault_writes").Scan(&count); err != nil || count != 1 {
		t.Fatal("registry cleanup incorrect")
	}
}

func TestVaultPersistenceRetryExpiryAndMigration(t *testing.T) {
	s, r, now := sessionFixture(t)
	ctx := context.Background()
	g := sessionLogin(t, s, r)
	// Recreate schema 7, preserving an active session and account.
	for _, q := range []string{"DROP TABLE admin_panel_key", "DELETE FROM schema_migrations WHERE version=9", "DROP TABLE vault_writes", "DROP TABLE vault_objects", "DROP TABLE vault_state", "DELETE FROM schema_migrations WHERE version=8"} {
		if _, err := s.store.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var path string
	if err := s.store.db.QueryRow("SELECT file FROM pragma_database_list WHERE name='main'").Scan(&path); err != nil {
		t.Fatal(err)
	}
	reopen := func() {
		t.Helper()
		if err := s.store.Close(); err != nil {
			t.Fatal(err)
		}
		db, err := Open(ctx, filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		db.now = func() time.Time { return *now }
		s, err = NewSessions(db, s.engine, s.preloginKey, s.quotaKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	reopen()
	first := vaultWriteTest(t, s, r, protocol.ID{1}, protocol.ID{101}, 1, 32)
	expected, err := s.WriteVault(ctx, g.AccessToken, first)
	if err != nil {
		t.Fatal("migration damaged session")
	}
	reopen()
	replay, err := s.WriteVault(ctx, g.AccessToken, first)
	if err != nil || replay != expected {
		t.Fatal("restart lost idempotency")
	}
	if _, err := s.VaultObject(ctx, g.AccessToken, first.ObjectID); err != nil {
		t.Fatal("restart lost object")
	}
	*now = now.Add(48 * time.Hour)
	g = sessionLogin(t, s, r)
	if _, err := s.WriteVault(ctx, g.AccessToken, first); !errors.Is(err, ErrVaultConflict) {
		t.Fatal("expired retry replayed")
	}
}
