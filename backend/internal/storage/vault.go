package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"time"

	"passwordmanager/internal/protocol"
)

var (
	ErrVaultNotFound     = errors.New("storage: vault object not found")
	ErrVaultConflict     = errors.New("storage: vault object already exists")
	ErrVaultEpoch        = errors.New("storage: vault epoch changed")
	ErrVaultSnapshot     = errors.New("storage: vault snapshot changed")
	ErrVaultPrecondition = errors.New("storage: vault revision mismatch")
	ErrVaultIdempotency  = errors.New("storage: vault idempotency conflict")
	ErrVaultQuota        = errors.New("storage: vault quota exceeded")
	ErrVaultWriteLimit   = errors.New("storage: vault write registry full")
	ErrInvalidVault      = errors.New("storage: invalid vault operation")
)

const (
	maxVaultObjects       = 10000
	maxVaultBytes         = 64 << 20
	maxInstanceVaultBytes = 512 << 20
	maxSyncJSONBytes      = 4 << 20
)

type VaultState struct {
	ServerID             protocol.ID      `json:"server_id"`
	AccountID            protocol.ID      `json:"account_id"`
	VaultID              protocol.ID      `json:"vault_id"`
	EpochID              protocol.ID      `json:"epoch_id"`
	CredentialGeneration protocol.Counter `json:"credential_generation"`
	RecoveryGeneration   protocol.Counter `json:"recovery_generation"`
	Revision             protocol.Counter `json:"collection_revision"`
	ObjectCount          int              `json:"object_count"`
	StoredBytes          protocol.Counter `json:"stored_bytes"`
}
type VaultObject struct {
	EpochID  protocol.ID      `json:"epoch_id"`
	ObjectID protocol.ID      `json:"object_id"`
	Revision protocol.Counter `json:"revision"`
	Sequence protocol.Counter `json:"sequence"`
	Envelope string           `json:"envelope"`
}
type VaultWriteResult struct {
	EpochID            protocol.ID      `json:"epoch_id"`
	ObjectID           protocol.ID      `json:"object_id"`
	Revision           protocol.Counter `json:"revision"`
	Sequence           protocol.Counter `json:"sequence"`
	CollectionRevision protocol.Counter `json:"collection_revision"`
}
type VaultWrite struct {
	OperationID, EpochID, ObjectID protocol.ID
	Envelope                       *protocol.Envelope
	// Base nil means POST; non-nil means PUT. Fingerprint binds the exact body
	// bytes plus canonical method, path and If-Match in the HTTP adapter.
	Base        *protocol.ObjectETag
	Fingerprint [32]byte
}
type VaultSyncRequest struct {
	EpochID               protocol.ID
	Since, Ceiling, After protocol.Counter
	Limit                 int
}
type VaultPage struct {
	EpochID  protocol.ID       `json:"epoch_id"`
	Snapshot protocol.Counter  `json:"snapshot_revision"`
	Items    []VaultObject     `json:"items"`
	Next     *protocol.Counter `json:"next_after_sequence"`
}

func counterBytes(c protocol.Counter) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, uint64(c))
	return result
}
func storedCounter(raw []byte) (protocol.Counter, error) {
	if len(raw) != 8 {
		return 0, ErrUnavailable
	}
	return protocol.Counter(binary.BigEndian.Uint64(raw)), nil
}
func (s *Sessions) vaultStateTx(ctx context.Context, tx *sql.Tx, f family) (VaultState, error) {
	var state VaultState
	var epoch []byte
	var recovery string
	if err := tx.QueryRowContext(ctx, "SELECT epoch_id,recovery_generation FROM accounts WHERE account_id=?", f.account[:]).Scan(&epoch, &recovery); err != nil || len(epoch) != 16 {
		return state, ErrUnavailable
	}
	copy(state.EpochID[:], epoch)
	state.ServerID = s.store.Instance().ServerID
	state.AccountID = f.account
	state.VaultID = f.vault
	state.CredentialGeneration = f.generation
	var err error
	state.RecoveryGeneration, err = protocol.ParseCounter(recovery)
	if err != nil {
		return state, ErrUnavailable
	}
	// Lazy initialization also covers previously activated accounts. All callers
	// commit this and session activity in the same transaction as their operation.
	if _, err := tx.ExecContext(ctx, "INSERT INTO vault_state(account_id,epoch_id,revision) VALUES(?,?,?) ON CONFLICT(account_id) DO NOTHING", f.account[:], epoch, counterBytes(0)); err != nil {
		return state, ErrUnavailable
	}
	var revision []byte
	var stored int64
	var savedEpoch []byte
	if err := tx.QueryRowContext(ctx, "SELECT epoch_id,revision,object_count,stored_bytes FROM vault_state WHERE account_id=?", f.account[:]).Scan(&savedEpoch, &revision, &state.ObjectCount, &stored); err != nil || !bytes.Equal(savedEpoch, epoch) || stored < 0 {
		return state, ErrUnavailable
	}
	state.Revision, err = storedCounter(revision)
	if err != nil {
		return state, err
	}
	state.StoredBytes = protocol.Counter(stored)
	return state, nil
}
func (s *Sessions) VaultState(ctx context.Context, token protocol.Secret) (VaultState, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return VaultState{}, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return VaultState{}, err
	}
	state, err := s.vaultStateTx(ctx, tx, f)
	if err != nil {
		return VaultState{}, err
	}
	if err := tx.Commit(); err != nil {
		return VaultState{}, ErrUnavailable
	}
	return state, nil
}
func readVaultObject(ctx context.Context, tx *sql.Tx, account, epoch, id protocol.ID) (VaultObject, int, error) {
	var item VaultObject
	var revision, sequence, raw []byte
	err := tx.QueryRowContext(ctx, "SELECT revision,sequence,envelope FROM vault_objects WHERE account_id=? AND object_id=?", account[:], id[:]).Scan(&revision, &sequence, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return item, 0, ErrVaultNotFound
	}
	if err != nil {
		return item, 0, ErrUnavailable
	}
	item.EpochID = epoch
	item.ObjectID = id
	item.Revision, err = storedCounter(revision)
	if err != nil || item.Revision == 0 {
		return item, 0, ErrUnavailable
	}
	item.Sequence, err = storedCounter(sequence)
	if err != nil || item.Sequence == 0 {
		return item, 0, ErrUnavailable
	}
	item.Envelope = base64.RawURLEncoding.EncodeToString(raw)
	return item, len(raw), nil
}
func (s *Sessions) VaultObject(ctx context.Context, token protocol.Secret, id protocol.ID) (VaultObject, error) {
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return VaultObject{}, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return VaultObject{}, err
	}
	state, err := s.vaultStateTx(ctx, tx, f)
	if err != nil {
		return VaultObject{}, err
	}
	item, _, err := readVaultObject(ctx, tx, f.account, state.EpochID, id)
	if err != nil {
		return VaultObject{}, err
	}
	if err := tx.Commit(); err != nil {
		return VaultObject{}, ErrUnavailable
	}
	return item, nil
}

// VaultFingerprint binds a logical operation without retaining the JSON body.
// Length-prefixing prevents ambiguity between fields. Use the original body,
// not a decoded/re-serialized value, for the final field.
func VaultFingerprint(method, path, condition string, body []byte) [32]byte {
	hash := sha256.New()
	for _, value := range [][]byte{[]byte(method), []byte(path), []byte(condition), body} {
		_, _ = hash.Write(counterBytes(protocol.Counter(len(value))))
		_, _ = hash.Write(value)
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
func (s *Sessions) WriteVault(ctx context.Context, token protocol.Secret, request VaultWrite) (VaultWriteResult, error) {
	var empty VaultWriteResult
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return empty, err
	}
	if request.OperationID.IsZero() || request.ObjectID.IsZero() || request.EpochID.IsZero() || request.Envelope == nil || (request.Base != nil && !request.Base.Valid()) {
		return empty, ErrInvalidVault
	}
	now := s.store.now().UTC()
	if _, err := tx.ExecContext(ctx, "DELETE FROM vault_writes WHERE expires_at_ms<=?", now.UnixMilli()); err != nil {
		return empty, ErrUnavailable
	}
	var fingerprint, response []byte
	err = tx.QueryRowContext(ctx, "SELECT fingerprint,response FROM vault_writes WHERE account_id=? AND operation_id=?", f.account[:], request.OperationID[:]).Scan(&fingerprint, &response)
	if err == nil {
		if !bytes.Equal(fingerprint, request.Fingerprint[:]) {
			return empty, ErrVaultIdempotency
		}
		var saved VaultWriteResult
		if json.Unmarshal(response, &saved) != nil {
			return empty, ErrUnavailable
		}
		if err := tx.Commit(); err != nil {
			return empty, ErrUnavailable
		}
		return saved, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return empty, ErrUnavailable
	}
	state, err := s.vaultStateTx(ctx, tx, f)
	if err != nil {
		return empty, err
	}
	if state.EpochID != request.EpochID {
		return empty, ErrVaultEpoch
	}
	old, oldBytes, err := readVaultObject(ctx, tx, f.account, state.EpochID, request.ObjectID)
	if err != nil && !errors.Is(err, ErrVaultNotFound) {
		return empty, err
	}
	revision := protocol.Counter(1)
	count := state.ObjectCount
	if request.Base == nil {
		if err == nil {
			return empty, ErrVaultConflict
		}
		count++
	} else {
		if errors.Is(err, ErrVaultNotFound) || request.Base.EpochID != state.EpochID || request.Base.Revision != old.Revision {
			return empty, ErrVaultPrecondition
		}
		if uint64(old.Revision) == math.MaxUint64 {
			return empty, ErrVaultQuota
		}
		revision = old.Revision + 1
	}
	if request.Envelope.MatchServerContext(protocol.ServerContext{Kind: protocol.KindObject, ServerID: state.ServerID, AccountID: f.account, VaultID: f.vault, EpochID: state.EpochID, ObjectID: request.ObjectID, Generation: uint64(revision)}) != nil {
		return empty, ErrInvalidVault
	}
	raw := request.Envelope.Bytes()
	size := int64(state.StoredBytes) + int64(len(raw)-oldBytes)
	var globalBytes int64
	if err := tx.QueryRowContext(ctx, "SELECT coalesce(sum(stored_bytes),0) FROM vault_state").Scan(&globalBytes); err != nil {
		return empty, ErrUnavailable
	}
	// Permit replacements that reduce storage if an operator lowers a quota.
	if (count > maxVaultObjects && count > state.ObjectCount) || (size > maxVaultBytes && size > int64(state.StoredBytes)) || (globalBytes+int64(len(raw)-oldBytes) > maxInstanceVaultBytes && len(raw) > oldBytes) || uint64(state.Revision) == math.MaxUint64 {
		return empty, ErrVaultQuota
	}
	sequence := state.Revision + 1
	result := VaultWriteResult{state.EpochID, request.ObjectID, revision, sequence, sequence}
	encoded, err := json.Marshal(result)
	if err != nil {
		return empty, ErrUnavailable
	}
	var total, own, registryBytes int64
	if err := tx.QueryRowContext(ctx, "SELECT count(*),coalesce(sum(account_id=?),0),coalesce(sum(length(response)+length(fingerprint)+length(account_id)+length(operation_id)+8),0) FROM vault_writes", f.account[:]).Scan(&total, &own, &registryBytes); err != nil {
		return empty, ErrUnavailable
	}
	if total >= 100000 || own >= 20000 || registryBytes+int64(len(encoded)+72) > 64<<20 {
		return empty, ErrVaultWriteLimit
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO vault_objects(account_id,object_id,revision,sequence,envelope) VALUES(?,?,?,?,?) ON CONFLICT(account_id,object_id) DO UPDATE SET revision=excluded.revision,sequence=excluded.sequence,envelope=excluded.envelope", f.account[:], request.ObjectID[:], counterBytes(revision), counterBytes(sequence), raw); err != nil {
		return empty, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "UPDATE vault_state SET revision=?,object_count=?,stored_bytes=? WHERE account_id=?", counterBytes(sequence), count, size, f.account[:]); err != nil {
		return empty, ErrUnavailable
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO vault_writes VALUES(?,?,?,?,?)", f.account[:], request.OperationID[:], request.Fingerprint[:], encoded, now.Add(48*time.Hour).UnixMilli()); err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	return result, nil
}
func (s *Sessions) SyncVault(ctx context.Context, token protocol.Secret, request VaultSyncRequest) (VaultPage, error) {
	var empty VaultPage
	tx, err := s.store.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer tx.Rollback()
	f, err := s.authenticateTx(ctx, tx, token)
	if err != nil {
		return empty, err
	}
	if request.EpochID.IsZero() || request.Since > request.After || request.After > request.Ceiling || request.Limit < 1 || request.Limit > 100 {
		return empty, ErrInvalidVault
	}
	state, err := s.vaultStateTx(ctx, tx, f)
	if err != nil {
		return empty, err
	}
	if state.EpochID != request.EpochID {
		return empty, ErrVaultEpoch
	}
	if state.Revision != request.Ceiling {
		return empty, ErrVaultSnapshot
	}
	rows, err := tx.QueryContext(ctx, "SELECT object_id,revision,sequence,envelope FROM vault_objects WHERE account_id=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?", f.account[:], counterBytes(request.After), counterBytes(request.Ceiling), request.Limit+1)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer rows.Close()
	page := VaultPage{EpochID: state.EpochID, Snapshot: state.Revision, Items: make([]VaultObject, 0)}
	// Base JSON is small. Include a conservative allowance for separators and Next.
	size := 256
	for rows.Next() {
		var id, revision, sequence, raw []byte
		if err := rows.Scan(&id, &revision, &sequence, &raw); err != nil || len(id) != 16 {
			return empty, ErrUnavailable
		}
		item := VaultObject{EpochID: state.EpochID, Envelope: base64.RawURLEncoding.EncodeToString(raw)}
		copy(item.ObjectID[:], id)
		item.Revision, err = storedCounter(revision)
		if err != nil {
			return empty, err
		}
		item.Sequence, err = storedCounter(sequence)
		if err != nil {
			return empty, err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return empty, ErrUnavailable
		}
		if len(page.Items) >= request.Limit || size+len(encoded)+1 > maxSyncJSONBytes {
			if len(page.Items) == 0 {
				return empty, ErrUnavailable
			}
			last := page.Items[len(page.Items)-1].Sequence
			page.Next = &last
			break
		}
		page.Items = append(page.Items, item)
		size += len(encoded) + 1
	}
	if err := rows.Err(); err != nil {
		return empty, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return empty, ErrUnavailable
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrUnavailable
	}
	return page, nil
}
