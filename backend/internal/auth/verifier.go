// Package auth verifies the client's derived authentication credential, never
// a Master Password. It cannot derive or decrypt the user's vault key.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"golang.org/x/crypto/argon2"
	"passwordmanager/internal/protocol"
)

const (
	ServerMemoryKiB        = 19456
	ServerIterations       = 2
	ServerParallelism      = 1
	MaxActiveVerifications = 2
	MaxQueuedVerifications = 16
	verifierRecordSize     = 63
	redacted               = "[REDACTED]"
)

var (
	ErrInvalidCredential = errors.New("auth: invalid credential")
	ErrInvalidVerifier   = errors.New("auth: invalid stored verifier")
	ErrBusy              = errors.New("auth: verification capacity exhausted")
)

type Verifier struct {
	salt   [16]byte
	digest [32]byte
	valid  bool
}

// Engine must be shared by all handlers so the resource budget is global.
// Argon2 cannot be interrupted halfway through a calculation. Cancellation
// discards its result but retains the active slot until calculation finishes.
type Engine struct {
	admitted chan struct{}
	active   chan struct{}
	derive   func([]byte, []byte) []byte
	dummy    Verifier
}

func NewEngine() *Engine {
	e := &Engine{
		admitted: make(chan struct{}, MaxActiveVerifications+MaxQueuedVerifications),
		active:   make(chan struct{}, MaxActiveVerifications),
		derive: func(credential, salt []byte) []byte {
			return argon2.IDKey(credential, salt, ServerIterations, ServerMemoryKiB, ServerParallelism, 32)
		},
	}
	rand.Read(e.dummy.salt[:])
	rand.Read(e.dummy.digest[:])
	e.dummy.valid = true
	return e
}

func (e *Engine) acquire(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case e.admitted <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	select {
	case e.active <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-e.active
			<-e.admitted
			return nil, err
		}
		return func() { <-e.active; <-e.admitted }, nil
	case <-ctx.Done():
		<-e.admitted
		return nil, ctx.Err()
	}
}

func (e *Engine) Create(ctx context.Context, credential protocol.Secret) (Verifier, error) {
	raw, err := credential.Bytes()
	if err != nil {
		return Verifier{}, ErrInvalidCredential
	}
	defer clear(raw[:])
	release, err := e.acquire(ctx)
	if err != nil {
		return Verifier{}, err
	}
	defer release()
	var verifier Verifier
	rand.Read(verifier.salt[:])
	digest := e.derive(raw[:], verifier.salt[:])
	defer clear(digest)
	if err := ctx.Err(); err != nil {
		return Verifier{}, err
	}
	copy(verifier.digest[:], digest)
	verifier.valid = true
	return verifier, nil
}

func (e *Engine) Verify(ctx context.Context, credential protocol.Secret, verifier Verifier) (bool, error) {
	if !verifier.valid {
		return false, ErrInvalidVerifier
	}
	raw, err := credential.Bytes()
	if err != nil {
		return false, ErrInvalidCredential
	}
	defer clear(raw[:])
	release, err := e.acquire(ctx)
	if err != nil {
		return false, err
	}
	defer release()
	digest := e.derive(raw[:], verifier.salt[:])
	defer clear(digest)
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(digest, verifier.digest[:]) == 1, nil
}

// DummyVerify performs the same costly verification for an unknown account.
// Completion never authenticates a caller. The login handler must still reject
// the request, with the same rate limits as a known account.
func (e *Engine) DummyVerify(ctx context.Context, credential protocol.Secret) error {
	_, err := e.Verify(ctx, credential, e.dummy)
	return err
}

func (v Verifier) Valid() bool { return v.valid }

// StorageRecord explicitly exposes the verifier for protected database storage.
// PAV1 is an internal storage format, not an API or a client vault envelope:
// magic[4], algorithm[1], version[1], memory[4], iterations[4], parallelism[1],
// salt[16], digest[32]. Integers use big-endian byte order.
func (v Verifier) StorageRecord() ([]byte, error) {
	if !v.valid {
		return nil, ErrInvalidVerifier
	}
	result := make([]byte, verifierRecordSize)
	copy(result[:4], "PAV1")
	result[4] = 1
	result[5] = argon2.Version
	binary.BigEndian.PutUint32(result[6:10], ServerMemoryKiB)
	binary.BigEndian.PutUint32(result[10:14], ServerIterations)
	result[14] = ServerParallelism
	copy(result[15:31], v.salt[:])
	copy(result[31:], v.digest[:])
	return result, nil
}

// ParseVerifier accepts only the fixed server PM1 cost. Stored or remote bytes
// cannot request arbitrary memory or CPU usage from Argon2.
func ParseVerifier(record []byte) (Verifier, error) {
	if len(record) != verifierRecordSize || string(record[:4]) != "PAV1" || record[4] != 1 || record[5] != argon2.Version ||
		binary.BigEndian.Uint32(record[6:10]) != ServerMemoryKiB || binary.BigEndian.Uint32(record[10:14]) != ServerIterations || record[14] != ServerParallelism {
		return Verifier{}, ErrInvalidVerifier
	}
	var result Verifier
	copy(result.salt[:], record[15:31])
	copy(result.digest[:], record[31:])
	result.valid = true
	return result, nil
}

func (v Verifier) String() string                    { return redacted }
func (v Verifier) GoString() string                  { return redacted }
func (v Verifier) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, redacted) }
func (v Verifier) LogValue() slog.Value              { return slog.StringValue(redacted) }
func (v Verifier) MarshalJSON() ([]byte, error)      { return []byte(`"` + redacted + `"`), nil }
