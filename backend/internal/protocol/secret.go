package protocol

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const (
	SecretSize          = 32
	EncodedSecretLength = 43
	redactedSecret      = "[REDACTED]"
)

var ErrInvalidSecret = errors.New("protocol: invalid secret")

// Secret holds the 32-byte API Secret type, not a Master Password or vault key.
// Diagnostic formatting and ordinary JSON serialization are always redacted.
// API response builders must call WireValue explicitly at the transport boundary.
// Once converted to bytes or a wire string, the value must not be logged.
type Secret struct {
	value [SecretSize]byte
	valid bool
}

var (
	_ fmt.Stringer     = Secret{}
	_ fmt.GoStringer   = Secret{}
	_ fmt.Formatter    = Secret{}
	_ slog.LogValuer   = Secret{}
	_ json.Marshaler   = Secret{}
	_ json.Unmarshaler = (*Secret)(nil)
)

// NewSecret uses the operating system's cryptographically secure randomness.
// In the required Go versions, rand.Read fills the entire buffer or terminates
// the process on an unrecoverable randomness failure; it never falls back.
func NewSecret() Secret {
	var secret Secret
	rand.Read(secret.value[:])
	secret.valid = true
	return secret
}

// ParseSecret accepts canonical, unpadded base64url and exactly 32 decoded bytes.
// Unlike identifiers, the wire Secret type does not reserve all-zero bytes.
func ParseSecret(encoded string) (Secret, error) {
	if len(encoded) != EncodedSecretLength {
		return Secret{}, ErrInvalidSecret
	}
	raw, err := decodeCanonical(encoded, SecretSize)
	if err != nil || len(raw) != SecretSize {
		return Secret{}, ErrInvalidSecret
	}
	var secret Secret
	copy(secret.value[:], raw)
	clear(raw)
	secret.valid = true
	return secret, nil
}

func (s Secret) Valid() bool {
	return s.valid
}

// WireValue explicitly exposes the credential for a permitted API response or
// request. Never include the returned string in diagnostic messages or URLs.
func (s Secret) WireValue() (string, error) {
	if !s.valid {
		return "", ErrInvalidSecret
	}
	return base64.RawURLEncoding.EncodeToString(s.value[:]), nil
}

// Bytes returns an independent copy for credential verification or token hashing.
// Callers own and must protect that copy; this method does not derive any key.
func (s Secret) Bytes() ([SecretSize]byte, error) {
	if !s.valid {
		return [SecretSize]byte{}, ErrInvalidSecret
	}
	return s.value, nil
}

// Equal compares valid, fixed-length secret values in constant time.
// Invalid or cleared values never compare equal, including to each other.
func (s Secret) Equal(other Secret) bool {
	if !s.valid || !other.valid {
		return false
	}
	return subtle.ConstantTimeCompare(s.value[:], other.value[:]) == 1
}

// Clear invalidates this instance and overwrites its buffer. Previously made
// copies remain independent; this is not a guarantee of erasure from all memory.
func (s *Secret) Clear() {
	if s == nil {
		return
	}
	clear(s.value[:])
	s.valid = false
}

func (s Secret) String() string {
	return redactedSecret
}

func (s Secret) GoString() string {
	return redactedSecret
}

// Format redacts every verb, including numeric and hexadecimal formatting that
// could otherwise inspect the private byte array through fmt's reflection.
func (s Secret) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, redactedSecret)
}

func (s Secret) LogValue() slog.Value {
	return slog.StringValue(redactedSecret)
}

// MarshalJSON is intentionally diagnostic, not a wire encoder. This protects
// secrets nested in request structs that a logger might serialize to JSON.
// WireValue is the explicit opt-in for constructing the real API transport DTO.
func (s Secret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + redactedSecret + `"`), nil
}

// UnmarshalJSON is a wire decoder and accepts only a valid Secret string.
// Null, other JSON types and malformed values leave the receiver unchanged.
func (s *Secret) UnmarshalJSON(data []byte) error {
	if s == nil {
		return ErrInvalidSecret
	}
	value, ok := boundedJSONString(data)
	if !ok {
		return ErrInvalidSecret
	}
	parsed, err := ParseSecret(value)
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}
