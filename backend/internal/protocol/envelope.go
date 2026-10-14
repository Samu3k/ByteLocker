// Package protocol validates PM1 wire formats without decrypting vault data.
package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
)

const (
	EnvelopeMagic                 = "PME1"
	EnvelopeSuite          uint16 = 1
	FixedHeaderSize               = 148
	AuthenticationTagSize         = 16
	PasswordDescriptorSize        = 30
	MaxPlaintextSize              = 1 << 20
	MaxEnvelopeSize               = FixedHeaderSize + PasswordDescriptorSize + MaxPlaintextSize + AuthenticationTagSize
)

var (
	ErrInvalidEncoding   = errors.New("protocol: invalid canonical base64url")
	ErrEnvelopeTooLarge  = errors.New("protocol: envelope exceeds size limit")
	ErrInvalidEnvelope   = errors.New("protocol: invalid PME1 envelope")
	ErrInvalidDescriptor = errors.New("protocol: invalid PM1 password descriptor")
	ErrInvalidContext    = errors.New("protocol: invalid expected server context")
	ErrContextMismatch   = errors.New("protocol: envelope does not match expected server context")
)

// ID is a PM1 identifier. Its all-zero value is reserved, except for the
// object identifier in password and recovery envelopes.
type ID [16]byte

type EnvelopeKind uint8

const (
	KindPassword EnvelopeKind = 1
	KindRecovery EnvelopeKind = 2
	KindObject   EnvelopeKind = 3
	KindLocal    EnvelopeKind = 4
)

// PasswordDescriptor is the exact 30-byte Argon2id descriptor defined by PM1.
// MemoryKiB is the total memory budget, not memory per lane.
type PasswordDescriptor struct {
	Algorithm   uint8
	Version     uint8
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint32
	Salt        [16]byte
}

// Validate accepts only the three KDF profiles permitted by PM1.
func (d PasswordDescriptor) Validate() error {
	if d.Algorithm != 1 || d.Version != 19 || d.Iterations != 3 || d.Parallelism != 4 {
		return ErrInvalidDescriptor
	}
	switch d.MemoryKiB {
	case 65536, 131072, 262144:
		return nil
	default:
		return ErrInvalidDescriptor
	}
}

// Bytes returns the binary descriptor. Call Validate before storing a
// descriptor constructed by an application rather than parsed from the wire.
func (d PasswordDescriptor) Bytes() [PasswordDescriptorSize]byte {
	var result [PasswordDescriptorSize]byte
	result[0] = d.Algorithm
	result[1] = d.Version
	binary.BigEndian.PutUint32(result[2:6], d.MemoryKiB)
	binary.BigEndian.PutUint32(result[6:10], d.Iterations)
	binary.BigEndian.PutUint32(result[10:14], d.Parallelism)
	copy(result[14:30], d.Salt[:])
	return result
}

// ParsePasswordDescriptor requires canonical, unpadded base64url.
func ParsePasswordDescriptor(encoded string) (PasswordDescriptor, error) {
	raw, err := decodeCanonical(encoded, PasswordDescriptorSize)
	if err != nil {
		return PasswordDescriptor{}, ErrInvalidDescriptor
	}
	return parseDescriptor(raw)
}

func parseDescriptor(raw []byte) (PasswordDescriptor, error) {
	if len(raw) != PasswordDescriptorSize {
		return PasswordDescriptor{}, ErrInvalidDescriptor
	}
	d := PasswordDescriptor{
		Algorithm:   raw[0],
		Version:     raw[1],
		MemoryKiB:   binary.BigEndian.Uint32(raw[2:6]),
		Iterations:  binary.BigEndian.Uint32(raw[6:10]),
		Parallelism: binary.BigEndian.Uint32(raw[10:14]),
	}
	copy(d.Salt[:], raw[14:30])
	if err := d.Validate(); err != nil {
		return PasswordDescriptor{}, err
	}
	return d, nil
}

// EnvelopeHeader contains untrusted metadata. Parsing does not authenticate it.
type EnvelopeHeader struct {
	Kind            EnvelopeKind
	ServerID        ID
	AccountID       ID
	VaultID         ID
	EpochID         ID
	ObjectID        ID
	Generation      uint64
	PlaintextLength uint32
	EnvelopeSalt    [32]byte
	Nonce           [12]byte
	MetadataLength  uint32
}

// Envelope owns its parsed bytes. Accessors return copies, so callers cannot
// accidentally invalidate the relationship between the header and the blob.
// A valid structure is not proof of a valid AES-GCM tag.
type Envelope struct {
	raw        []byte
	header     EnvelopeHeader
	descriptor PasswordDescriptor
	recoveryID ID
	headerSize int
}

// ParseEnvelope performs bounded decoding and all PME1 structural checks.
// It accepts local envelopes for format inspection; MatchServerContext always
// rejects them for server storage.
func ParseEnvelope(encoded string) (*Envelope, error) {
	raw, err := decodeCanonical(encoded, MaxEnvelopeSize)
	if err != nil {
		return nil, err
	}
	if len(raw) < FixedHeaderSize+AuthenticationTagSize {
		return nil, ErrInvalidEnvelope
	}
	if string(raw[:4]) != EnvelopeMagic || raw[5] != 0 || binary.BigEndian.Uint16(raw[6:8]) != EnvelopeSuite {
		return nil, ErrInvalidEnvelope
	}
	h := EnvelopeHeader{
		Kind:            EnvelopeKind(raw[4]),
		Generation:      binary.BigEndian.Uint64(raw[88:96]),
		PlaintextLength: binary.BigEndian.Uint32(raw[96:100]),
		MetadataLength:  binary.BigEndian.Uint32(raw[144:148]),
	}
	copy(h.ServerID[:], raw[8:24])
	copy(h.AccountID[:], raw[24:40])
	copy(h.VaultID[:], raw[40:56])
	copy(h.EpochID[:], raw[56:72])
	copy(h.ObjectID[:], raw[72:88])
	copy(h.EnvelopeSalt[:], raw[100:132])
	copy(h.Nonce[:], raw[132:144])

	if h.ServerID == (ID{}) || h.AccountID == (ID{}) || h.VaultID == (ID{}) || h.EpochID == (ID{}) || h.Generation == 0 {
		return nil, ErrInvalidEnvelope
	}
	if h.MetadataLength > PasswordDescriptorSize || h.PlaintextLength == 0 || h.PlaintextLength > MaxPlaintextSize {
		return nil, ErrInvalidEnvelope
	}
	// Compare lengths before converting untrusted integers or taking slices.
	total := uint64(FixedHeaderSize) + uint64(h.MetadataLength) + uint64(h.PlaintextLength) + uint64(AuthenticationTagSize)
	if total != uint64(len(raw)) {
		return nil, ErrInvalidEnvelope
	}
	e := &Envelope{
		raw:        raw,
		header:     h,
		headerSize: FixedHeaderSize + int(h.MetadataLength),
	}
	metadata := raw[FixedHeaderSize:e.headerSize]
	switch h.Kind {
	case KindPassword:
		if h.ObjectID != (ID{}) || h.PlaintextLength != 32 || h.MetadataLength != PasswordDescriptorSize {
			return nil, ErrInvalidEnvelope
		}
		e.descriptor, err = parseDescriptor(metadata)
		if err != nil {
			return nil, ErrInvalidEnvelope
		}
	case KindRecovery:
		if h.ObjectID != (ID{}) || h.PlaintextLength != 32 || h.MetadataLength != 16 {
			return nil, ErrInvalidEnvelope
		}
		copy(e.recoveryID[:], metadata)
		if e.recoveryID == (ID{}) {
			return nil, ErrInvalidEnvelope
		}
	case KindObject, KindLocal:
		if h.ObjectID == (ID{}) || h.MetadataLength != 0 {
			return nil, ErrInvalidEnvelope
		}
	default:
		return nil, ErrInvalidEnvelope
	}
	return e, nil
}

func decodeCanonical(encoded string, maxBytes int) ([]byte, error) {
	if len(encoded) > base64.RawURLEncoding.EncodedLen(maxBytes) {
		return nil, ErrEnvelopeTooLarge
	}
	if encoded == "" {
		return nil, ErrInvalidEncoding
	}
	// Go's base64 decoder normally ignores CR/LF. PM1 forbids them, padding,
	// whitespace and the standard base64 alphabet even in otherwise valid input.
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return nil, ErrInvalidEncoding
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidEncoding
	}
	if len(raw) > maxBytes {
		return nil, ErrEnvelopeTooLarge
	}
	if base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return nil, ErrInvalidEncoding
	}
	return raw, nil
}

func (e *Envelope) Header() EnvelopeHeader {
	if e == nil {
		return EnvelopeHeader{}
	}
	return e.header
}

func (e *Envelope) PasswordDescriptor() (PasswordDescriptor, bool) {
	if e == nil || len(e.raw) == 0 || e.header.Kind != KindPassword {
		return PasswordDescriptor{}, false
	}
	return e.descriptor, true
}

func (e *Envelope) RecoveryID() (ID, bool) {
	if e == nil || len(e.raw) == 0 || e.header.Kind != KindRecovery {
		return ID{}, false
	}
	return e.recoveryID, true
}

func (e *Envelope) Bytes() []byte {
	if e == nil {
		return nil
	}
	return bytes.Clone(e.raw)
}

// HeaderBytes returns the exact AES-GCM AAD, not a reconstructed header.
func (e *Envelope) HeaderBytes() []byte {
	if e == nil || len(e.raw) == 0 {
		return nil
	}
	return bytes.Clone(e.raw[:e.headerSize])
}

func (e *Envelope) Ciphertext() []byte {
	if e == nil || len(e.raw) == 0 {
		return nil
	}
	return bytes.Clone(e.raw[e.headerSize : len(e.raw)-AuthenticationTagSize])
}

func (e *Envelope) Tag() [AuthenticationTagSize]byte {
	var tag [AuthenticationTagSize]byte
	if e != nil && len(e.raw) != 0 {
		copy(tag[:], e.raw[len(e.raw)-AuthenticationTagSize:])
	}
	return tag
}

func (e *Envelope) Base64URL() string {
	if e == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(e.raw)
}

// ServerContext must be assembled from authenticated account state, the
// requested operation and its preconditions, never from the incoming envelope.
// PasswordDescriptor and RecoveryID are mandatory for their respective kinds.
type ServerContext struct {
	Kind               EnvelopeKind
	ServerID           ID
	AccountID          ID
	VaultID            ID
	EpochID            ID
	ObjectID           ID
	Generation         uint64
	PasswordDescriptor *PasswordDescriptor
	RecoveryID         *ID
}

// MatchServerContext checks structural ownership and operation metadata.
// It does not authorize an HTTP caller or verify an AES-GCM tag; those are
// responsibilities of the server's authorization layer and the client.
func (e *Envelope) MatchServerContext(expected ServerContext) error {
	if expected.ServerID == (ID{}) || expected.AccountID == (ID{}) || expected.VaultID == (ID{}) || expected.EpochID == (ID{}) || expected.Generation == 0 {
		return ErrInvalidContext
	}
	switch expected.Kind {
	case KindPassword:
		if expected.ObjectID != (ID{}) || expected.PasswordDescriptor == nil || expected.RecoveryID != nil {
			return ErrInvalidContext
		}
		if expected.PasswordDescriptor.Validate() != nil {
			return ErrInvalidContext
		}
	case KindRecovery:
		if expected.ObjectID != (ID{}) || expected.PasswordDescriptor != nil || expected.RecoveryID == nil || *expected.RecoveryID == (ID{}) {
			return ErrInvalidContext
		}
	case KindObject:
		if expected.ObjectID == (ID{}) || expected.PasswordDescriptor != nil || expected.RecoveryID != nil {
			return ErrInvalidContext
		}
	default:
		return ErrInvalidContext
	}
	if e == nil || len(e.raw) == 0 {
		return ErrInvalidEnvelope
	}
	h := e.header
	if h.Kind != expected.Kind || h.ServerID != expected.ServerID || h.AccountID != expected.AccountID || h.VaultID != expected.VaultID || h.EpochID != expected.EpochID || h.ObjectID != expected.ObjectID || h.Generation != expected.Generation {
		return ErrContextMismatch
	}
	if h.Kind == KindPassword && e.descriptor != *expected.PasswordDescriptor {
		return ErrContextMismatch
	}
	if h.Kind == KindRecovery && e.recoveryID != *expected.RecoveryID {
		return ErrContextMismatch
	}
	return nil
}
