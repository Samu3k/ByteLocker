package protocol

import (
	"encoding"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
)

const (
	EncodedIDLength   = 22
	MaxCounterLength  = 20
	maxScalarJSONSize = 256
)

var (
	ErrInvalidID      = errors.New("protocol: invalid nonzero identifier")
	ErrInvalidCounter = errors.New("protocol: invalid canonical unsigned counter")
)

// Counter is an unsigned 64-bit value encoded as a JSON string. This preserves
// precision in clients whose default JSON number type cannot represent uint64.
// Zero is valid for a checkpoint or a never-configured recovery generation;
// each operation must separately reject zero where a generation is required.
type Counter uint64

var (
	_ encoding.TextMarshaler   = ID{}
	_ encoding.TextUnmarshaler = (*ID)(nil)
	_ json.Marshaler           = ID{}
	_ json.Unmarshaler         = (*ID)(nil)
	_ encoding.TextMarshaler   = Counter(0)
	_ encoding.TextUnmarshaler = (*Counter)(nil)
	_ json.Marshaler           = Counter(0)
	_ json.Unmarshaler         = (*Counter)(nil)
)

// ParseID accepts only the 22-character canonical PM1 wire representation.
// The reserved all-zero object ID in a binary envelope is not an API Id.
func ParseID(value string) (ID, error) {
	if len(value) != EncodedIDLength {
		return ID{}, ErrInvalidID
	}
	raw, err := decodeCanonical(value, len(ID{}))
	if err != nil || len(raw) != len(ID{}) {
		return ID{}, ErrInvalidID
	}
	var id ID
	copy(id[:], raw)
	if id.IsZero() {
		return ID{}, ErrInvalidID
	}
	return id, nil
}

func (id ID) IsZero() bool {
	return id == (ID{})
}

// String encodes the identifier's bytes, including the reserved zero value.
// Use MarshalText or MarshalJSON when validation of an outgoing API Id is needed.
func (id ID) String() string {
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func (id ID) MarshalText() ([]byte, error) {
	if id.IsZero() {
		return nil, ErrInvalidID
	}
	return []byte(id.String()), nil
}

// UnmarshalText changes the receiver only after successful validation.
func (id *ID) UnmarshalText(text []byte) error {
	if id == nil || len(text) != EncodedIDLength {
		return ErrInvalidID
	}
	parsed, err := ParseID(string(text))
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id ID) MarshalJSON() ([]byte, error) {
	if id.IsZero() {
		return nil, ErrInvalidID
	}
	// Canonical base64url contains no characters requiring JSON escaping.
	return []byte(`"` + id.String() + `"`), nil
}

// UnmarshalJSON rejects null, numeric values and invalid identifiers.
func (id *ID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return ErrInvalidID
	}
	value, ok := boundedJSONString(data)
	if !ok {
		return ErrInvalidID
	}
	parsed, err := ParseID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

// ParseCounter accepts decimal ASCII digits, without signs or leading zeroes.
func ParseCounter(value string) (Counter, error) {
	if len(value) == 0 || len(value) > MaxCounterLength || (len(value) > 1 && value[0] == '0') {
		return 0, ErrInvalidCounter
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, ErrInvalidCounter
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, ErrInvalidCounter
	}
	return Counter(parsed), nil
}

func (c Counter) String() string {
	return strconv.FormatUint(uint64(c), 10)
}

func (c Counter) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

func (c *Counter) UnmarshalText(text []byte) error {
	if c == nil || len(text) > MaxCounterLength {
		return ErrInvalidCounter
	}
	parsed, err := ParseCounter(string(text))
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

func (c Counter) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.String() + `"`), nil
}

func (c *Counter) UnmarshalJSON(data []byte) error {
	if c == nil {
		return ErrInvalidCounter
	}
	value, ok := boundedJSONString(data)
	if !ok {
		return ErrInvalidCounter
	}
	parsed, err := ParseCounter(value)
	if err != nil {
		return err
	}
	*c = parsed
	return nil
}

// The cap permits JSON-escaped forms of every valid Id or Counter without
// allocating arbitrarily large strings when a scalar decoder is used directly.
func boundedJSONString(data []byte) (string, bool) {
	if len(data) == 0 || len(data) > maxScalarJSONSize {
		return "", false
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil || value == "" {
		return "", false
	}
	return value, true
}
