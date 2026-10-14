package protocol

import (
	"encoding"
	"encoding/json"
	"errors"
	"time"
)

const (
	TimestampLayout        = "2006-01-02T15:04:05.000Z"
	EncodedTimestampLength = 24
)

var ErrInvalidTimestamp = errors.New("protocol: invalid UTC millisecond timestamp")

// Timestamp implements the API Time scalar. Its zero value is invalid.
// It represents a wall-clock instant, not a monotonic timer or expiry policy.
type Timestamp struct {
	value time.Time
	valid bool
}

var (
	_ encoding.TextMarshaler   = Timestamp{}
	_ encoding.TextUnmarshaler = (*Timestamp)(nil)
	_ json.Marshaler           = Timestamp{}
	_ json.Unmarshaler         = (*Timestamp)(nil)
)

// NewTimestamp converts an instant to UTC and truncates sub-millisecond precision.
// Conversion strips the monotonic clock reading. Keep the original time.Time
// separately when runtime deadlines or finer-grained expiry checks require it.
// Years outside the wire format's four-digit range are rejected, not clamped.
func NewTimestamp(value time.Time) (Timestamp, error) {
	value = value.UTC().Truncate(time.Millisecond)
	if value.Year() < 0 || value.Year() > 9999 {
		return Timestamp{}, ErrInvalidTimestamp
	}
	return Timestamp{value: value, valid: true}, nil
}

// ParseTimestamp accepts exactly YYYY-MM-DDTHH:mm:ss.sssZ, with a valid date.
// Offsets, leap seconds, alternate separators and different precision fail.
func ParseTimestamp(value string) (Timestamp, error) {
	if len(value) != EncodedTimestampLength {
		return Timestamp{}, ErrInvalidTimestamp
	}
	parsed, err := time.Parse(TimestampLayout, value)
	if err != nil || parsed.Format(TimestampLayout) != value {
		return Timestamp{}, ErrInvalidTimestamp
	}
	return Timestamp{value: parsed.UTC(), valid: true}, nil
}

func (t Timestamp) Valid() bool {
	return t.valid
}

// Time returns the represented instant, without a monotonic clock reading.
func (t Timestamp) Time() (time.Time, error) {
	if !t.valid {
		return time.Time{}, ErrInvalidTimestamp
	}
	return t.value, nil
}

// String returns the canonical wire value, or empty for an invalid instance.
func (t Timestamp) String() string {
	if !t.valid {
		return ""
	}
	return t.value.Format(TimestampLayout)
}

func (t Timestamp) MarshalText() ([]byte, error) {
	if !t.valid {
		return nil, ErrInvalidTimestamp
	}
	return []byte(t.String()), nil
}

// UnmarshalText preserves the receiver on failure, including a nil receiver.
func (t *Timestamp) UnmarshalText(text []byte) error {
	if t == nil || len(text) != EncodedTimestampLength {
		return ErrInvalidTimestamp
	}
	parsed, err := ParseTimestamp(string(text))
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	if !t.valid {
		return nil, ErrInvalidTimestamp
	}
	return []byte(`"` + t.String() + `"`), nil
}

// UnmarshalJSON accepts a bounded JSON string, rejecting null and other types.
// JSON escapes may encode the string, but its decoded value must be canonical.
func (t *Timestamp) UnmarshalJSON(data []byte) error {
	if t == nil {
		return ErrInvalidTimestamp
	}
	value, ok := boundedJSONString(data)
	if !ok {
		return ErrInvalidTimestamp
	}
	parsed, err := ParseTimestamp(value)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}
