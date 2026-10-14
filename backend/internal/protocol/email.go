package protocol

import (
	"encoding"
	"encoding/json"
	"errors"
	"strings"
)

const (
	MaxEmailLength      = 254
	MaxEmailLocalLength = 64
	// Allows every character to be JSON-escaped, with bounded surrounding space.
	maxEmailJSONSize = 2048
)

var ErrInvalidEmail = errors.New("protocol: invalid account email")

// Email is a validated, canonical account identifier under the API v1 policy.
// It is not a general-purpose RFC mailbox parser or a delivery guarantee.
// The zero value is invalid. Email addresses are account metadata, not secrets;
// callers must still avoid unnecessary disclosure in logs or public responses.
type Email struct {
	value string
}

var (
	_ encoding.TextMarshaler   = Email{}
	_ encoding.TextUnmarshaler = (*Email)(nil)
	_ json.Marshaler           = Email{}
	_ json.Unmarshaler         = (*Email)(nil)
)

// ParseEmail trims only outer ASCII spaces and lowercases the entire address.
// Dots and plus suffixes remain significant. Internationalized addresses,
// quoted local parts, display names and domain literals are unsupported in v1.
func ParseEmail(value string) (Email, error) {
	value = strings.Trim(value, " ")
	if len(value) == 0 || len(value) > MaxEmailLength {
		return Email{}, ErrInvalidEmail
	}
	at := strings.IndexByte(value, '@')
	if at < 1 || at > MaxEmailLocalLength || at == len(value)-1 {
		return Email{}, ErrInvalidEmail
	}
	local, domain := value[:at], value[at+1:]
	if local[0] == '.' || local[len(local)-1] == '.' {
		return Email{}, ErrInvalidEmail
	}
	for i := 0; i < len(local); i++ {
		c := local[i]
		if !emailASCIIAlphanumeric(c) && c != '.' && c != '_' && c != '+' && c != '-' {
			return Email{}, ErrInvalidEmail
		}
		if c == '.' && i > 0 && local[i-1] == '.' {
			return Email{}, ErrInvalidEmail
		}
	}
	// Validate labels directly, without allocating a slice for untrusted input.
	start, labels := 0, 0
	for end := 0; end <= len(domain); end++ {
		if end < len(domain) && domain[end] != '.' {
			continue
		}
		length := end - start
		if length < 1 || length > 63 || domain[start] == '-' || domain[end-1] == '-' {
			return Email{}, ErrInvalidEmail
		}
		for i := start; i < end; i++ {
			if !emailASCIIAlphanumeric(domain[i]) && domain[i] != '-' {
				return Email{}, ErrInvalidEmail
			}
		}
		labels++
		start = end + 1
	}
	if labels < 2 {
		return Email{}, ErrInvalidEmail
	}
	return Email{value: strings.ToLower(value)}, nil
}

func emailASCIIAlphanumeric(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func (e Email) Valid() bool {
	return e.value != ""
}

// String returns the canonical address, or an empty string for the zero value.
func (e Email) String() string {
	return e.value
}

func (e Email) MarshalText() ([]byte, error) {
	if !e.Valid() {
		return nil, ErrInvalidEmail
	}
	return []byte(e.value), nil
}

// UnmarshalText preserves the receiver if validation fails.
func (e *Email) UnmarshalText(text []byte) error {
	if e == nil {
		return ErrInvalidEmail
	}
	parsed, err := ParseEmail(string(text))
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

func (e Email) MarshalJSON() ([]byte, error) {
	if !e.Valid() {
		return nil, ErrInvalidEmail
	}
	// Every allowed character is ASCII and needs no JSON escaping.
	return []byte(`"` + e.value + `"`), nil
}

// UnmarshalJSON accepts a bounded string only; null and other types fail.
// Invalid JSON or an unsupported address leaves the receiver unchanged.
func (e *Email) UnmarshalJSON(data []byte) error {
	if e == nil || len(data) == 0 || len(data) > maxEmailJSONSize {
		return ErrInvalidEmail
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return ErrInvalidEmail
	}
	parsed, err := ParseEmail(value)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}
