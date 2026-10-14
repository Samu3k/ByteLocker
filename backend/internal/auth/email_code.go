package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"

	"passwordmanager/internal/protocol"
)

var ErrInvalidEmailCode = errors.New("auth: invalid email verification code")

type EmailCode struct {
	value [8]byte
	valid bool
}

// NewEmailCode uses unbiased cryptographic sampling, retaining leading zeroes.
func NewEmailCode() (EmailCode, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(100000000))
	if err != nil {
		return EmailCode{}, ErrInvalidEmailCode
	}
	encoded := fmt.Sprintf("%08d", value.Int64())
	var result EmailCode
	copy(result.value[:], encoded)
	result.valid = true
	return result, nil
}

func ParseEmailCode(value string) (EmailCode, error) {
	if len(value) != 8 {
		return EmailCode{}, ErrInvalidEmailCode
	}
	var result EmailCode
	for i := range result.value {
		if value[i] < '0' || value[i] > '9' {
			return EmailCode{}, ErrInvalidEmailCode
		}
		result.value[i] = value[i]
	}
	result.valid = true
	return result, nil
}

// DeliveryValue is only for the encrypted SMTP outbox and outgoing email.
// Never return it through an API or include it in diagnostic output.
func (c EmailCode) DeliveryValue() (string, error) {
	if !c.valid {
		return "", ErrInvalidEmailCode
	}
	return string(c.value[:]), nil
}

// EmailCodeMAC binds the code to registration_id. The key is a dedicated server
// operational key, unrelated to authentication credentials and vault keys.
// Lifetime, attempt counts and resend invalidation belong to registration storage.
func EmailCodeMAC(key protocol.Secret, registrationID protocol.ID, code EmailCode) ([32]byte, error) {
	if registrationID.IsZero() || !code.valid {
		return [32]byte{}, ErrInvalidEmailCode
	}
	raw, err := key.Bytes()
	if err != nil {
		return [32]byte{}, ErrInvalidEmailCode
	}
	defer clear(raw[:])
	mac := hmac.New(sha256.New, raw[:])
	_, _ = mac.Write(registrationID[:])
	_, _ = mac.Write(code.value[:])
	var result [32]byte
	mac.Sum(result[:0])
	return result, nil
}

func VerifyEmailCode(key protocol.Secret, registrationID protocol.ID, code EmailCode, expected [32]byte) bool {
	actual, err := EmailCodeMAC(key, registrationID, code)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func (c *EmailCode) Clear() {
	if c != nil {
		clear(c.value[:])
		c.valid = false
	}
}
func (c EmailCode) String() string                    { return redacted }
func (c EmailCode) GoString() string                  { return redacted }
func (c EmailCode) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, redacted) }
func (c EmailCode) LogValue() slog.Value              { return slog.StringValue(redacted) }
func (c EmailCode) MarshalJSON() ([]byte, error)      { return []byte(`"` + redacted + `"`), nil }
