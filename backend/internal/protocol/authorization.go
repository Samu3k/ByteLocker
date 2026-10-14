package protocol

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

var ErrInvalidAuthorization = errors.New("protocol: invalid authorization header")

type TokenClass uint8

const (
	AccessToken TokenClass = iota + 1
	RegistrationToken
	RecoveryToken
)

// Authorization contains a parsed credential, not an authenticated identity.
// Account state, token digest, class, scope, expiry and revocation must be
// checked against server storage before granting access. Refresh tokens are
// accepted only in the refresh request body, never in this header.
type Authorization struct {
	class TokenClass
	token Secret
}

// ParseAuthorization reads the project's canonical wire header. The HTTP
// layer must first reject missing or repeated Authorization header values.
// No trimming, comma lists, alternate whitespace or unknown schemes is allowed.
func ParseAuthorization(value string) (Authorization, error) {
	if len(value) < len("Bearer ")+EncodedSecretLength || len(value) > len("Registration ")+EncodedSecretLength {
		return Authorization{}, ErrInvalidAuthorization
	}
	scheme, encoded, found := strings.Cut(value, " ")
	if !found {
		return Authorization{}, ErrInvalidAuthorization
	}
	var class TokenClass
	switch scheme {
	case "Bearer":
		class = AccessToken
	case "Registration":
		class = RegistrationToken
	case "Recovery":
		class = RecoveryToken
	default:
		return Authorization{}, ErrInvalidAuthorization
	}
	token, err := ParseSecret(encoded)
	if err != nil {
		return Authorization{}, ErrInvalidAuthorization
	}
	return Authorization{class: class, token: token}, nil
}

func (a Authorization) Valid() bool {
	return a.class >= AccessToken && a.class <= RecoveryToken && a.token.Valid()
}

func (a Authorization) Class() TokenClass { return a.class }

// Token returns an independent copy. Do not log its WireValue or Bytes result.
func (a Authorization) Token() Secret { return a.token }

func (a *Authorization) Clear() {
	if a == nil {
		return
	}
	a.token.Clear()
	a.class = 0
}

func (a Authorization) String() string   { return redactedSecret }
func (a Authorization) GoString() string { return redactedSecret }
func (a Authorization) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, redactedSecret)
}
func (a Authorization) LogValue() slog.Value         { return slog.StringValue(redactedSecret) }
func (a Authorization) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedSecret + `"`), nil }
