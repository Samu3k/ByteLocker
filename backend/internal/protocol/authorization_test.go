package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAuthorizationClassesAndRedaction(t *testing.T) {
	// Public synthetic fixture, never an operational credential.
	wire := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for scheme, class := range map[string]TokenClass{"Bearer": AccessToken, "Registration": RegistrationToken, "Recovery": RecoveryToken} {
		credential, err := ParseAuthorization(scheme + " " + wire)
		if err != nil || !credential.Valid() || credential.Class() != class {
			t.Fatalf("valid authorization rejected: %v", err)
		}
		token := credential.Token()
		encoded, err := token.WireValue()
		if err != nil || encoded != wire {
			t.Fatal("token extraction failed")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
			if fmt.Sprintf(format, credential) != redactedSecret || fmt.Sprintf(format, &credential) != redactedSecret {
				t.Fatal("format leaked authorization")
			}
		}
		payload, err := json.Marshal(struct{ Credential Authorization }{credential})
		if err != nil || bytes.Contains(payload, []byte(wire)) || !bytes.Contains(payload, []byte(redactedSecret)) {
			t.Fatal("JSON leaked authorization")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "authorization", credential)
		if strings.Contains(log.String(), wire) || !strings.Contains(log.String(), redactedSecret) {
			t.Fatal("log leaked authorization")
		}
		copy := credential
		credential.Clear()
		if credential.Valid() || credential.Class() != 0 || credential.Token().Valid() || !copy.Valid() || !token.Valid() {
			t.Fatal("clear/copy isolation failed")
		}
	}
	var nilCredential *Authorization
	nilCredential.Clear()
	if (Authorization{}).Valid() {
		t.Fatal("zero credential valid")
	}
}

func TestInvalidAuthorization(t *testing.T) {
	wire := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, input := range []string{"", wire, "Bearer", "Bearer ", "bearer " + wire, "Refresh " + wire, "Basic " + wire,
		" Bearer " + wire, "Bearer  " + wire, "Bearer\t" + wire, "Bearer " + wire + " ", "Bearer " + wire + "=", "Bearer " + wire + "\n",
		"Bearer " + wire + ",Bearer " + wire, "Registration bad", "Recovery " + wire[:42], "Bearer " + wire[:42] + "B", strings.Repeat("x", 10000),
	} {
		credential, err := ParseAuthorization(input)
		if !errors.Is(err, ErrInvalidAuthorization) || credential.Valid() || credential.Token().Valid() || credential.Class() != 0 {
			t.Fatal("invalid authorization accepted")
		}
		if err.Error() != ErrInvalidAuthorization.Error() {
			t.Fatal("error disclosed header")
		}
	}
}

func FuzzAuthorization(f *testing.F) {
	for _, input := range []string{"Bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Registration AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "Recovery AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", "Bearer bad"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		credential, err := ParseAuthorization(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidAuthorization) || credential.Valid() {
				t.Fatal("bad failure")
			}
			return
		}
		if !credential.Valid() || credential.String() != redactedSecret {
			t.Fatal("bad credential")
		}
		token, err := credential.Token().WireValue()
		if err != nil || len(token) != EncodedSecretLength {
			t.Fatal("invalid token")
		}
	})
}
