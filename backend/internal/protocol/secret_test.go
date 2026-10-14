package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// fixtureSecret uses only the public synthetic bytes 00 through 1f.
func fixtureSecret(t *testing.T) (Secret, string) {
	t.Helper()
	var raw [32]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	wire := base64.RawURLEncoding.EncodeToString(raw[:])
	s, err := ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	return s, wire
}

func TestSecretFormatAndCopies(t *testing.T) {
	s, wire := fixtureSecret(t)
	if !s.Valid() {
		t.Fatal("not valid")
	}
	got, err := s.WireValue()
	if err != nil || got != wire {
		t.Fatal("wire mismatch")
	}
	raw, err := s.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range raw {
		if b != byte(i) {
			t.Fatal("byte mismatch")
		}
	}
	raw[0] ^= 1
	again, err := s.Bytes()
	if err != nil || again[0] != 0 {
		t.Fatal("mutable alias or invalid copy")
	}
	copy := s
	if !copy.Equal(s) {
		t.Fatal("equal value rejected")
	}
	s.Clear()
	if s.Valid() || copy.Equal(s) || !copy.Valid() {
		t.Fatal("clear behavior")
	}
	if _, err := s.Bytes(); !errors.Is(err, ErrInvalidSecret) {
		t.Fatal(err)
	}
	if _, err := s.WireValue(); !errors.Is(err, ErrInvalidSecret) {
		t.Fatal(err)
	}
	if (Secret{}).Equal(Secret{}) {
		t.Fatal("invalid values compared equal")
	}
	var nilSecret *Secret
	nilSecret.Clear()
	generated := NewSecret()
	if !generated.Valid() {
		t.Fatal("generator returned invalid secret")
	}
	generatedWire, err := generated.WireValue()
	if err != nil || len(generatedWire) != 43 {
		t.Fatal("generated encoding")
	}
	parsed, err := ParseSecret(generatedWire)
	if err != nil || !parsed.Equal(generated) {
		t.Fatal("generated roundtrip")
	}
}

func TestSecretDistinctValues(t *testing.T) {
	original, _ := fixtureSecret(t)
	raw, err := original.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	different, err := ParseSecret(base64.RawURLEncoding.EncodeToString(raw[:]))
	if err != nil {
		t.Fatal(err)
	}
	if original.Equal(different) || different.Equal(original) {
		t.Fatal("distinct valid credentials compare equal")
	}
	if original.Equal(Secret{}) || (Secret{}).Equal(original) {
		t.Fatal("invalid credential compares equal to a valid one")
	}
}

func TestSecretCollectionRedaction(t *testing.T) {
	secret, wire := fixtureSecret(t)
	payload := map[string]any{
		"credentials": []Secret{secret, secret},
		"nested":      map[string]any{"token": &secret},
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(wire)) || bytes.Count(encoded, []byte("[REDACTED]")) != 3 {
		t.Fatal("collection serialization disclosed a credential")
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	logger.Info("synthetic test", slog.Any("credential", secret))
	if strings.Contains(logs.String(), wire) || !strings.Contains(logs.String(), "[REDACTED]") {
		t.Fatal("text logger disclosed a credential")
	}
}

func FuzzParseSecret(f *testing.F) {
	var raw [SecretSize]byte
	for i := range raw {
		raw[i] = byte(i)
	}
	for _, input := range []string{
		base64.RawURLEncoding.EncodeToString(raw[:]),
		base64.RawURLEncoding.EncodeToString(make([]byte, SecretSize)),
		"", "[REDACTED]", "invalid=",
	} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		secret, err := ParseSecret(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidSecret) || secret.Valid() {
				t.Fatal("failed parse returned an unexpected error or valid secret")
			}
			return
		}
		wire, err := secret.WireValue()
		if err != nil || wire != input || !secret.Valid() {
			t.Fatal("successful parse accepted a noncanonical credential")
		}
		encoded, err := json.Marshal(secret)
		if err != nil || string(encoded) != `"[REDACTED]"` {
			t.Fatal("diagnostic serialization did not redact")
		}
		var decoded Secret
		wireJSON, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if err := decoded.UnmarshalJSON(wireJSON); err != nil || !decoded.Equal(secret) {
			t.Fatal("explicit transport round-trip failed")
		}
	})
}

func TestSecretDiagnosticRedaction(t *testing.T) {
	s, wire := fixtureSecret(t)
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%b", "%#x", "% 100.2v"} {
		if got := fmt.Sprintf(format, s); got != "[REDACTED]" {
			t.Fatalf("format %s did not redact", format)
		}
		if got := fmt.Sprintf(format, &s); got != "[REDACTED]" {
			t.Fatalf("pointer format %s did not redact", format)
		}
	}
	if s.String() != "[REDACTED]" || s.GoString() != "[REDACTED]" || s.LogValue().String() != "[REDACTED]" {
		t.Fatal("direct diagnostic method")
	}
	nested := struct {
		Credential Secret `json:"credential"`
	}{s}
	for _, value := range []any{s, &s, nested} {
		data, err := json.Marshal(value)
		if err != nil || !bytes.Contains(data, []byte("[REDACTED]")) || bytes.Contains(data, []byte(wire)) {
			t.Fatal("JSON disclosure")
		}
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("test", slog.Any("value", s), slog.Any("pointer", &s), slog.Any("nested", nested))
	raw, _ := s.Bytes()
	if !strings.Contains(logs.String(), "[REDACTED]") || strings.Contains(logs.String(), wire) || strings.Contains(logs.String(), hex.EncodeToString(raw[:])) {
		t.Fatal("structured log disclosure")
	}
}

func TestSecretWireJSON(t *testing.T) {
	s, wire := fixtureSecret(t)
	transport := struct {
		Token string `json:"token"`
	}{wire}
	encoded, err := json.Marshal(transport)
	if err != nil {
		t.Fatal(err)
	}
	var inbound struct {
		Token Secret `json:"token"`
	}
	if err = json.Unmarshal(encoded, &inbound); err != nil || !inbound.Token.Equal(s) {
		t.Fatal("explicit transport roundtrip")
	}
	var decoded Secret
	if err = decoded.UnmarshalJSON([]byte(`"\u0041` + wire[1:] + `"`)); err != nil || !decoded.Equal(s) {
		t.Fatal("escaped JSON")
	}
	zeroWire := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	zero, err := ParseSecret(zeroWire)
	if err != nil || !zero.Valid() {
		t.Fatal("all-zero wire bytes are allowed by contract")
	}
}

func TestSecretInvalidInputs(t *testing.T) {
	original, wire := fixtureSecret(t)
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, wire[len(wire)-1])
	noncanonical := wire[:len(wire)-1] + string(alphabet[last+1])
	for _, input := range []string{"", wire + "=", wire + "\n", " " + wire, "+" + wire[1:], noncanonical, wire[:42], strings.Repeat("A", 100000)} {
		parsed, err := ParseSecret(input)
		if !errors.Is(err, ErrInvalidSecret) || parsed.Valid() {
			t.Fatal("invalid wire accepted")
		}
	}
	for _, input := range []string{"", "null", "1", "false", "{}", "[]", `""`, `"[REDACTED]"`, `"` + wire + `="`, `"` + wire + `" null`, strings.Repeat(" ", 300) + `"` + wire + `"`} {
		value := original
		if err := value.UnmarshalJSON([]byte(input)); !errors.Is(err, ErrInvalidSecret) || !value.Equal(original) {
			t.Fatal("invalid JSON changed value", err)
		}
	}
	var nilSecret *Secret
	if !errors.Is(nilSecret.UnmarshalJSON([]byte(`"`+wire+`"`)), ErrInvalidSecret) {
		t.Fatal("nil receiver")
	}
}
