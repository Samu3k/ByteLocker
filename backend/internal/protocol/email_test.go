package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestEmailIdentityPreservesDotsAndSuffixes(t *testing.T) {
	inputs := []string{"marco@example.com", "mar.co@example.com", "marco+work@example.com"}
	seen := make(map[Email]bool)
	for _, input := range inputs {
		e, err := ParseEmail(input)
		if err != nil {
			t.Fatal(err)
		}
		if seen[e] {
			t.Fatal("distinct account addresses were merged")
		}
		seen[e] = true
	}
	upper, err := ParseEmail(" MARCO@EXAMPLE.COM ")
	if err != nil {
		t.Fatal(err)
	}
	lower, err := ParseEmail(inputs[0])
	if err != nil || upper != lower {
		t.Fatal("case and outer spaces did not normalize")
	}
}

func TestEmailFullyEscapedMaximumLength(t *testing.T) {
	address := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(address) != MaxEmailLength {
		t.Fatal("incorrect boundary fixture")
	}
	var wire strings.Builder
	wire.WriteByte('"')
	for i := 0; i < len(address); i++ {
		fmt.Fprintf(&wire, `\u%04x`, address[i])
	}
	wire.WriteByte('"')
	var e Email
	if err := e.UnmarshalJSON([]byte(wire.String())); err != nil || e.String() != address {
		t.Fatalf("fully escaped maximum-length address rejected: %v", err)
	}
	// The raw JSON cap includes whitespace, regardless of decoded string length.
	exact := `"a@example.com"`
	padded := strings.Repeat(" ", maxEmailJSONSize-len(exact)) + exact
	if err := e.UnmarshalJSON([]byte(padded)); err != nil {
		t.Fatal(err)
	}
	original := e
	if err := e.UnmarshalJSON([]byte(" " + padded)); !errors.Is(err, ErrInvalidEmail) || e != original {
		t.Fatal("oversized JSON accepted or receiver changed")
	}
}

func FuzzEmailJSON(f *testing.F) {
	for _, s := range []string{`"a@example.com"`, `"\u0041@example.com"`, "null", `"\ud800@example.com"`, "\"a\xff@example.com\""} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		original, err := ParseEmail("original@example.com")
		if err != nil {
			t.Fatal(err)
		}
		e := original
		err = e.UnmarshalJSON(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidEmail) || e != original {
				t.Fatal("invalid input changed receiver")
			}
			return
		}
		if !e.Valid() {
			t.Fatal("accepted invalid email")
		}
		wire, err := e.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var decoded Email
		if err = json.Unmarshal(wire, &decoded); err != nil || decoded != e {
			t.Fatal("JSON roundtrip failed")
		}
	})
}

func TestEmailPolicy(t *testing.T) {
	valid := map[string]string{
		"  MARCO.Tag+Work@EXAMPLE.COM  ":         "marco.tag+work@example.com",
		"a_b-c+1@sub-domain.example.com":         "a_b-c+1@sub-domain.example.com",
		"a@1.2":                                  "a@1.2",
		strings.Repeat("a", 64) + "@example.com": strings.Repeat("a", 64) + "@example.com",
	}
	// Exactly 254 bytes with all DNS labels within 63 bytes.
	boundary := strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	valid[boundary] = boundary
	for input, want := range valid {
		e, err := ParseEmail(input)
		if err != nil || !e.Valid() || e.String() != want {
			t.Fatalf("valid address rejected: %v", err)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Email
		if err = json.Unmarshal(b, &decoded); err != nil || decoded != e {
			t.Fatal("JSON roundtrip failed")
		}
		text, err := e.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if err = decoded.UnmarshalText(text); err != nil || decoded != e {
			t.Fatal("text roundtrip failed")
		}
	}
	invalid := []string{"", " ", "@example.com", "a@", "a@@example.com", ".a@example.com", "a.@example.com", "a..b@example.com", "a@localhost", "a@.example.com", "a@example..com", "a@example.com.", "a@-example.com", "a@example-.com", "a@exa_mple.com", "a b@example.com", "a\t@example.com", "\ta@example.com", "a@example.com\n", "é@example.com", "a@éxample.com", "a\x00@example.com", "\"a\"@example.com", "a@[127.0.0.1]", strings.Repeat("a", 65) + "@example.com", "a@" + strings.Repeat("b", 64) + ".com", boundary + "d", "a@exa@mple.com", "a!@example.com"}
	for _, input := range invalid {
		e, err := ParseEmail(input)
		if !errors.Is(err, ErrInvalidEmail) || e.Valid() {
			t.Fatal("invalid address accepted")
		}
		if err.Error() != ErrInvalidEmail.Error() {
			t.Fatal("error disclosed input")
		}
	}
	original, _ := ParseEmail("a@example.com")
	for _, data := range []string{"", "null", "123", "false", "{}", "[]", `""`, `"bad"`, `"a@example.com" true`, `"\ud800@example.com"`, strings.Repeat(" ", 2049)} {
		e := original
		if !errors.Is(e.UnmarshalJSON([]byte(data)), ErrInvalidEmail) || e != original {
			t.Fatal("invalid JSON changed receiver")
		}
	}
	escaped := `"\u0041@example.com"`
	var e Email
	if err := e.UnmarshalJSON([]byte(escaped)); err != nil || e.String() != "a@example.com" {
		t.Fatal("escaped input rejected")
	}
	var zero Email
	if zero.Valid() || zero.String() != "" {
		t.Fatal("zero value valid")
	}
	if _, err := zero.MarshalJSON(); !errors.Is(err, ErrInvalidEmail) {
		t.Fatal("invalid output accepted")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidEmail) {
		t.Fatal("invalid output accepted")
	}
	e = original
	if err := e.UnmarshalText([]byte("bad")); !errors.Is(err, ErrInvalidEmail) || e != original {
		t.Fatal("invalid text changed receiver")
	}
	var nilEmail *Email
	if !errors.Is(nilEmail.UnmarshalText(nil), ErrInvalidEmail) || !errors.Is(nilEmail.UnmarshalJSON(nil), ErrInvalidEmail) {
		t.Fatal("nil receiver accepted")
	}
}

func FuzzParseEmail(f *testing.F) {
	for _, s := range []string{"a@example.com", " A.Tag+1@EXAMPLE.COM ", "a@.", "", "a@@example.com"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		e, err := ParseEmail(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidEmail) || e.Valid() {
				t.Fatal("bad failure")
			}
			return
		}
		canonical := e.String()
		again, err := ParseEmail(canonical)
		if err != nil || again != e || len(canonical) > 254 || canonical != strings.ToLower(canonical) {
			t.Fatal("noncanonical result")
		}
		wire, err := e.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var decoded Email
		if err = decoded.UnmarshalJSON(wire); err != nil || decoded != e {
			t.Fatal("roundtrip failed")
		}
	})
}
