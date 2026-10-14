package protocol

import (
	"errors"
	"strings"
	"testing"
)

func TestRevisionTags(t *testing.T) {
	id, err := ParseID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []AccountETag{
		{CredentialGeneration: 1, RecoveryGeneration: 0, EpochID: id},
		{CredentialGeneration: Counter(^uint64(0)), RecoveryGeneration: Counter(^uint64(0)), EpochID: id},
	} {
		parsed, err := ParseAccountETag(tag.String())
		if err != nil || parsed != tag || !parsed.Valid() {
			t.Fatal("account tag roundtrip failed")
		}
	}
	for _, tag := range []ObjectETag{{EpochID: id, Revision: 1}, {EpochID: id, Revision: Counter(^uint64(0))}} {
		parsed, err := ParseObjectETag(tag.String())
		if err != nil || parsed != tag || !parsed.Valid() {
			t.Fatal("object tag roundtrip failed")
		}
	}
	account := `"a:1:0:` + id.String() + `"`
	object := `"o:` + id.String() + `:1"`
	if (AccountETag{}).String() != "" || (ObjectETag{}).String() != "" {
		t.Fatal("invalid tag serialized")
	}
	for _, input := range []string{"", "*", "W/" + account, " " + account, account + " ", account + "," + account, account[1 : len(account)-1], strings.Repeat("x", 100),
		`"a:0:0:` + id.String() + `"`, `"a:01:0:` + id.String() + `"`, `"a:1:00:` + id.String() + `"`, `"a:1:-1:` + id.String() + `"`,
		`"a:18446744073709551616:0:` + id.String() + `"`, `"a:1:0:AAAAAAAAAAAAAAAAAAAAAA"`, object,
		`"a:1:0:` + id.String() + `="`, `"a:1:0:` + id.String() + `:extra"`,
	} {
		parsed, err := ParseAccountETag(input)
		if !errors.Is(err, ErrInvalidETag) || parsed.Valid() {
			t.Fatalf("invalid account tag accepted: %q", input)
		}
	}
	for _, input := range []string{"", "*", "W/" + object, object + "," + object, " " + object, account,
		`"o:` + id.String() + `:0"`, `"o:` + id.String() + `:01"`, `"o:` + id.String() + `:+1"`,
		`"o:` + id.String() + `:18446744073709551616"`, `"o:AAAAAAAAAAAAAAAAAAAAAA:1"`, `"o:invalid:1"`, `"o:` + id.String() + `:1:extra"`,
	} {
		parsed, err := ParseObjectETag(input)
		if !errors.Is(err, ErrInvalidETag) || parsed.Valid() {
			t.Fatalf("invalid object tag accepted: %q", input)
		}
	}
}

func FuzzRevisionTags(f *testing.F) {
	for _, input := range []string{`"a:1:0:AQEBAQEBAQEBAQEBAQEBAQ"`, `"o:AQEBAQEBAQEBAQEBAQEBAQ:1"`, "*", ""} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		account, err := ParseAccountETag(input)
		if err == nil {
			if !account.Valid() || account.String() != input {
				t.Fatal("noncanonical account tag")
			}
		} else if !errors.Is(err, ErrInvalidETag) || account.Valid() {
			t.Fatal("bad account failure")
		}
		object, err := ParseObjectETag(input)
		if err == nil {
			if !object.Valid() || object.String() != input {
				t.Fatal("noncanonical object tag")
			}
		} else if !errors.Is(err, ErrInvalidETag) || object.Valid() {
			t.Fatal("bad object failure")
		}
	})
}
