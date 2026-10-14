package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const sampleID = "AAECAwQFBgcICQoLDA0ODw"

// sampleID encodes the public, synthetic bytes 00 through 0f.
// None of these tests generates or stores a real account credential.

func TestIdentifierWire(t *testing.T) {
	id, err := ParseID(sampleID)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range id {
		if b != byte(i) {
			t.Fatal("wrong decoded ID")
		}
	}
	if id.IsZero() || id.String() != sampleID {
		t.Fatal("wrong encoded ID")
	}
	b, err := id.MarshalText()
	if err != nil || string(b) != sampleID {
		t.Fatal(err)
	}
	var decoded ID
	if err = decoded.UnmarshalText(b); err != nil || decoded != id {
		t.Fatal(err)
	}
	j, err := json.Marshal(id)
	if err != nil || string(j) != `"`+sampleID+`"` {
		t.Fatalf("bad JSON: %q %v", j, err)
	}
	if err = json.Unmarshal(j, &decoded); err != nil || decoded != id {
		t.Fatal(err)
	}
	if err = decoded.UnmarshalJSON([]byte(`"\u0041` + sampleID[1:] + `"`)); err != nil || decoded != id {
		t.Fatal("escaped JSON string", err)
	}
}

func TestIdentifierInvalidInputs(t *testing.T) {
	original, _ := ParseID(sampleID)
	for _, s := range []string{"", "AAAAAAAAAAAAAAAAAAAAAA", sampleID + "=", sampleID + "\n", " " + sampleID, "+" + sampleID[1:], sampleID[:21] + "x", strings.Repeat("A", 100000)} {
		if _, err := ParseID(s); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("input length %d: %v", len(s), err)
		}
		value := original
		if err := value.UnmarshalText([]byte(s)); !errors.Is(err, ErrInvalidID) || value != original {
			t.Fatal("text decode changed value on failure")
		}
	}
	for _, s := range []string{"null", "1", "false", "{}", "[]", `""`, `"AAAAAAAAAAAAAAAAAAAAAA"`, `"` + sampleID + `" null`, strings.Repeat(" ", 300) + `"` + sampleID + `"`} {
		value := original
		if err := value.UnmarshalJSON([]byte(s)); !errors.Is(err, ErrInvalidID) || value != original {
			t.Fatal("JSON decode changed value on failure", err)
		}
	}
	if _, err := (ID{}).MarshalJSON(); !errors.Is(err, ErrInvalidID) {
		t.Fatal("zero ID serialized")
	}
	if _, err := (ID{}).MarshalText(); !errors.Is(err, ErrInvalidID) {
		t.Fatal("zero ID text serialized")
	}
	var nilID *ID
	if !errors.Is(nilID.UnmarshalText([]byte(sampleID)), ErrInvalidID) || !errors.Is(nilID.UnmarshalJSON([]byte(`"`+sampleID+`"`)), ErrInvalidID) {
		t.Fatal("nil receiver")
	}
}

func TestCounterWire(t *testing.T) {
	for _, s := range []string{"0", "1", "9007199254740993", "18446744073709551615"} {
		value, err := ParseCounter(s)
		if err != nil || value.String() != s {
			t.Fatal(s, err)
		}
		text, err := value.MarshalText()
		if err != nil || string(text) != s {
			t.Fatal(s, err)
		}
		var decoded Counter
		if err = decoded.UnmarshalText(text); err != nil || decoded != value {
			t.Fatal(s, err)
		}
		j, err := json.Marshal(value)
		if err != nil || string(j) != `"`+s+`"` {
			t.Fatalf("wrong string representation %q %v", j, err)
		}
		if err = json.Unmarshal(j, &decoded); err != nil || decoded != value {
			t.Fatal(s, err)
		}
	}
	var escaped Counter
	if err := escaped.UnmarshalJSON([]byte(`"\u0031"`)); err != nil || escaped != 1 {
		t.Fatal(err)
	}
}

func TestCounterInvalidInputs(t *testing.T) {
	for _, s := range []string{"", "00", "01", "+1", "-1", "1.0", "1e2", " 1", "1 ", "١", "18446744073709551616", strings.Repeat("9", 100000)} {
		if _, err := ParseCounter(s); !errors.Is(err, ErrInvalidCounter) {
			t.Fatalf("input length %d: %v", len(s), err)
		}
		value := Counter(42)
		if err := value.UnmarshalText([]byte(s)); !errors.Is(err, ErrInvalidCounter) || value != 42 {
			t.Fatal("text decode changed value on failure")
		}
	}
	for _, s := range []string{"null", "1", "false", "{}", "[]", `""`, `"01"`, `"18446744073709551616"`, `"1" "2"`, strings.Repeat(" ", 300) + `"1"`} {
		value := Counter(42)
		if err := value.UnmarshalJSON([]byte(s)); !errors.Is(err, ErrInvalidCounter) || value != 42 {
			t.Fatal("JSON decode changed value on failure", err)
		}
	}
	var nilCounter *Counter
	if !errors.Is(nilCounter.UnmarshalText([]byte("1")), ErrInvalidCounter) || !errors.Is(nilCounter.UnmarshalJSON([]byte(`"1"`)), ErrInvalidCounter) {
		t.Fatal("nil receiver")
	}
}

func TestIdentifierCounterInJSONDocument(t *testing.T) {
	type document struct {
		ID       ID      `json:"id"`
		Revision Counter `json:"revision"`
	}
	id, err := ParseID(sampleID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := ParseCounter("18446744073709551615")
	if err != nil {
		t.Fatal(err)
	}
	original := document{ID: id, Revision: revision}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"` + sampleID + `","revision":"18446744073709551615"}`
	if string(encoded) != want {
		t.Fatalf("wire representation = %s, want %s", encoded, want)
	}
	var decoded document
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != original {
		t.Fatal("JSON document lost identifier or revision precision")
	}
	if err := json.Unmarshal([]byte(`{"id":"`+sampleID+`","revision":18446744073709551615}`), &decoded); !errors.Is(err, ErrInvalidCounter) {
		t.Fatalf("numeric JSON revision accepted: %v", err)
	}
}

func TestEmptyScalarJSONRejected(t *testing.T) {
	id, err := ParseID(sampleID)
	if err != nil {
		t.Fatal(err)
	}
	original := id
	if err := id.UnmarshalJSON(nil); !errors.Is(err, ErrInvalidID) || id != original {
		t.Fatal("empty JSON input changed identifier")
	}
	revision := Counter(42)
	if err := revision.UnmarshalJSON(nil); !errors.Is(err, ErrInvalidCounter) || revision != 42 {
		t.Fatal("empty JSON input changed revision")
	}
}

func FuzzParseIdentifier(f *testing.F) {
	for _, input := range []string{sampleID, "", "AAAAAAAAAAAAAAAAAAAAAA", "_____________________w", sampleID + "="} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		id, err := ParseID(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidID) {
				t.Fatalf("unexpected parse error: %v", err)
			}
			return
		}
		if id.IsZero() || id.String() != input {
			t.Fatal("successful parse accepted reserved or noncanonical identifier")
		}
		encoded, err := json.Marshal(id)
		if err != nil {
			t.Fatal(err)
		}
		var decoded ID
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != id {
			t.Fatalf("identifier JSON round-trip failed: %v", err)
		}
	})
}

func FuzzParseCounter(f *testing.F) {
	for _, input := range []string{"0", "1", "9007199254740993", "18446744073709551615", "18446744073709551616", "01", "-1", ""} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		counter, err := ParseCounter(input)
		if err != nil {
			if !errors.Is(err, ErrInvalidCounter) {
				t.Fatalf("unexpected parse error: %v", err)
			}
			return
		}
		if counter.String() != input {
			t.Fatal("successful parse accepted a noncanonical revision")
		}
		encoded, err := json.Marshal(counter)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Counter
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != counter {
			t.Fatalf("counter JSON round-trip failed: %v", err)
		}
	})
}
