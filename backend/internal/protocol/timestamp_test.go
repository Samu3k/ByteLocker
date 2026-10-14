package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTimestampCalendarBoundaries(t *testing.T) {
	for _, input := range []string{"2000-02-29T23:59:59.999Z", "2400-02-29T00:00:00.000Z"} {
		if _, err := ParseTimestamp(input); err != nil {
			t.Fatalf("valid leap date rejected: %v", err)
		}
	}
	for _, input := range []string{"1900-02-29T00:00:00.000Z", "2100-02-29T00:00:00.000Z", "2026-04-31T00:00:00.000Z", "2026-01-00T00:00:00.000Z"} {
		if _, err := ParseTimestamp(input); !errors.Is(err, ErrInvalidTimestamp) {
			t.Fatal("invalid calendar date accepted")
		}
	}
	// Validate the UTC year after conversion, even if the local year fits.
	for _, input := range []time.Time{
		time.Date(0, 1, 1, 0, 0, 0, 0, time.FixedZone("east", 3600)),
		time.Date(9999, 12, 31, 23, 59, 59, 0, time.FixedZone("west", -3600)),
	} {
		if value, err := NewTimestamp(input); !errors.Is(err, ErrInvalidTimestamp) || value.Valid() {
			t.Fatal("UTC year overflow accepted")
		}
	}
}

func TestTimestampEscapedJSONAndSize(t *testing.T) {
	input := "2026-10-08T12:34:56.789Z"
	expected, err := ParseTimestamp(input)
	if err != nil {
		t.Fatal(err)
	}
	var wire strings.Builder
	wire.WriteByte('"')
	for i := 0; i < len(input); i++ {
		fmt.Fprintf(&wire, `\u%04x`, input[i])
	}
	wire.WriteByte('"')
	var decoded Timestamp
	if err := decoded.UnmarshalJSON([]byte(wire.String())); err != nil || decoded != expected {
		t.Fatal("fully escaped timestamp rejected")
	}
	compact := `"` + input + `"`
	padded := strings.Repeat(" ", maxScalarJSONSize-len(compact)) + compact
	if err := decoded.UnmarshalJSON([]byte(padded)); err != nil || decoded != expected {
		t.Fatal("bounded whitespace rejected")
	}
	if err := decoded.UnmarshalJSON([]byte(" " + padded)); !errors.Is(err, ErrInvalidTimestamp) || decoded != expected {
		t.Fatal("oversized JSON accepted or receiver changed")
	}
}

func FuzzTimestampJSON(f *testing.F) {
	for _, input := range []string{`"2026-10-08T12:34:56.789Z"`, `"\u0032026-10-08T12:34:56.789Z"`, "null", "", `"2026-10-08T12:34:56.789Z" false`} {
		f.Add([]byte(input))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		original, err := ParseTimestamp("2000-01-01T00:00:00.000Z")
		if err != nil {
			t.Fatal(err)
		}
		decoded := original
		if err = decoded.UnmarshalJSON(data); err != nil {
			if !errors.Is(err, ErrInvalidTimestamp) || decoded != original {
				t.Fatal("failed decoding changed receiver")
			}
			return
		}
		if !decoded.Valid() {
			t.Fatal("invalid value accepted")
		}
		wire, err := decoded.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var roundtrip Timestamp
		if err = json.Unmarshal(wire, &roundtrip); err != nil || roundtrip != decoded {
			t.Fatal("JSON roundtrip failed")
		}
	})
}

func TestTimestampWire(t *testing.T) {
	for _, s := range []string{"2026-10-08T12:34:56.789Z", "2024-02-29T00:00:00.000Z", "0000-01-01T00:00:00.000Z", "0001-01-01T00:00:00.000Z", "9999-12-31T23:59:59.999Z", "1969-12-31T23:59:59.999Z"} {
		ts, err := ParseTimestamp(s)
		if err != nil || !ts.Valid() || ts.String() != s {
			t.Fatalf("valid timestamp rejected: %v", err)
		}
		instant, err := ts.Time()
		if err != nil || instant.Location() != time.UTC {
			t.Fatal("not UTC")
		}
		created, err := NewTimestamp(instant)
		if err != nil || created != ts {
			t.Fatal("constructor differs")
		}
		b, err := json.Marshal(ts)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Timestamp
		if err = json.Unmarshal(b, &decoded); err != nil || decoded != ts {
			t.Fatal("JSON roundtrip failed")
		}
		b, err = ts.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		if err = decoded.UnmarshalText(b); err != nil || decoded != ts {
			t.Fatal("text roundtrip failed")
		}
	}
	invalid := []string{"", "2026-10-08T12:34:56Z", "2026-10-08T12:34:56.78Z", "2026-10-08T12:34:56.7890Z", "2026-10-08T12:34:56.789+00:00", "2026-10-08t12:34:56.789Z", "2026-10-08T12:34:56.789z", "2026-10-08T12:34:56,789Z", "2026-10-08T 2:34:56.789Z", "2023-02-29T00:00:00.000Z", "2026-13-01T00:00:00.000Z", "2026-01-01T24:00:00.000Z", "2026-01-01T00:00:60.000Z", " 2026-10-08T12:34:56.789Z", strings.Repeat("a", 257)}
	original, _ := ParseTimestamp("2026-10-08T12:34:56.789Z")
	for _, s := range invalid {
		ts, err := ParseTimestamp(s)
		if !errors.Is(err, ErrInvalidTimestamp) || ts.Valid() {
			t.Fatal("bad input accepted")
		}
		ts = original
		if err = ts.UnmarshalText([]byte(s)); !errors.Is(err, ErrInvalidTimestamp) || ts != original {
			t.Fatal("receiver changed")
		}
	}
	for _, s := range []string{"", "null", "false", "123", "{}", "[]", `"bad"`, `"2026-10-08T12:34:56.789Z" true`, strings.Repeat(" ", 257)} {
		ts := original
		if err := ts.UnmarshalJSON([]byte(s)); !errors.Is(err, ErrInvalidTimestamp) || ts != original {
			t.Fatal("bad JSON accepted")
		}
	}
	var ts Timestamp
	if err := ts.UnmarshalJSON([]byte(`"\u0032026-10-08T12:34:56.789Z"`)); err != nil || ts != original {
		t.Fatal("escaped timestamp rejected")
	}
	var zero Timestamp
	if zero.Valid() || zero.String() != "" {
		t.Fatal("zero valid")
	}
	if _, err := zero.Time(); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatal("zero Time accepted")
	}
	if _, err := zero.MarshalJSON(); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatal("zero JSON accepted")
	}
	if _, err := zero.MarshalText(); !errors.Is(err, ErrInvalidTimestamp) {
		t.Fatal("zero text accepted")
	}
	var nilTS *Timestamp
	if !errors.Is(nilTS.UnmarshalJSON(nil), ErrInvalidTimestamp) || !errors.Is(nilTS.UnmarshalText(nil), ErrInvalidTimestamp) {
		t.Fatal("nil accepted")
	}
}

func TestTimestampConversion(t *testing.T) {
	zone := time.FixedZone("offset", 2*60*60)
	input := time.Date(2026, 10, 8, 14, 34, 56, 789999999, zone)
	ts, err := NewTimestamp(input)
	if err != nil || ts.String() != "2026-10-08T12:34:56.789Z" {
		t.Fatal("UTC truncation failed")
	}
	beforeEpoch := time.Unix(-1, 999999999)
	ts, err = NewTimestamp(beforeEpoch)
	if err != nil || ts.String() != "1969-12-31T23:59:59.999Z" {
		t.Fatal("pre-epoch truncation failed")
	}
	for _, year := range []int{-1, 10000} {
		ts, err = NewTimestamp(time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC))
		if !errors.Is(err, ErrInvalidTimestamp) || ts.Valid() {
			t.Fatal("out-of-range year accepted")
		}
	}
	now := time.Now()
	ts, err = NewTimestamp(now)
	if err != nil {
		t.Fatal(err)
	}
	value, err := ts.Time()
	if err != nil || value != now.UTC().Truncate(time.Millisecond) {
		t.Fatal("clock conversion failed")
	}
}

func FuzzParseTimestamp(f *testing.F) {
	for _, s := range []string{"2026-10-08T12:34:56.789Z", "0000-01-01T00:00:00.000Z", "", "2023-02-29T00:00:00.000Z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ts, err := ParseTimestamp(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidTimestamp) || ts.Valid() {
				t.Fatal("bad failure")
			}
			return
		}
		if ts.String() != s || len(s) != 24 {
			t.Fatal("noncanonical result")
		}
		b, err := ts.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		var decoded Timestamp
		if err = decoded.UnmarshalJSON(b); err != nil || decoded != ts {
			t.Fatal("roundtrip failed")
		}
	})
}
