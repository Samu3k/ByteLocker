package protocol

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type jsonChild struct {
	Name string `json:"name"`
}
type jsonRequest struct {
	Email    Email             `json:"email"`
	Count    int               `json:"count"`
	Active   bool              `json:"active"`
	Child    jsonChild         `json:"child"`
	Items    []jsonChild       `json:"items"`
	Optional *string           `json:"optional"`
	Auth     Secret            `json:"auth"`
	Pair     [2]int            `json:"pair"`
	Labels   map[string]string `json:"labels"`
}

func TestJSONRequest(t *testing.T) {
	input := `{"email":" A@EXAMPLE.COM ","count":1,"active":true,"child":{"name":"hi"},"items":[{"name":"ok"}],"optional":null,"auth":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","pair":[1,2],"labels":{"a":"b"}}`
	result, err := DecodeJSON[jsonRequest]([]byte(input), 16384)
	if err != nil || result.Email.String() != "a@example.com" || !result.Auth.Valid() || result.Count != 1 || result.Child.Name != "hi" || result.Pair != [2]int{1, 2} {
		t.Fatalf("valid input failed: %v", err)
	}
	for _, s := range []string{
		"", " ", "null", "[]", `"x"`, `{`, `{} {}`, `{"count":1,"count":2}`, `{"count":1,"\u0063ount":2}`,
		`{"Count":1}`, `{"unknown":"secret"}`, `{"child":{"name":"a","name":"b"}}`, `{"child":{"Name":"a"}}`, `{"items":[{"extra":1}]}`,
		`{"count":null}`, `{"active":null}`, `{"child":null}`, `{"count":"1"}`, `{"active":1}`, `{"child":[]}`, `{"items":{}}`, `{"items":null}`,
		`{"count":1.1}`, `{"count":1e999}`, `{"email":"invalid"}`, `{"auth":null}`, `{"auth":"bad"}`, `{"pair":[1]}`, `{"pair":[1,2,3]}`,
		`{"labels":{"a":"b","a":"c"}}`, `{"optional":"\ud800"}`, `{"optional":"\udfff"}`, `{"optional":"\ud800\u0041"}`,
		"{\"optional\":\"\xff\"}", `{"optional":"\uZZZZ"}`, `{"optional":"\u123"}`, `{"optional":"\"}`,
	} {
		result, err := DecodeJSON[jsonRequest]([]byte(s), 16384)
		if !errors.Is(err, ErrInvalidJSONRequest) || result.Email.Valid() || result.Auth.Valid() || result.Count != 0 {
			t.Fatalf("bad input accepted or partial output for %q", s)
		}
		if err.Error() != ErrInvalidJSONRequest.Error() {
			t.Fatal("error disclosed diagnostic")
		}
	}
	for _, s := range []string{`{"optional":"\ud83d\ude00"}`, `{"optional":"😀"}`, `{"optional":"\ufffd"}`, `{"optional":"\\ud800"}`, `{"optional":"quote\"slash\\"}`} {
		if _, err := DecodeJSON[jsonRequest]([]byte(s), 16384); err != nil {
			t.Fatalf("valid Unicode/escape failed: %s", s)
		}
	}
	if _, err := DecodeJSON[jsonRequest]([]byte(`{}`), 2); err != nil {
		t.Fatal("exact byte bound failed")
	}
	for _, cap := range []int{-1, 0, 1, MaxJSONRequestBytes + 1} {
		if _, err := DecodeJSON[jsonRequest]([]byte(`{}`), cap); !errors.Is(err, ErrInvalidJSONRequest) {
			t.Fatal("invalid cap accepted")
		}
	}
	if _, err := DecodeJSON[string]([]byte(`{}`), 16); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("non-DTO accepted")
	}
	if _, err := DecodeJSON[any]([]byte(`{}`), 16); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("interface root accepted")
	}
	if _, err := DecodeJSON[Timestamp]([]byte(`"2026-10-08T12:34:56.789Z"`), 100); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("scalar root accepted")
	}
	type untagged struct{ Count int }
	if _, err := DecodeJSON[untagged]([]byte(`{}`), 16); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("untagged field accepted")
	}
	// Construct an intentionally invalid schema at runtime so static analysis
	// does not confuse this rejection fixture with a production DTO defect.
	duplicate := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeFor[int](), Tag: `json:"same"`},
		{Name: "B", Type: reflect.TypeFor[int](), Tag: `json:"same"`},
	})
	if _, err := jsonDTOFields(duplicate); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("duplicate tags accepted")
	}
	type rawDTO struct {
		Value json.RawMessage `json:"value"`
	}
	nested := strings.Repeat("[", MaxJSONDepth+1) + "0" + strings.Repeat("]", MaxJSONDepth+1)
	if _, err := DecodeJSON[rawDTO]([]byte(`{"value":`+nested+`}`), 16384); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("depth cap ignored")
	}
	if _, err := DecodeJSON[rawDTO]([]byte(`{"value":{"x":1,"x":2}}`), 16384); !errors.Is(err, ErrInvalidJSONRequest) {
		t.Fatal("custom decoder duplicates accepted")
	}
}

func FuzzDecodeJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"count":1}`, `{"child":{"name":"test"}}`, `{"optional":"\ud83d\ude00"}`, `{"count":1,"count":2}`, "null"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		value, err := DecodeJSON[jsonRequest](b, 16384)
		if err != nil {
			if !errors.Is(err, ErrInvalidJSONRequest) || value.Email.Valid() || value.Auth.Valid() {
				t.Fatal("partial result")
			}
			return
		}
		if !json.Valid(b) {
			t.Fatal("invalid JSON accepted")
		}
	})
}
