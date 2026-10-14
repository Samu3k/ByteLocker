package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	MaxJSONRequestBytes = 2 << 20
	MaxJSONDepth        = 32
)

var ErrInvalidJSONRequest = errors.New("protocol: invalid JSON request")

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// DecodeJSON decodes one request object into a fresh DTO. Every exported DTO
// field must have an explicit json tag; embedded fields and interface fields
// are unsupported. Names are case-sensitive, unlike encoding/json's fallback.
// Custom UnmarshalJSON methods own their scalar validation. Required fields,
// allowed enum values and cross-field rules remain the endpoint's responsibility.
// The HTTP layer must bound body reads before calling this function.
// Errors never contain input, field names or underlying decoder diagnostics.
func DecodeJSON[T any](data []byte, maxBytes int) (T, error) {
	var zero T
	target := reflect.TypeFor[T]()
	if maxBytes < 1 || maxBytes > MaxJSONRequestBytes || len(data) == 0 || len(data) > maxBytes ||
		target == nil || target.Kind() != reflect.Struct || !utf8.Valid(data) || !validJSONSurrogates(data) {
		return zero, ErrInvalidJSONRequest
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return zero, ErrInvalidJSONRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := readJSONValue(decoder, target, 0); err != nil {
		return zero, ErrInvalidJSONRequest
	}
	if _, err := decoder.Token(); err != io.EOF {
		return zero, ErrInvalidJSONRequest
	}
	var result T
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return zero, ErrInvalidJSONRequest
	}
	return result, nil
}

// A nil schema is used only inside a custom decoder, whose validation runs
// after this syntax, depth and duplicate-key preflight has succeeded.
func readJSONValue(decoder *json.Decoder, schema reflect.Type, depth int) error {
	if depth > MaxJSONDepth {
		return ErrInvalidJSONRequest
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidJSONRequest
	}
	if schema != nil {
		if schema.Kind() == reflect.Pointer {
			if token == nil {
				return nil
			}
			schema = schema.Elem()
		}
		if schema.Implements(jsonUnmarshalerType) || reflect.PointerTo(schema).Implements(jsonUnmarshalerType) {
			schema = nil
		}
	}
	if token == nil {
		if schema == nil {
			return nil
		}
		return ErrInvalidJSONRequest
	}
	if delimiter, ok := token.(json.Delim); ok {
		switch delimiter {
		case '{':
			var fields map[string]reflect.Type
			var element reflect.Type
			if schema != nil {
				switch schema.Kind() {
				case reflect.Struct:
					fields, err = jsonDTOFields(schema)
					if err != nil {
						return err
					}
				case reflect.Map:
					if schema.Key().Kind() != reflect.String {
						return ErrInvalidJSONRequest
					}
					element = schema.Elem()
				default:
					return ErrInvalidJSONRequest
				}
			}
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return ErrInvalidJSONRequest
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrInvalidJSONRequest
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalidJSONRequest
				}
				seen[key] = struct{}{}
				child := element
				if fields != nil {
					child, ok = fields[key]
					if !ok {
						return ErrInvalidJSONRequest
					}
				}
				if err := readJSONValue(decoder, child, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalidJSONRequest
			}
			return nil
		case '[':
			var element reflect.Type
			if schema != nil {
				if schema.Kind() != reflect.Slice && schema.Kind() != reflect.Array {
					return ErrInvalidJSONRequest
				}
				// []byte is a base64 string in encoding/json, not an array DTO.
				if schema.Kind() == reflect.Slice && schema.Elem().Kind() == reflect.Uint8 {
					return ErrInvalidJSONRequest
				}
				element = schema.Elem()
			}
			count := 0
			for decoder.More() {
				if err := readJSONValue(decoder, element, depth+1); err != nil {
					return err
				}
				count++
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalidJSONRequest
			}
			if schema != nil && schema.Kind() == reflect.Array && count != schema.Len() {
				return ErrInvalidJSONRequest
			}
			return nil
		default:
			return ErrInvalidJSONRequest
		}
	}
	if schema == nil {
		return nil
	}
	switch schema.Kind() {
	case reflect.String:
		if _, ok := token.(string); ok {
			return nil
		}
	case reflect.Bool:
		if _, ok := token.(bool); ok {
			return nil
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		if _, ok := token.(json.Number); ok {
			return nil
		}
	case reflect.Slice:
		if schema.Elem().Kind() == reflect.Uint8 {
			if _, ok := token.(string); ok {
				return nil
			}
		}
	}
	return ErrInvalidJSONRequest
}

func jsonDTOFields(schema reflect.Type) (map[string]reflect.Type, error) {
	fields := make(map[string]reflect.Type)
	for i := 0; i < schema.NumField(); i++ {
		field := schema.Field(i)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.SplitN(tag, ",", 2)[0]
		if field.Anonymous || name == "" {
			return nil, ErrInvalidJSONRequest
		}
		if _, duplicate := fields[name]; duplicate {
			return nil, ErrInvalidJSONRequest
		}
		fields[name] = field.Type
	}
	return fields, nil
}

// encoding/json replaces unpaired escaped UTF-16 surrogates with U+FFFD.
// Reject them instead; valid literal U+FFFD and valid surrogate pairs are allowed.
// This scan validates surrogate escapes only; the decoder validates JSON syntax.
func validJSONSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		unit, ok := jsonHexUnit(data, i+1)
		if !ok {
			return false
		}
		i += 4
		if unit >= 0xDC00 && unit <= 0xDFFF {
			return false
		}
		if unit >= 0xD800 && unit <= 0xDBFF {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, ok := jsonHexUnit(data, i+3)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 6
		}
	}
	return true
}

func jsonHexUnit(data []byte, start int) (uint16, bool) {
	if start+4 > len(data) {
		return 0, false
	}
	var result uint16
	for _, c := range data[start : start+4] {
		result <<= 4
		switch {
		case c >= '0' && c <= '9':
			result |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			result |= uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			result |= uint16(c - 'A' + 10)
		default:
			return 0, false
		}
	}
	return result, true
}
