package auth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"passwordmanager/internal/protocol"
)

func TestEmailCodeBinding(t *testing.T) {
	key, err := protocol.ParseSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	var registration protocol.ID
	registration[0] = 1
	code, err := ParseEmailCode("00001234")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := EmailCodeMAC(key, registration, code)
	if err != nil {
		t.Fatal(err)
	}
	// Independently generated with Python's hmac/hashlib using a zero key,
	// registration bytes 01 followed by 15 zeroes, and ASCII "00001234".
	const expected = "862d84977ab20dcef646be0615c79733053491bbfed71df0c7f1d3cefa954212"
	if hex.EncodeToString(digest[:]) != expected {
		t.Fatal("email code MAC differs from reference")
	}
	if !VerifyEmailCode(key, registration, code, digest) {
		t.Fatal("correct code rejected")
	}
	otherRegistration := registration
	otherRegistration[0] = 2
	otherCode, _ := ParseEmailCode("00001235")
	if VerifyEmailCode(key, otherRegistration, code, digest) || VerifyEmailCode(key, registration, otherCode, digest) || VerifyEmailCode(protocol.NewSecret(), registration, code, digest) {
		t.Fatal("code not bound to registration and key")
	}
	if VerifyEmailCode(key, registration, EmailCode{}, digest) {
		t.Fatal("invalid code accepted")
	}
	if _, err := EmailCodeMAC(key, protocol.ID{}, code); !errors.Is(err, ErrInvalidEmailCode) {
		t.Fatal("zero registration accepted")
	}
	if _, err := EmailCodeMAC(protocol.Secret{}, registration, code); !errors.Is(err, ErrInvalidEmailCode) {
		t.Fatal("invalid key accepted")
	}
}

func TestEmailCodeInputAndRedaction(t *testing.T) {
	for _, value := range []string{"00000000", "99999999", "12345678"} {
		code, err := ParseEmailCode(value)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := code.DeliveryValue()
		if err != nil || wire != value {
			t.Fatal("leading zeroes lost")
		}
		for _, format := range []string{"%v", "%#v", "%s", "%x"} {
			if fmt.Sprintf(format, code) != redacted || fmt.Sprintf(format, &code) != redacted {
				t.Fatal("code leaked")
			}
		}
		encoded, err := json.Marshal(code)
		if err != nil || string(encoded) != `"[REDACTED]"` {
			t.Fatal("JSON code leaked")
		}
		copy := code
		code.Clear()
		if _, err := code.DeliveryValue(); !errors.Is(err, ErrInvalidEmailCode) {
			t.Fatal("cleared code valid")
		}
		if _, err := copy.DeliveryValue(); err != nil {
			t.Fatal("copy invalidated")
		}
	}
	for _, value := range []string{"", "1234567", "123456789", "1234 678", "1234567a", " 12345678", "１２３４５６７８", "12345678\n"} {
		if _, err := ParseEmailCode(value); !errors.Is(err, ErrInvalidEmailCode) {
			t.Fatal("invalid code accepted")
		}
	}
	code, err := NewEmailCode()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := code.DeliveryValue()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEmailCode(wire); err != nil {
		t.Fatal("generator produced invalid code")
	}
	var nilCode *EmailCode
	nilCode.Clear()
}
