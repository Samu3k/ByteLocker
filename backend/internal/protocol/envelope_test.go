package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// goldenEnvelopeHex is the public synthetic PM1 fixture from crypto-protocol.md.
// It is deliberately embedded so tests do not require documentation files.
const goldenEnvelopeHex = "504d453101000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00000000000000000000000000000000000000000000000100000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaab0000001e0113000100000000000300000004000102030405060708090a0b0c0d0e0fa5656aa25fd4d401ceeeb391808aae8f6801f2c8f5cc96f70ede1533b146a56fbbf822bc077e3e9bc4c603dcf01f2af7"

func vector(t *testing.T) []byte {
	t.Helper()
	raw, err := hex.DecodeString(goldenEnvelopeHex)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func encode(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func contextFor(e *Envelope) ServerContext {
	h := e.Header()
	c := ServerContext{Kind: h.Kind, ServerID: h.ServerID, AccountID: h.AccountID, VaultID: h.VaultID, EpochID: h.EpochID, ObjectID: h.ObjectID, Generation: h.Generation}
	if d, ok := e.PasswordDescriptor(); ok {
		c.PasswordDescriptor = &d
	}
	if id, ok := e.RecoveryID(); ok {
		c.RecoveryID = &id
	}
	return c
}

func structural(t *testing.T, kind EnvelopeKind, length int) []byte {
	t.Helper()
	original := vector(t)
	metadata := 0
	if kind == KindPassword {
		metadata = 30
	}
	if kind == KindRecovery {
		metadata = 16
	}
	raw := make([]byte, 148+metadata+length+16)
	copy(raw[:148], original[:148])
	raw[4] = byte(kind)
	binary.BigEndian.PutUint32(raw[96:100], uint32(length))
	binary.BigEndian.PutUint32(raw[144:148], uint32(metadata))
	if kind == KindPassword {
		copy(raw[148:178], original[148:178])
	}
	if kind == KindRecovery {
		copy(raw[148:164], original[8:24])
	}
	if kind == KindObject || kind == KindLocal {
		raw[72] = 1
	}
	return raw
}

func TestPM1GoldenEnvelope(t *testing.T) {
	raw := vector(t)
	e, err := ParseEnvelope(encode(raw))
	if err != nil {
		t.Fatal(err)
	}
	if e.Header().Kind != KindPassword || len(e.HeaderBytes()) != 178 || len(e.Ciphertext()) != 32 || len(e.Bytes()) != 226 {
		t.Fatal("wrong fields")
	}
	if err = e.MatchServerContext(contextFor(e)); err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString("e35187d5b2589a340149d81f784fe5f4cafd756a703ae6d930a38b8542237692")
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	nonce := e.Header().Nonce
	plaintext, err := aead.Open(nil, nonce[:], raw[178:], e.HeaderBytes())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte{96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127}) {
		t.Fatal("wrong plaintext")
	}
	bad := bytes.Clone(raw)
	bad[len(bad)-1] ^= 1
	parsed, err := ParseEnvelope(encode(bad))
	if err != nil {
		t.Fatal("parser must not pretend to verify tag")
	}
	if err = parsed.MatchServerContext(contextFor(e)); err != nil {
		t.Fatal(err)
	}
	if _, err = aead.Open(nil, nonce[:], bad[178:], e.HeaderBytes()); err == nil {
		t.Fatal("GCM accepted altered tag")
	}
}

func TestCanonicalEncoding(t *testing.T) {
	valid := encode(vector(t))
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := bytes.IndexByte([]byte(alphabet), valid[len(valid)-1])
	noncanonical := valid[:len(valid)-1] + string(alphabet[last+1])
	for name, input := range map[string]string{"empty": "", "newline": valid + "\n", "crlf": valid + "\r\n", "padding": valid + "=", "space": " " + valid, "standard": "+" + valid[1:], "unicode": "é" + valid, "unused_bits": noncanonical} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseEnvelope(input); !errors.Is(err, ErrInvalidEncoding) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMalformedHeaders(t *testing.T) {
	changes := map[string]func([]byte){
		"magic": func(b []byte) { b[0] = 0 }, "kind": func(b []byte) { b[4] = 0 }, "flags": func(b []byte) { b[5] = 1 }, "suite": func(b []byte) { b[7] = 2 },
		"server": func(b []byte) { clear(b[8:24]) }, "account": func(b []byte) { clear(b[24:40]) }, "vault": func(b []byte) { clear(b[40:56]) }, "epoch": func(b []byte) { clear(b[56:72]) },
		"object": func(b []byte) { b[72] = 1 }, "generation": func(b []byte) { clear(b[88:96]) }, "plaintext_zero": func(b []byte) { clear(b[96:100]) },
		"plaintext_overflow": func(b []byte) { binary.BigEndian.PutUint32(b[96:100], 0xffffffff) }, "metadata_overflow": func(b []byte) { binary.BigEndian.PutUint32(b[144:148], 0xffffffff) },
		"algorithm": func(b []byte) { b[148] = 2 }, "argon_version": func(b []byte) { b[149] = 16 }, "memory": func(b []byte) { binary.BigEndian.PutUint32(b[150:154], 19456) },
		"iterations": func(b []byte) { binary.BigEndian.PutUint32(b[154:158], 2) }, "lanes": func(b []byte) { binary.BigEndian.PutUint32(b[158:162], 1) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			b := vector(t)
			change(b)
			if _, err := ParseEnvelope(encode(b)); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("got %v", err)
			}
		})
	}
	for n := 0; n < len(vector(t)); n++ {
		if _, err := ParseEnvelope(encode(vector(t)[:n])); err == nil {
			t.Fatalf("accepted prefix %d", n)
		}
	}
	if _, err := ParseEnvelope(encode(append(vector(t), 0))); err == nil {
		t.Fatal("accepted trailing byte")
	}
}

func TestKindsAndLimits(t *testing.T) {
	for _, kind := range []EnvelopeKind{KindPassword, KindRecovery, KindObject, KindLocal} {
		length := 32
		if kind == KindObject || kind == KindLocal {
			length = 1
		}
		e, err := ParseEnvelope(encode(structural(t, kind, length)))
		if err != nil {
			t.Fatal(kind, err)
		}
		err = e.MatchServerContext(contextFor(e))
		if kind == KindLocal {
			if !errors.Is(err, ErrInvalidContext) {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(kind, err)
		}
	}
	if _, err := ParseEnvelope(encode(structural(t, KindObject, MaxPlaintextSize))); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEnvelope(encode(structural(t, KindObject, MaxPlaintextSize+1))); err == nil {
		t.Fatal("accepted excess plaintext")
	}
	if _, err := ParseEnvelope(encode(make([]byte, MaxEnvelopeSize+1))); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Fatal(err)
	}
	bad := structural(t, KindRecovery, 32)
	clear(bad[148:164])
	if _, err := ParseEnvelope(encode(bad)); err == nil {
		t.Fatal("accepted zero recovery ID")
	}
	bad = structural(t, KindObject, 1)
	clear(bad[72:88])
	if _, err := ParseEnvelope(encode(bad)); err == nil {
		t.Fatal("accepted zero object ID")
	}
}

func TestContextsAndIsolation(t *testing.T) {
	e, _ := ParseEnvelope(encode(vector(t)))
	baseline := contextFor(e)
	for name, change := range map[string]func(*ServerContext){"server": func(c *ServerContext) { c.ServerID[0] ^= 1 }, "account": func(c *ServerContext) { c.AccountID[0] ^= 1 }, "vault": func(c *ServerContext) { c.VaultID[0] ^= 1 }, "epoch": func(c *ServerContext) { c.EpochID[0] ^= 1 }, "generation": func(c *ServerContext) { c.Generation++ }, "salt": func(c *ServerContext) { d := *c.PasswordDescriptor; d.Salt[0] ^= 1; c.PasswordDescriptor = &d }} {
		t.Run(name, func(t *testing.T) {
			c := baseline
			change(&c)
			if !errors.Is(e.MatchServerContext(c), ErrContextMismatch) {
				t.Fatal("accepted mismatch")
			}
		})
	}
	if !errors.Is(e.MatchServerContext(ServerContext{}), ErrInvalidContext) {
		t.Fatal("accepted empty context")
	}
	c := baseline
	c.PasswordDescriptor = nil
	if !errors.Is(e.MatchServerContext(c), ErrInvalidContext) {
		t.Fatal("descriptor not required")
	}
	var absent *Envelope
	if !errors.Is(absent.MatchServerContext(baseline), ErrInvalidEnvelope) {
		t.Fatal("accepted nil")
	}
	zero := &Envelope{}
	if !errors.Is(zero.MatchServerContext(baseline), ErrInvalidEnvelope) {
		t.Fatal("accepted zero value")
	}
	original := e.Base64URL()
	b := e.Bytes()
	b[0] ^= 1
	h := e.HeaderBytes()
	h[0] ^= 1
	ct := e.Ciphertext()
	ct[0] ^= 1
	tag := e.Tag()
	tag[0] ^= 1
	header := e.Header()
	header.AccountID[0] ^= 1
	d, _ := e.PasswordDescriptor()
	d.Salt[0] ^= 1
	if e.Base64URL() != original || e.MatchServerContext(baseline) != nil {
		t.Fatal("accessor exposed mutable storage")
	}
}

func TestDescriptorProfiles(t *testing.T) {
	e, _ := ParseEnvelope(encode(vector(t)))
	d, _ := e.PasswordDescriptor()
	for _, memory := range []uint32{65536, 131072, 262144} {
		d.MemoryKiB = memory
		b := d.Bytes()
		parsed, err := ParsePasswordDescriptor(encode(b[:]))
		if err != nil || parsed != d {
			t.Fatal(memory, err)
		}
	}
	for _, input := range []string{"", encode([]byte{1}), encode(make([]byte, 31))} {
		if _, err := ParsePasswordDescriptor(input); !errors.Is(err, ErrInvalidDescriptor) {
			t.Fatal(err)
		}
	}
}

// FuzzEnvelope explores arbitrary input; only the bounded public parser runs.
func FuzzEnvelope(f *testing.F) {
	golden, err := hex.DecodeString(goldenEnvelopeHex)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encode(golden))
	f.Add("")
	f.Add("UE1FMQ")
	f.Add("not-base64!")
	f.Fuzz(func(t *testing.T, input string) {
		e, err := ParseEnvelope(input)
		if err != nil {
			return
		}
		if e.Base64URL() != input {
			t.Fatal("noncanonical success")
		}
		again, err := ParseEnvelope(e.Base64URL())
		if err != nil || !bytes.Equal(again.Bytes(), e.Bytes()) {
			t.Fatal("roundtrip failed")
		}
	})
}

func TestMalformedKindLayouts(t *testing.T) {
	cases := []struct {
		name      string
		kind      EnvelopeKind
		plaintext int
		mutate    func([]byte)
	}{
		{"password_payload", KindPassword, 31, nil},
		{"recovery_payload", KindRecovery, 31, nil},
		{"empty_object", KindObject, 0, nil},
		{"empty_local", KindLocal, 0, nil},
		{"password_metadata", KindPassword, 32, func(b []byte) { binary.BigEndian.PutUint32(b[144:148], 29) }},
		{"recovery_object", KindRecovery, 32, func(b []byte) { b[72] = 1 }},
		{"local_object", KindLocal, 1, func(b []byte) { clear(b[72:88]) }},
		{"object_metadata", KindObject, 1, func(b []byte) { binary.BigEndian.PutUint32(b[144:148], 1) }},
		{"unknown_kind", KindObject, 1, func(b []byte) { b[4] = 255 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := structural(t, tc.kind, tc.plaintext)
			if tc.mutate != nil {
				tc.mutate(raw)
			}
			if _, err := ParseEnvelope(encode(raw)); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestMaximumGeneration(t *testing.T) {
	raw := vector(t)
	binary.BigEndian.PutUint64(raw[88:96], ^uint64(0))
	e, err := ParseEnvelope(encode(raw))
	if err != nil {
		t.Fatal(err)
	}
	if e.Header().Generation != ^uint64(0) {
		t.Fatal("generation truncated")
	}
	if err := e.MatchServerContext(contextFor(e)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryContext(t *testing.T) {
	e, err := ParseEnvelope(encode(structural(t, KindRecovery, 32)))
	if err != nil {
		t.Fatal(err)
	}
	c := contextFor(e)
	wrong := *c.RecoveryID
	wrong[0] ^= 1
	c.RecoveryID = &wrong
	if !errors.Is(e.MatchServerContext(c), ErrContextMismatch) {
		t.Fatal("accepted different recovery ID")
	}
	c.RecoveryID = nil
	if !errors.Is(e.MatchServerContext(c), ErrInvalidContext) {
		t.Fatal("accepted missing recovery ID")
	}
}

func TestLocalStateRejectedForStorage(t *testing.T) {
	e, err := ParseEnvelope(encode(structural(t, KindLocal, 1)))
	if err != nil {
		t.Fatal(err)
	}
	c := contextFor(e)
	if !errors.Is(e.MatchServerContext(c), ErrInvalidContext) {
		t.Fatal("local kind accepted for server")
	}
	c.Kind = KindObject
	if !errors.Is(e.MatchServerContext(c), ErrContextMismatch) {
		t.Fatal("local blob accepted as object")
	}
}

func TestNilAndZeroAccessors(t *testing.T) {
	for _, e := range []*Envelope{nil, {}} {
		if e.Header() != (EnvelopeHeader{}) || len(e.Bytes()) != 0 || len(e.HeaderBytes()) != 0 || len(e.Ciphertext()) != 0 || e.Base64URL() != "" || e.Tag() != ([AuthenticationTagSize]byte{}) {
			t.Fatal("unexpected empty accessor")
		}
		if _, ok := e.PasswordDescriptor(); ok {
			t.Fatal("empty descriptor reported present")
		}
		if _, ok := e.RecoveryID(); ok {
			t.Fatal("empty recovery ID reported present")
		}
	}
}
