package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

func TestCredentialVerifier(t *testing.T) {
	e := NewEngine()
	credential, err := protocol.ParseSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := e.Create(context.Background(), credential)
	if err != nil || !verifier.Valid() {
		t.Fatalf("create failed: %v", err)
	}
	if match, err := e.Verify(context.Background(), credential, verifier); err != nil || !match {
		t.Fatal("correct credential rejected")
	}
	other := protocol.NewSecret()
	if match, err := e.Verify(context.Background(), other, verifier); err != nil || match {
		t.Fatal("incorrect credential accepted")
	}
	second, err := e.Create(context.Background(), credential)
	if err != nil || verifier.salt == second.salt || verifier.digest == second.digest {
		t.Fatal("salt not randomized")
	}
	record, err := verifier.StorageRecord()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseVerifier(record)
	if err != nil || parsed != verifier {
		t.Fatal("storage roundtrip failed")
	}
	record[15] ^= 1
	if parsed.salt != verifier.salt {
		t.Fatal("storage input retained by reference")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%x", "%q"} {
		if fmt.Sprintf(format, verifier) != redacted || fmt.Sprintf(format, &verifier) != redacted {
			t.Fatal("verifier diagnostic leak")
		}
	}
	encoded, err := json.Marshal(struct{ Verifier Verifier }{verifier})
	if err != nil || !bytes.Contains(encoded, []byte(redacted)) {
		t.Fatal("JSON not redacted")
	}
	if err := e.DummyVerify(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Create(context.Background(), protocol.Secret{}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatal("invalid credential accepted")
	}
	if _, err := e.Verify(context.Background(), credential, Verifier{}); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatal("invalid verifier accepted")
	}
	if _, err := (Verifier{}).StorageRecord(); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatal("invalid record emitted")
	}
	for _, offset := range []int{0, 4, 5, 6, 10, 14} {
		record, _ := verifier.StorageRecord()
		record[offset] ^= 1
		if _, err := ParseVerifier(record); !errors.Is(err, ErrInvalidVerifier) {
			t.Fatal("unsupported parameters accepted")
		}
	}
	if _, err := ParseVerifier(make([]byte, verifierRecordSize-1)); !errors.Is(err, ErrInvalidVerifier) {
		t.Fatal("truncated record accepted")
	}
}

func TestEngineCapacityAndQueueCancellation(t *testing.T) {
	e := NewEngine()
	started := make(chan struct{}, MaxActiveVerifications+MaxQueuedVerifications)
	unblock := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	e.derive = func([]byte, []byte) []byte { started <- struct{}{}; <-unblock; return make([]byte, 32) }
	credential := protocol.NewSecret()
	results := make(chan error, MaxActiveVerifications+MaxQueuedVerifications)
	for i := 0; i < MaxActiveVerifications; i++ {
		go func() { _, err := e.Create(context.Background(), credential); results <- err }()
	}
	for i := 0; i < MaxActiveVerifications; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("active jobs did not start")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for i := 0; i < MaxQueuedVerifications; i++ {
		go func() { _, err := e.Create(ctx, credential); results <- err }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(e.admitted) < MaxActiveVerifications+MaxQueuedVerifications && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(e.admitted) != MaxActiveVerifications+MaxQueuedVerifications || len(e.active) != MaxActiveVerifications {
		t.Fatal("queue accounting incorrect")
	}
	if _, err := e.Create(context.Background(), credential); !errors.Is(err, ErrBusy) {
		t.Fatal("overflow not rejected")
	}
	cancel()
	for i := 0; i < MaxQueuedVerifications; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("queued job not cancelled")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("queue did not release")
		}
	}
	if len(e.active) != MaxActiveVerifications {
		t.Fatal("cancellation freed an active computation")
	}
	once.Do(func() { close(unblock) })
	for i := 0; i < MaxActiveVerifications; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if len(e.admitted) != 0 || len(e.active) != 0 {
		t.Fatal("capacity leaked")
	}
}

func TestInFlightCancellationRetainsSlot(t *testing.T) {
	e := NewEngine()
	started := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	e.derive = func([]byte, []byte) []byte { close(started); <-unblock; return make([]byte, 32) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := e.Create(ctx, protocol.NewSecret()); finished <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("computation did not start")
	}
	cancel()
	if len(e.active) != 1 {
		t.Fatal("active slot released before computation finished")
	}
	once.Do(func() { close(unblock) })
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancelled result returned")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("computation did not finish")
	}
	if len(e.active) != 0 || len(e.admitted) != 0 {
		t.Fatal("cancelled computation leaked a slot")
	}
}

func FuzzStoredVerifier(f *testing.F) {
	fixture := Verifier{valid: true}
	fixture.salt[0] = 1
	fixture.digest[0] = 2
	record, _ := fixture.StorageRecord()
	f.Add(record)
	f.Add([]byte{})
	f.Add([]byte("PAV1"))
	f.Fuzz(func(t *testing.T, data []byte) {
		verifier, err := ParseVerifier(data)
		if err != nil {
			if !errors.Is(err, ErrInvalidVerifier) || verifier.Valid() {
				t.Fatal("bad rejection")
			}
			return
		}
		encoded, err := verifier.StorageRecord()
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatal("noncanonical record accepted")
		}
	})
}
