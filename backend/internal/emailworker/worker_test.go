package emailworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

type queueFunc func(context.Context, storage.VerificationSender) (bool, error)

func (f queueFunc) DeliverNext(ctx context.Context, s storage.VerificationSender) (bool, error) {
	return f(ctx, s)
}

type inertSender struct{}

func (inertSender) SendVerification(context.Context, protocol.Email, auth.EmailCode, time.Time) error {
	return nil
}

func TestWorkerDrainsAndStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	q := queueFunc(func(context.Context, storage.VerificationSender) (bool, error) {
		calls++
		if calls == 4 {
			cancel()
			return false, nil
		}
		return true, nil
	})
	if err := Run(ctx, q, inertSender{}, nil); err != nil || calls != 4 {
		t.Fatal("worker did not drain or stop")
	}
}

func TestWorkerErrorsAreBoundedAndRetry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, reports := 0, 0
	now := time.Now()
	q := queueFunc(func(context.Context, storage.VerificationSender) (bool, error) {
		calls++
		if calls == 4 {
			cancel()
		}
		return false, errors.New("private SMTP diagnostic")
	})
	err := run(ctx, q, inertSender{}, func() { reports++ }, time.Millisecond, func() time.Time { return now })
	if err != nil || calls != 4 || reports != 1 {
		t.Fatal("worker stopped on transient failure or repeated diagnostics")
	}
}

func TestWorkerIdleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	done := make(chan error, 1)
	q := queueFunc(func(context.Context, storage.VerificationSender) (bool, error) { close(entered); return false, nil })
	go func() { done <- Run(ctx, q, inertSender{}, nil) }()
	<-entered
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle worker did not stop")
	}
}
