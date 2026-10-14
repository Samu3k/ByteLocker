// Package emailworker runs the bounded dispatcher independently of HTTP.
package emailworker

import (
	"context"
	"errors"
	"time"

	"passwordmanager/internal/storage"
)

type Queue interface {
	DeliverNext(context.Context, storage.VerificationSender) (bool, error)
}

// Run is single-threaded. Empty queues and errors wait two seconds; successful
// jobs drain sequentially. onFailure receives no SMTP diagnostics or personal
// data and runs at most once per minute. Caller cancels and joins before closing
// SQLite. Sender implementations must honor context cancellation.
func Run(ctx context.Context, queue Queue, sender storage.VerificationSender, onFailure func()) error {
	return run(ctx, queue, sender, onFailure, 2*time.Second, time.Now)
}

func run(ctx context.Context, queue Queue, sender storage.VerificationSender, onFailure func(), interval time.Duration, now func() time.Time) error {
	if queue == nil || sender == nil {
		return errors.New("emailworker: invalid configuration")
	}
	var reported time.Time
	for {
		if ctx.Err() != nil {
			return nil
		}
		handled, err := queue.DeliverNext(ctx, sender)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && onFailure != nil && (reported.IsZero() || !now().Before(reported.Add(time.Minute))) {
			reported = now()
			onFailure()
		}
		if handled && err == nil {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
