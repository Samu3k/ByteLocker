package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

func TestOperationalBindingPersistsAndRejectsReplacement(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	var fingerprint [32]byte
	fingerprint[0] = 1
	if bound, err := s.HasOperationalKeys(context.Background()); err != nil || bound {
		t.Fatal("new database already bound")
	}
	if err := s.BindOperationalKeys(context.Background(), fingerprint); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if bound, err := s.HasOperationalKeys(context.Background()); err != nil || !bound {
		t.Fatal("binding lost on restart")
	}
	if err := s.BindOperationalKeys(context.Background(), fingerprint); err != nil {
		t.Fatal("same keys refused")
	}
	fingerprint[1] = 2
	if err := s.BindOperationalKeys(context.Background(), fingerprint); !errors.Is(err, ErrOperationalKeys) {
		t.Fatal("different keys accepted")
	}
}

func TestOperationalBindingRefusesOrphanedCodes(t *testing.T) {
	s, now := invitationStore(t)
	if _, _, err := issueTestCode(t, s, protocol.NewSecret(), protocol.ID{1}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var fingerprint [32]byte
	fingerprint[0] = 1
	if err := s.BindOperationalKeys(context.Background(), fingerprint); !errors.Is(err, ErrOperationalKeys) {
		t.Fatal("new keys bound to existing code state")
	}
}
