package maintenance

import (
	"context"
	"os"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
	"path/filepath"
	"testing"
)

func TestOnlineSnapshotKeepsCommittedWALAndCanBeRestored(t *testing.T) {
	root, want := fixture(t)
	ctx := context.Background()
	data := filepath.Join(root, "data")
	store, err := storage.Open(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	email, _ := protocol.ParseEmail("online@example.test")
	grant, err := store.CreateUserInvitation(ctx, email, storage.DefaultInvitationTTL)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Secret.Clear()
	snapshot := filepath.Join(data, ".bytelocker-snapshot-test")
	report, err := Snapshot(ctx, data, snapshot)
	if err != nil || report != want {
		t.Fatalf("online snapshot: %v", err)
	}
	// A subsequent live write must not change the completed snapshot.
	later, _ := protocol.ParseEmail("later@example.test")
	another, err := store.CreateUserInvitation(ctx, later, storage.DefaultInvitationTTL)
	if err != nil {
		t.Fatal(err)
	}
	defer another.Secret.Clear()
	archive := filepath.Join(t.TempDir(), "online.tar.gz")
	if _, err = CreateWithSnapshot(ctx, root, archive, snapshot); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, archive, restored); err != nil {
		t.Fatal(err)
	}
	copy, err := storage.Open(ctx, filepath.Join(restored, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	list, _, err := copy.ListInvitations(ctx, protocol.ID{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	firstFound, laterFound := false, false
	for _, item := range list {
		if item.ID == grant.Invitation.ID {
			firstFound = true
		}
		if item.ID == another.Invitation.ID {
			laterFound = true
		}
	}
	if !firstFound || laterFound {
		t.Fatal("snapshot not consistent at committed boundary")
	}
	if _, err = Snapshot(ctx, data, snapshot); err == nil {
		t.Fatal("snapshot replaced existing directory")
	}
	if _, err = os.Stat(filepath.Join(data, "passwordmanager.db")); err != nil {
		t.Fatal("live source lost")
	}
}
