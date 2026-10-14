package storage

import (
	"context"
	"errors"
	"passwordmanager/internal/protocol"
	"testing"
	"time"
)

func TestAdminPanelAccessRotationExpiryAndRevocation(t *testing.T) {
	r, invite, now := registrationFixture(t)
	ctx := context.Background()
	if _, err := r.store.RotateAdminPanelKey(ctx); !errors.Is(err, ErrAdministratorRequired) {
		t.Fatal("key issued without administrator")
	}
	activateInvitedAccount(t, r, invite, "owner@example.test", 1)
	email := invitationEmail(t, "friend@example.test")
	friend, err := r.store.CreateUserInvitation(ctx, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	activateInvitedAccount(t, r, friend, email.String(), 2)
	key, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	items, next, err := r.store.AdminAccounts(ctx, key, protocol.ID{})
	if err != nil || len(items) != 2 || next != nil {
		t.Fatal("account list failed")
	}
	for _, item := range items {
		if item.Email != "owner@example.test" && item.Email != "friend@example.test" {
			t.Fatal("unexpected metadata")
		}
	}
	if _, _, err := r.store.AdminAccounts(ctx, protocol.NewSecret(), protocol.ID{}); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("wrong key accepted")
	}
	rotated, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rotated.Clear()
	if _, _, err := r.store.AdminAccounts(ctx, key, protocol.ID{}); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("old key accepted")
	}
	*now = now.Add(24 * time.Hour)
	if _, _, err := r.store.AdminAccounts(ctx, rotated, protocol.ID{}); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("expired key accepted")
	}
	revoked, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer revoked.Clear()
	if err := r.store.RevokeAdminPanelKey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.store.AdminAccounts(ctx, revoked, protocol.ID{}); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("revoked key accepted")
	}
}

func TestAdminPanelPaginationAndAdministratorRole(t *testing.T) {
	r, invite, _ := registrationFixture(t)
	ctx := context.Background()
	activateInvitedAccount(t, r, invite, "owner@example.test", 1)
	for i := 0; i < 101; i++ {
		id := protocol.ID{240, byte(i + 1)}
		vault := protocol.ID{241, byte(i + 1)}
		email := id.String() + "@example.test"
		_, err := r.store.db.Exec(`INSERT INTO accounts(account_id,email,role,vault_id,epoch_id,descriptor,verifier,password_envelope,created_at_ms) SELECT ?,?,'user',?,epoch_id,descriptor,verifier,password_envelope,created_at_ms FROM accounts WHERE role='admin' LIMIT 1`, id[:], email, vault[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	key, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	first, next, err := r.store.AdminAccounts(ctx, key, protocol.ID{})
	if err != nil || len(first) != 100 || next == nil {
		t.Fatal("first page invalid")
	}
	second, end, err := r.store.AdminAccounts(ctx, key, *next)
	if err != nil || len(second) != 2 || end != nil {
		t.Fatal("second page invalid")
	}
	seen := make(map[protocol.ID]bool)
	for _, item := range append(first, second...) {
		if seen[item.ID] {
			t.Fatal("duplicate account across pages")
		}
		seen[item.ID] = true
	}
	if _, err := r.store.db.Exec("UPDATE accounts SET role='user' WHERE role='admin'"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.store.AdminAccounts(ctx, key, protocol.ID{}); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("key retained privileges after owner role changed")
	}
}
