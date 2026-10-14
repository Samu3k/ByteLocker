package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"passwordmanager/internal/protocol"
)

func activateInvitedAccount(t *testing.T, r *Registrations, invite InvitationGrant, email string, vault byte) RegistrationGrant {
	t.Helper()
	g := createRegistrationTest(t, r, invite, email, vault)
	if _, err := r.PutMaterial(context.Background(), g.Registration.ID, g.Token, registrationMaterialTest(t, r, g)); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(context.Background(), g.Registration.ID, g.Token, queuedRegistrationCode(t, r, g.Registration.ID)); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestUserInvitationRegistrationAfterBootstrap(t *testing.T) {
	r, bootstrap, now := registrationFixture(t)
	ctx := context.Background()
	email := invitationEmail(t, "friend@example.test")
	if _, err := r.store.CreateUserInvitation(ctx, email, time.Hour); !errors.Is(err, ErrAdministratorRequired) {
		t.Fatal("user invitation allowed before administrator activation")
	}
	activateInvitedAccount(t, r, bootstrap, "owner@example.test", 1)
	if _, err := r.store.CreateBootstrapInvitation(ctx, nil, time.Hour); !errors.Is(err, ErrBootstrapClosed) {
		t.Fatal("bootstrap reopened")
	}
	for _, ttl := range []time.Duration{time.Minute, DefaultInvitationTTL + time.Second} {
		if _, err := r.store.CreateUserInvitation(ctx, email, ttl); !errors.Is(err, ErrInvalidInvitationOptions) {
			t.Fatal("invalid lifetime accepted")
		}
	}
	if _, err := r.store.CreateUserInvitation(ctx, protocol.Email{}, time.Hour); !errors.Is(err, ErrInvalidInvitationOptions) {
		t.Fatal("missing email accepted")
	}
	friend, err := r.store.CreateUserInvitation(ctx, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer friend.Secret.Clear()
	if friend.Invitation.Scope != "user" || friend.Invitation.Email == nil || *friend.Invitation.Email != email {
		t.Fatal("wrong recipient or role")
	}
	if _, err := r.store.VerifyInvitation(ctx, friend.Secret, invitationEmail(t, "stranger@example.test")); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("another email accepted")
	}
	activateInvitedAccount(t, r, friend, email.String(), 2)
	if _, err := r.store.VerifyInvitation(ctx, friend.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("consumed invitation reused")
	}
	var role string
	var vault []byte
	if err := r.store.db.QueryRow("SELECT role,vault_id FROM accounts WHERE email=?", email.String()).Scan(&role, &vault); err != nil {
		t.Fatal(err)
	}
	if role != "user" || len(vault) != 16 || vault[0] != 2 {
		t.Fatal("friend role or vault incorrect")
	}
	var admins, accounts int
	if err := r.store.db.QueryRow("SELECT count(*),sum(role='admin') FROM accounts").Scan(&accounts, &admins); err != nil {
		t.Fatal(err)
	}
	if accounts != 2 || admins != 1 {
		t.Fatal("unexpected accounts or privilege escalation")
	}
	expiring, err := r.store.CreateUserInvitation(ctx, email, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer expiring.Secret.Clear()
	*now = now.Add(5 * time.Minute)
	if _, err := r.store.VerifyInvitation(ctx, expiring.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("expired invitation accepted")
	}
	revoked, err := r.store.CreateUserInvitation(ctx, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer revoked.Secret.Clear()
	if err := r.store.RevokeInvitation(ctx, revoked.Invitation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.VerifyInvitation(ctx, revoked.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("revoked invitation accepted")
	}
}
