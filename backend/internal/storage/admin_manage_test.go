package storage

import (
	"context"
	"errors"
	"passwordmanager/internal/protocol"
	"testing"
	"time"
)

func TestAdminInviteDeleteAndCascades(t *testing.T) {
	r, bootstrap, _ := registrationFixture(t)
	ctx := context.Background()
	owner := activateInvitedAccount(t, r, bootstrap, "owner@example.test", 1)
	key, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	email := invitationEmail(t, "friend@example.test")
	wrong := protocol.NewSecret()
	defer wrong.Clear()
	if _, err := r.store.AdminCreateInvitation(ctx, wrong, email, time.Hour); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("unauthorized invitation")
	}
	grant, err := r.store.AdminCreateInvitation(ctx, key, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Secret.Clear()
	if grant.Invitation.Scope != "user" || *grant.Invitation.Email != email {
		t.Fatal("invitation role or recipient")
	}
	extra, err := r.store.CreateUserInvitation(ctx, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Secret.Clear()
	pending := createRegistrationTest(t, r, extra, email.String(), 3)
	if _, err := r.PutMaterial(ctx, pending.Registration.ID, pending.Token, registrationMaterialTest(t, r, pending)); err != nil {
		t.Fatal(err)
	}
	account := createRegistrationTest(t, r, grant, email.String(), 2)
	material := registrationMaterialTest(t, r, account)
	if _, err := r.PutMaterial(ctx, account.Registration.ID, account.Token, material); err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(ctx, account.Registration.ID, account.Token, queuedRegistrationCode(t, r, account.Registration.ID)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.AdminCreateInvitation(ctx, key, email, time.Hour); !errors.Is(err, ErrAccountExists) {
		t.Fatal("existing account invited")
	}
	sessions, err := NewSessions(r.store, r.engine, protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	login := LoginRequest{Email: email, AccountID: account.Registration.AccountID, VaultID: account.Registration.VaultID, Generation: 1, AuthSecret: material.AuthSecret, DeviceID: protocol.ID{5}, DeviceName: "Test", Platform: "windows"}
	session := sessionLogin(t, sessions, login)
	if _, err := sessions.WriteVault(ctx, session.AccessToken, vaultWriteTest(t, sessions, login, protocol.ID{6}, protocol.ID{7}, 1, 32)); err != nil {
		t.Fatal(err)
	}
	if err := r.store.AdminDeleteAccount(ctx, wrong, login.AccountID, email); !errors.Is(err, ErrAdminDenied) {
		t.Fatal("unauthorized deletion")
	}
	if err := r.store.AdminDeleteAccount(ctx, key, owner.Registration.AccountID, invitationEmail(t, "owner@example.test")); !errors.Is(err, ErrAdminProtected) {
		t.Fatal("administrator deleted")
	}
	if err := r.store.AdminDeleteAccount(ctx, key, login.AccountID, invitationEmail(t, "different@example.test")); !errors.Is(err, ErrAdminConfirmation) {
		t.Fatal("confirmation bypassed")
	}
	// A failed final delete must roll back invitation revocation and all cleanup.
	if _, err := r.store.db.Exec("CREATE TRIGGER block_delete BEFORE DELETE ON accounts BEGIN SELECT RAISE(ABORT,'test'); END"); err != nil {
		t.Fatal(err)
	}
	if err := r.store.AdminDeleteAccount(ctx, key, login.AccountID, email); !errors.Is(err, ErrUnavailable) {
		t.Fatal("rollback trigger ignored")
	}
	if _, err := r.store.VerifyInvitation(ctx, extra.Secret, email); err != nil {
		t.Fatal("failed deletion revoked invitation")
	}
	if _, err := sessions.Material(ctx, session.AccessToken); err != nil {
		t.Fatal("failed deletion lost session")
	}
	if _, err := r.store.db.Exec("DROP TRIGGER block_delete"); err != nil {
		t.Fatal(err)
	}
	if err := r.store.AdminDeleteAccount(ctx, key, login.AccountID, email); err != nil {
		t.Fatal(err)
	}
	requireAccessRejected(t, sessions, session.AccessToken)
	if _, err := sessions.Refresh(ctx, session.RefreshToken, sessionTestIP); !errors.Is(err, ErrAuthentication) {
		t.Fatal("deleted user refreshed")
	}
	if _, err := r.store.VerifyInvitation(ctx, extra.Secret, email); !errors.Is(err, ErrInvalidInvitation) {
		t.Fatal("old invitation can recreate account")
	}
	for _, table := range []string{"sessions", "refresh_tokens", "vault_state", "vault_objects", "vault_writes", "registrations", "email_verifications", "email_outbox"} {
		var count int
		query := "SELECT count(*) FROM " + table
		var args []any
		if table == "registrations" {
			query += " WHERE email='friend@example.test'"
		}
		if table == "email_verifications" || table == "email_outbox" {
			query += " WHERE registration_id IN (?,?)"
			args = []any{account.Registration.ID[:], pending.Registration.ID[:]}
		}
		if err := r.store.db.QueryRow(query, args...).Scan(&count); err != nil || count != 0 {
			t.Fatalf("cleanup %s count=%d err=%v", table, count, err)
		}
	}
	if _, _, err := r.store.AdminAccounts(ctx, key, protocol.ID{}); err != nil {
		t.Fatal("owner access lost")
	}
	if err := r.store.AdminDeleteAccount(ctx, key, login.AccountID, email); !errors.Is(err, ErrAdminConfirmation) {
		t.Fatal("missing account accepted")
	}
	replacement, err := r.store.AdminCreateInvitation(ctx, key, email, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	replacement.Secret.Clear()
}

func TestAdminMutationsRejectExpiredRevokedAndDisabledKeys(t *testing.T) {
	r, bootstrap, now := registrationFixture(t)
	ctx := context.Background()
	activateInvitedAccount(t, r, bootstrap, "owner@example.test", 1)
	key, err := r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Clear()
	email := invitationEmail(t, "friend@example.test")
	check := func() {
		t.Helper()
		if _, err := r.store.AdminCreateInvitation(ctx, key, email, time.Hour); !errors.Is(err, ErrAdminDenied) {
			t.Fatal("invalid key invited")
		}
		if err := r.store.AdminDeleteAccount(ctx, key, protocol.ID{42}, email); !errors.Is(err, ErrAdminDenied) {
			t.Fatal("invalid key deleted")
		}
	}
	*now = now.Add(24 * time.Hour)
	check()
	key, err = r.store.RotateAdminPanelKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.store.db.Exec("UPDATE accounts SET status='disabled' WHERE role='admin'"); err != nil {
		t.Fatal(err)
	}
	check()
	if _, err := r.store.db.Exec("UPDATE accounts SET status='active' WHERE role='admin'"); err != nil {
		t.Fatal(err)
	}
	if err := r.store.RevokeAdminPanelKey(ctx); err != nil {
		t.Fatal(err)
	}
	check()
}
