package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

func TestAdminInvitationCommands(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	var output bytes.Buffer
	if err := run(ctx, []string{"-data-dir", directory, "bootstrap", "-email", " Marco@Example.com ", "-ttl", "1h"}, &output); err != nil {
		t.Fatal(err)
	}
	var grant struct {
		ServerID   protocol.ID      `json:"server_id"`
		Invitation invitationOutput `json:"invitation"`
		Secret     string           `json:"invitation_secret"`
	}
	if err := json.Unmarshal(output.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	secret, err := protocol.ParseSecret(grant.Secret)
	if err != nil || grant.ServerID.IsZero() || grant.Invitation.ID.IsZero() || grant.Invitation.Scope != "admin" || grant.Invitation.Email == nil || grant.Invitation.Email.String() != "marco@example.com" {
		t.Fatal("invalid bootstrap output")
	}
	output.Reset()
	if err := run(ctx, []string{"-data-dir", directory, "list"}, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), grant.Secret) || strings.Contains(output.String(), "digest") || strings.Contains(output.String(), "invitation_secret") {
		t.Fatal("list disclosed credential")
	}
	var listed struct {
		Items []invitationOutput `json:"items"`
	}
	if err := json.Unmarshal(output.Bytes(), &listed); err != nil || len(listed.Items) != 1 || listed.Items[0].Status != "active" {
		t.Fatal("list failed")
	}
	output.Reset()
	if err := run(ctx, []string{"-data-dir", directory, "revoke", "-id", grant.Invitation.ID.String()}, &output); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.VerifyInvitation(ctx, secret, *grant.Invitation.Email); !errors.Is(err, storage.ErrInvalidInvitation) {
		t.Fatal("revoked invitation still valid")
	}
}

func TestInvalidAdminArguments(t *testing.T) {
	for _, args := range [][]string{
		{}, {"unknown"}, {"bootstrap", "-email", "bad"}, {"bootstrap", "-ttl", "1m"}, {"bootstrap", "-ttl", "169h"},
		{"bootstrap", "-ttl", "1.000000001h"}, {"list", "-limit", "101"}, {"list", "-after", "bad"}, {"revoke"},
		{"revoke", "-id", "bad"}, {"bootstrap", "extra"}, {"-unknown"},
		{"invite"}, {"invite", "-email", "bad"}, {"invite", "-email", "a@example.test", "-scope", "admin"},
		{"invite", "-email", "a@example.test", "-ttl", "1m"},
	} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatal("invalid command accepted")
		}
	}
	if err := run(context.Background(), []string{"-h"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestInviteRequiresActivatedAdministrator(t *testing.T) {
	directory := t.TempDir()
	err := run(context.Background(), []string{"-data-dir", directory, "invite", "-email", "friend@example.test"}, io.Discard)
	if !errors.Is(err, storage.ErrAdministratorRequired) {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestUserInviteCommandAndRevocation(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	s, err := storage.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	// Only this CLI fixture sets the bootstrap marker directly. The storage
	// integration test exercises real administrator and friend activation.
	db, err := sql.Open("sqlite", filepath.Join(directory, "passwordmanager.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE instance SET bootstrap_closed=1 WHERE singleton=1"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	var output bytes.Buffer
	if err := run(ctx, []string{"-data-dir", directory, "invite", "-email", " Friend@Example.test ", "-ttl", "24h"}, &output); err != nil {
		t.Fatal(err)
	}
	var grant struct {
		Invitation invitationOutput `json:"invitation"`
		Secret     string           `json:"invitation_secret"`
	}
	if err := json.Unmarshal(output.Bytes(), &grant); err != nil {
		t.Fatal(err)
	}
	if grant.Invitation.Scope != "user" || grant.Invitation.Email == nil || grant.Invitation.Email.String() != "friend@example.test" {
		t.Fatal("incorrect invitation")
	}
	secret, err := protocol.ParseSecret(grant.Secret)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Clear()
	output.Reset()
	if err := run(ctx, []string{"-data-dir", directory, "list"}, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), grant.Secret) || strings.Contains(output.String(), "invitation_secret") {
		t.Fatal("list exposed secret")
	}
	s, err = storage.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.VerifyInvitation(ctx, secret, *grant.Invitation.Email); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := run(ctx, []string{"-data-dir", directory, "revoke", "-id", grant.Invitation.ID.String()}, io.Discard); err != nil {
		t.Fatal(err)
	}
	s, err = storage.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.VerifyInvitation(ctx, secret, *grant.Invitation.Email); !errors.Is(err, storage.ErrInvalidInvitation) {
		t.Fatal("revoked code accepted")
	}
	if err := run(ctx, []string{"-data-dir", directory, "invite", "-email", "next@example.test"}, failedOutput{}); err == nil || strings.Contains(err.Error(), "private writer") {
		t.Fatal("output failure not handled")
	}
}

type failedOutput struct{}

func (failedOutput) Write([]byte) (int, error) { return 0, errors.New("private writer error") }

func TestLostBootstrapOutputCanBeRevoked(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	err := run(ctx, []string{"-data-dir", directory, "bootstrap"}, failedOutput{})
	if err == nil || strings.Contains(err.Error(), "private writer") {
		t.Fatal("failed output not handled generically")
	}
	store, err := storage.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	items, _, err := store.ListInvitations(ctx, protocol.ID{}, 100)
	if err != nil || len(items) != 1 {
		t.Fatal("lost-response invitation cannot be found")
	}
	if err := store.RevokeInvitation(ctx, items[0].ID); err != nil {
		t.Fatal(err)
	}
}
