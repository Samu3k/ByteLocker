// Command admin is local operator tooling, never a public administration API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type invitationOutput struct {
	ID        protocol.ID        `json:"invitation_id"`
	Email     *protocol.Email    `json:"email"`
	Scope     string             `json:"scope"`
	Status    string             `json:"status"`
	CreatedAt protocol.Timestamp `json:"created_at"`
	ExpiresAt protocol.Timestamp `json:"expires_at"`
}

func outputInvitation(invitation storage.Invitation) (invitationOutput, error) {
	created, err := protocol.NewTimestamp(invitation.CreatedAt)
	if err != nil {
		return invitationOutput{}, storage.ErrSchemaMismatch
	}
	expires, err := protocol.NewTimestamp(invitation.ExpiresAt)
	if err != nil {
		return invitationOutput{}, storage.ErrSchemaMismatch
	}
	return invitationOutput{ID: invitation.ID, Email: invitation.Email, Scope: invitation.Scope, Status: invitation.Status, CreatedAt: created, ExpiresAt: expires}, nil
}

func run(ctx context.Context, args []string, output io.Writer) error {
	const usage = "Usage: bytelocker-admin [-data-dir ./data] bootstrap [-email address] [-ttl 168h] | invite -email address [-ttl 168h] | list [-after id] [-limit 50] | revoke -id invitation_id | panel-key | panel-revoke"
	global := flag.NewFlagSet("admin", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	directory := global.String("data-dir", "./data", "Persistent data directory")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, err = fmt.Fprintln(output, usage)
			return err
		}
		return errors.New("admin: invalid arguments")
	}
	if global.NArg() < 1 {
		return errors.New("admin: command required (bootstrap, invite, list, revoke)")
	}
	command := global.Arg(0)
	if command != "bootstrap" && command != "invite" && command != "list" && command != "revoke" && command != "panel-key" && command != "panel-revoke" {
		return errors.New("admin: unknown command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var emailValue, idValue, afterValue *string
	var ttl *time.Duration
	var limit *int
	switch command {
	case "bootstrap", "invite":
		emailValue = flags.String("email", "", "Optional account recipient")
		ttl = flags.Duration("ttl", storage.DefaultInvitationTTL, "Lifetime from 5m to 168h")
	case "list":
		afterValue = flags.String("after", "", "Pagination cursor")
		limit = flags.Int("limit", 50, "Page length 1-100")
	case "revoke":
		idValue = flags.String("id", "", "Invitation ID")
	}
	if err := flags.Parse(global.Args()[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("admin: invalid command arguments")
	}
	var email *protocol.Email
	var id, after protocol.ID
	var err error
	if command == "invite" && (emailValue == nil || *emailValue == "") {
		return errors.New("admin: invite requires -email")
	}
	if emailValue != nil && *emailValue != "" {
		parsed, parseErr := protocol.ParseEmail(*emailValue)
		if parseErr != nil {
			return protocol.ErrInvalidEmail
		}
		email = &parsed
	}
	if idValue != nil {
		id, err = protocol.ParseID(*idValue)
		if err != nil {
			return protocol.ErrInvalidID
		}
	}
	if afterValue != nil && *afterValue != "" {
		after, err = protocol.ParseID(*afterValue)
		if err != nil {
			return protocol.ErrInvalidID
		}
	}
	if ttl != nil && (*ttl < 5*time.Minute || *ttl > storage.DefaultInvitationTTL || *ttl%time.Second != 0) {
		return storage.ErrInvalidInvitationOptions
	}
	if limit != nil && (*limit < 1 || *limit > 100) {
		return storage.ErrInvalidInvitationOptions
	}
	store, err := storage.Open(ctx, *directory)
	if err != nil {
		return err
	}
	defer store.Close()
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	switch command {
	case "panel-key":
		secret, err := store.RotateAdminPanelKey(ctx)
		if err != nil {
			return err
		}
		defer secret.Clear()
		wire, err := secret.WireValue()
		if err != nil {
			return err
		}
		if err := encoder.Encode(struct {
			Key      string `json:"admin_panel_key"`
			Lifetime string `json:"valid_for"`
		}{wire, "24h"}); err != nil {
			_ = store.RevokeAdminPanelKey(ctx)
			return errors.New("admin: output failed; generate a new panel key")
		}
		return nil
	case "panel-revoke":
		return store.RevokeAdminPanelKey(ctx)
	case "bootstrap", "invite":
		var grant storage.InvitationGrant
		if command == "invite" {
			grant, err = store.CreateUserInvitation(ctx, *email, *ttl)
		} else {
			grant, err = store.CreateBootstrapInvitation(ctx, email, *ttl)
		}
		if err != nil {
			return err
		}
		defer grant.Secret.Clear()
		metadata, err := outputInvitation(grant.Invitation)
		if err != nil {
			return err
		}
		wire, err := grant.Secret.WireValue()
		if err != nil {
			return err
		}
		// Explicit one-time transport output, never a diagnostic log. If stdout
		// fails, use list/revoke; the server cannot redisplay the original code.
		if err := encoder.Encode(struct {
			ServerID   protocol.ID      `json:"server_id"`
			Invitation invitationOutput `json:"invitation"`
			Secret     string           `json:"invitation_secret"`
		}{ServerID: store.Instance().ServerID, Invitation: metadata, Secret: wire}); err != nil {
			return errors.New("admin: output failed; inspect and revoke the created invitation")
		}
		return nil
	case "list":
		items, next, err := store.ListInvitations(ctx, after, *limit)
		if err != nil {
			return err
		}
		result := make([]invitationOutput, 0, len(items))
		for _, invitation := range items {
			item, err := outputInvitation(invitation)
			if err != nil {
				return err
			}
			result = append(result, item)
		}
		if err := encoder.Encode(struct {
			Items     []invitationOutput `json:"items"`
			NextAfter *protocol.ID       `json:"next_after"`
		}{Items: result, NextAfter: next}); err != nil {
			return errors.New("admin: output failed")
		}
	case "revoke":
		if err := store.RevokeInvitation(ctx, id); err != nil {
			return err
		}
		if err := encoder.Encode(struct {
			Status string `json:"status"`
		}{Status: "revoked_or_absent"}); err != nil {
			return errors.New("admin: output failed")
		}
	}
	return nil
}
