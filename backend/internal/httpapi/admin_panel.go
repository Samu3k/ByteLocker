package httpapi

import (
	"context"
	"crypto/rand"
	"embed"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
	"strings"
	"time"
)

//go:embed panel/*
var panelAssets embed.FS

func (s *Server) EnableAdminPanel(store *storage.Store) error {
	if store == nil || s.adminStore != nil {
		return errors.New("httpapi: invalid admin configuration")
	}
	s.adminStore = store
	s.adminSlots = make(chan struct{}, 2)
	return nil
}

func (s *Server) adminHandler(w http.ResponseWriter, r *http.Request) {
	var requestID protocol.ID
	for requestID.IsZero() {
		_, _ = rand.Read(requestID[:])
	}
	w.Header().Set("X-Request-ID", requestID.String())
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.URL.EscapedPath() != r.URL.Path {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/v1/admin/") {
		s.adminAPI(w, r, requestID)
		return
	}
	if r.Method != "GET" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	if r.URL.RawQuery != "" {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	name, kind := "", ""
	switch r.URL.Path {
	case "/", "/admin", "/admin/":
		name = "index.html"
		kind = "text/html; charset=utf-8"
	case "/admin/app.js":
		name = "app.js"
		kind = "application/javascript; charset=utf-8"
	case "/admin/style.css":
		name = "style.css"
		kind = "text/css; charset=utf-8"
	case "/brand.png":
		name = "logo.png"
		kind = "image/png"
	default:
		writeProblem(w, 404, "not_found", requestID)
		return
	}
	data, err := panelAssets.ReadFile("panel/" + name)
	if err != nil {
		writeProblem(w, 503, "temporarily_unavailable", requestID)
		return
	}
	w.Header().Set("Content-Type", kind)
	w.WriteHeader(200)
	_, _ = w.Write(data)
}

func (s *Server) adminAPI(w http.ResponseWriter, r *http.Request, requestID protocol.ID) {
	list := r.URL.Path == "/api/v1/admin/accounts" && r.Method == "GET"
	invite := r.URL.Path == "/api/v1/admin/invitations" && r.Method == "POST"
	remove := r.URL.Path == "/api/v1/admin/accounts/delete" && r.Method == "POST"
	if !list && !invite && !remove {
		writeProblem(w, 404, "not_found", requestID)
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		writeProblem(w, 403, "invalid_origin", requestID)
		return
	}
	if origins := r.Header.Values("Origin"); len(origins) != 0 {
		origin, err := url.Parse(origins[0])
		if len(origins) != 1 || err != nil || origin.Host != r.Host || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || (origin.Scheme != "https" && !(origin.Scheme == "http" && (origin.Hostname() == "localhost" || origin.Hostname() == "127.0.0.1" || origin.Hostname() == "::1"))) {
			writeProblem(w, 403, "invalid_origin", requestID)
			return
		}
	}
	var after protocol.ID
	if list {
		var err error
		after, err = parseAdminQuery(r.URL.RawQuery)
		if err != nil || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
	} else if r.URL.RawQuery != "" {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		writeProblem(w, 401, "admin_access_denied", requestID)
		return
	}
	key, err := protocol.ParseSecret(strings.TrimPrefix(headers[0], "Bearer "))
	if err != nil {
		writeProblem(w, 401, "admin_access_denied", requestID)
		return
	}
	defer key.Clear()
	select {
	case s.adminSlots <- struct{}{}:
		defer func() { <-s.adminSlots }()
	default:
		w.Header().Set("Retry-After", "3")
		writeProblem(w, 429, "temporarily_unavailable", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if list {
		items, next, err := s.adminStore.AdminAccounts(ctx, key, after)
		if err != nil {
			adminAPIError(w, err, requestID)
			return
		}
		writeJSON(w, 200, struct {
			Items []storage.AdminAccount `json:"items"`
			Next  *protocol.ID           `json:"next_after"`
		}{items, next})
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(r.Header.Values("Content-Type")) != 1 || err != nil || media != "application/json" || len(params) > 1 || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) || r.Header.Get("Content-Encoding") != "" {
		writeProblem(w, 415, "unsupported_media_type", requestID)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	defer clear(data)
	if err != nil {
		writeProblem(w, 413, "request_too_large", requestID)
		return
	}
	if invite {
		body, err := protocol.DecodeJSON[struct {
			Email protocol.Email `json:"email"`
			Hours int            `json:"ttl_hours"`
		}](data, 4096)
		if err != nil || !body.Email.Valid() || body.Hours < 1 || body.Hours > 168 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		grant, err := s.adminStore.AdminCreateInvitation(ctx, key, body.Email, time.Duration(body.Hours)*time.Hour)
		if err != nil {
			adminAPIError(w, err, requestID)
			return
		}
		defer grant.Secret.Clear()
		secret, _ := grant.Secret.WireValue()
		expires, _ := protocol.NewTimestamp(grant.Invitation.ExpiresAt)
		writeJSON(w, 201, struct {
			ID      protocol.ID        `json:"invitation_id"`
			Email   protocol.Email     `json:"email"`
			Secret  string             `json:"invitation_secret"`
			Expires protocol.Timestamp `json:"expires_at"`
		}{grant.Invitation.ID, body.Email, secret, expires})
		return
	}
	body, err := protocol.DecodeJSON[struct {
		ID    protocol.ID    `json:"account_id"`
		Email protocol.Email `json:"confirm_email"`
	}](data, 4096)
	if err != nil || body.ID.IsZero() || !body.Email.Valid() {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	if err := s.adminStore.AdminDeleteAccount(ctx, key, body.ID, body.Email); err != nil {
		adminAPIError(w, err, requestID)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func adminAPIError(w http.ResponseWriter, err error, id protocol.ID) {
	switch {
	case errors.Is(err, storage.ErrAdminDenied):
		writeProblem(w, 401, "admin_access_denied", id)
	case errors.Is(err, storage.ErrAdminProtected):
		writeProblem(w, 403, "administrator_protected", id)
	case errors.Is(err, storage.ErrAdminConfirmation):
		writeProblem(w, 409, "confirmation_mismatch", id)
	case errors.Is(err, storage.ErrAccountExists):
		writeProblem(w, 409, "account_exists", id)
	case errors.Is(err, storage.ErrInvitationLimit):
		writeProblem(w, 429, "invitation_limit", id)
	case errors.Is(err, storage.ErrInvalidInvitationOptions):
		writeProblem(w, 400, "invalid_request", id)
	default:
		writeProblem(w, 503, "temporarily_unavailable", id)
	}
}

func parseAdminQuery(raw string) (protocol.ID, error) {
	if raw == "" {
		return protocol.ID{}, nil
	}
	if !strings.HasPrefix(raw, "after=") || strings.Count(raw, "=") != 1 {
		return protocol.ID{}, errors.New("invalid cursor")
	}
	return protocol.ParseID(strings.TrimPrefix(raw, "after="))
}
