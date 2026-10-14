package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

// EnableAuthentication is startup configuration. Call before serving handlers;
// it must not be used to change a running server.
func (s *Server) EnableAuthentication(service *storage.Sessions) error {
	if service == nil || s.sessions != nil {
		return errors.New("httpapi: invalid authentication configuration")
	}
	s.sessions = service
	return nil
}

func (s *Server) authenticationHandler(w http.ResponseWriter, r *http.Request) {
	var requestID protocol.ID
	for requestID.IsZero() {
		_, _ = rand.Read(requestID[:])
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-ID", requestID.String())
	if r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	action, method := "", "POST"
	var target protocol.ID
	switch r.URL.Path {
	case "/api/v1/auth/prelogin":
		action = "prelogin"
	case "/api/v1/auth/login":
		action = "login"
	case "/api/v1/auth/refresh":
		action = "refresh"
	case "/api/v1/auth/logout":
		action = "logout"
	case "/api/v1/account/material":
		action = "material"
		method = "GET"
	case "/api/v1/account/sessions":
		action = "sessions"
		method = "GET"
	default:
		if strings.HasPrefix(r.URL.Path, "/api/v1/account/sessions/") {
			var err error
			target, err = protocol.ParseID(strings.TrimPrefix(r.URL.Path, "/api/v1/account/sessions/"))
			if err == nil {
				action = "revoke"
				method = "DELETE"
			}
		}
	}
	if action == "" {
		writeProblem(w, 404, "not_found", requestID)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeProblem(w, 405, "method_not_allowed", requestID)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	authenticated := action == "logout" || action == "material" || action == "sessions" || action == "revoke"
	var token protocol.Secret
	defer token.Clear()
	limit := 20
	switch action {
	case "login":
		limit = 10
	case "refresh":
		limit = 60
	}
	if authenticated {
		limit = 600
	}
	ipBucket := "auth:" + action + ":ip:" + ip.Unmap().String()
	if authenticated {
		ipBucket = "auth:authenticated:ip:" + ip.Unmap().String()
	}
	if !s.registrationLimits.allow(ipBucket, limit) {
		s.authenticationError(w, storage.ErrAuthRate, requestID)
		return
	}
	if authenticated {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			s.authenticationError(w, storage.ErrAuthentication, requestID)
			return
		}
		capability, err := protocol.ParseAuthorization(values[0])
		defer capability.Clear()
		if err != nil || capability.Class() != protocol.AccessToken {
			s.authenticationError(w, storage.ErrAuthentication, requestID)
			return
		}
		token = capability.Token()
		// Authenticate before charging an account bucket. Never trust an ID from a request.
		material, err := s.sessions.Material(ctx, token)
		if err != nil {
			s.authenticationError(w, err, requestID)
			return
		}
		if !s.registrationLimits.allow("auth:account:"+material.AccountID.String(), 120) {
			s.authenticationError(w, storage.ErrAuthRate, requestID)
			return
		}
	}
	if method == "GET" || method == "DELETE" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		switch action {
		case "material":
			a, err := s.sessions.Material(ctx, token)
			if err != nil {
				s.authenticationError(w, err, requestID)
				return
			}
			d := a.Descriptor.Bytes()
			w.Header().Set("ETag", (protocol.AccountETag{CredentialGeneration: a.Generation, RecoveryGeneration: a.RecoveryGeneration, EpochID: a.EpochID}).String())
			writeJSON(w, 200, map[string]any{"server_id": s.serverID, "account_id": a.AccountID, "vault_id": a.VaultID, "epoch_id": a.EpochID, "email": a.Email, "role": a.Role,
				"credential_generation": a.Generation, "password_descriptor": base64.RawURLEncoding.EncodeToString(d[:]), "password_envelope": a.Envelope.Base64URL(),
				"recovery_generation": a.RecoveryGeneration, "recovery_enabled": false, "recovery_id": nil, "recovery_envelope": nil})
		case "sessions":
			items, err := s.sessions.List(ctx, token)
			if err != nil {
				s.authenticationError(w, err, requestID)
				return
			}
			result := make([]map[string]any, 0, len(items))
			for _, item := range items {
				result = append(result, map[string]any{"session_id": item.SessionID, "device_id": item.DeviceID, "device_name": item.DeviceName, "platform": item.Platform,
					"created_at": wireTime(item.CreatedAt), "last_used_at": wireTime(item.LastUsedAt), "session_expires_at": wireTime(item.SessionExpiresAt), "current": item.Current})
			}
			writeJSON(w, 200, map[string]any{"items": result})
		case "revoke":
			if err := s.sessions.Revoke(ctx, token, target); err != nil {
				s.authenticationError(w, err, requestID)
				return
			}
			w.WriteHeader(204)
		}
		return
	}
	if r.Header.Get("Content-Encoding") != "" {
		writeProblem(w, 415, "unsupported_media_type", requestID)
		return
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		writeProblem(w, 415, "unsupported_media_type", requestID)
		return
	}
	const maxBytes = 16 << 10
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	defer clear(data)
	if err != nil || len(data) > maxBytes {
		writeProblem(w, 413, "request_too_large", requestID)
		return
	}
	switch action {
	case "prelogin":
		body, err := protocol.DecodeJSON[struct {
			Email protocol.Email `json:"email"`
		}](data, maxBytes)
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		p, err := s.sessions.Prelogin(ctx, body.Email)
		if err != nil {
			s.authenticationError(w, err, requestID)
			return
		}
		d := p.Descriptor.Bytes()
		writeJSON(w, 200, map[string]any{"server_id": s.serverID, "account_id": p.AccountID, "vault_id": p.VaultID, "password_descriptor": base64.RawURLEncoding.EncodeToString(d[:]), "credential_generation": p.Generation})
	case "login":
		body, err := protocol.DecodeJSON[struct {
			Email      protocol.Email   `json:"email"`
			Account    protocol.ID      `json:"account_id"`
			Vault      protocol.ID      `json:"vault_id"`
			Generation protocol.Counter `json:"credential_generation"`
			Secret     protocol.Secret  `json:"auth_secret"`
			Device     protocol.ID      `json:"device_id"`
			Name       string           `json:"device_name"`
			Platform   string           `json:"platform"`
		}](data, maxBytes)
		defer body.Secret.Clear()
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		grant, err := s.sessions.Login(ctx, storage.LoginRequest{Email: body.Email, AccountID: body.Account, VaultID: body.Vault, Generation: body.Generation, AuthSecret: body.Secret, DeviceID: body.Device, DeviceName: body.Name, Platform: body.Platform}, ip)
		if err != nil {
			s.authenticationError(w, err, requestID)
			return
		}
		writeSessionGrant(w, grant, true)
	case "refresh":
		body, err := protocol.DecodeJSON[struct {
			Token protocol.Secret `json:"refresh_token"`
		}](data, maxBytes)
		defer body.Token.Clear()
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		grant, err := s.sessions.Refresh(ctx, body.Token, ip)
		if err != nil {
			s.authenticationError(w, err, requestID)
			return
		}
		writeSessionGrant(w, grant, false)
	case "logout":
		if _, err := protocol.DecodeJSON[struct{}](data, maxBytes); err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		if err := s.sessions.Logout(ctx, token); err != nil {
			s.authenticationError(w, err, requestID)
			return
		}
		w.WriteHeader(204)
	}
}
func wireTime(t time.Time) protocol.Timestamp { result, _ := protocol.NewTimestamp(t); return result }
func writeSessionGrant(w http.ResponseWriter, g storage.SessionGrant, login bool) {
	defer g.AccessToken.Clear()
	defer g.RefreshToken.Clear()
	access, _ := g.AccessToken.WireValue()
	refresh, _ := g.RefreshToken.WireValue()
	result := map[string]any{"session_id": g.SessionID, "access_token": access, "refresh_token": refresh, "access_expires_at": wireTime(g.AccessExpiresAt), "refresh_expires_at": wireTime(g.RefreshExpiresAt), "session_expires_at": wireTime(g.SessionExpiresAt)}
	if login {
		result["account_id"] = g.AccountID
		result["vault_id"] = g.VaultID
	}
	writeJSON(w, 200, result)
}
func (s *Server) authenticationError(w http.ResponseWriter, err error, id protocol.ID) {
	status, code := 503, "temporarily_unavailable"
	switch {
	case errors.Is(err, storage.ErrAuthentication):
		status, code = 401, "invalid_credentials"
	case errors.Is(err, storage.ErrInvalidLogin):
		status, code = 400, "invalid_request"
	case errors.Is(err, storage.ErrAuthRate):
		status, code = 429, "rate_limited"
	case errors.Is(err, storage.ErrSessionLimit):
		status, code = 409, "session_limit"
	case errors.Is(err, storage.ErrSessionNotFound):
		status, code = 404, "not_found"
	}
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	if status == 503 {
		w.Header().Set("Retry-After", "5")
	}
	writeProblem(w, status, code, id)
}
