package httpapi

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

// Bounded per-process sliding windows. Persisted creation/email/attempt quotas
// are enforced by storage as well; forwarded IP headers are deliberately ignored.
type registrationLimits struct {
	sync.Mutex
	buckets map[string][]time.Time
}

func (l *registrationLimits) allow(key string, limit int) bool {
	l.Lock()
	defer l.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	for k, values := range l.buckets {
		n := 0
		for _, v := range values {
			if v.After(cutoff) {
				values[n] = v
				n++
			}
		}
		if n == 0 {
			delete(l.buckets, k)
		} else {
			l.buckets[k] = values[:n]
		}
	}
	values := l.buckets[key]
	if len(values) >= limit || (len(values) == 0 && len(l.buckets) >= 4096) {
		return false
	}
	l.buckets[key] = append(values, now)
	return true
}

func (s *Server) registrationHandler(w http.ResponseWriter, r *http.Request) {
	var requestID protocol.ID
	for requestID.IsZero() {
		rand.Read(requestID[:])
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-ID", requestID.String())
	if r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || ipErr != nil {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	if !s.registrationLimits.allow("ip:"+ip.Unmap().String(), 20) {
		w.Header().Set("Retry-After", "60")
		writeProblem(w, 429, "rate_limited", requestID)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/registrations"), "/")
	var id protocol.ID
	action := "create"
	allowed := "POST"
	if len(parts) == 1 && parts[0] == "" {
	} else if (len(parts) == 2 || len(parts) == 3) && parts[0] == "" {
		id, err = protocol.ParseID(parts[1])
		if err != nil {
			writeProblem(w, 404, "not_found", requestID)
			return
		}
		action = "state"
		allowed = "GET, DELETE"
		if len(parts) == 3 {
			action = parts[2]
			switch action {
			case "material":
				allowed = "PUT"
			case "resend", "verify":
				allowed = "POST"
			default:
				writeProblem(w, 404, "not_found", requestID)
				return
			}
		}
	} else {
		writeProblem(w, 404, "not_found", requestID)
		return
	}
	validMethod := r.Method == allowed || (action == "state" && (r.Method == "GET" || r.Method == "DELETE"))
	if !validMethod {
		w.Header().Set("Allow", allowed)
		writeProblem(w, 405, "method_not_allowed", requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	var token protocol.Secret
	defer token.Clear()
	if action != "create" {
		values := r.Header.Values("Authorization")
		if len(values) != 1 {
			writeProblem(w, 401, "invalid_credentials", requestID)
			return
		}
		capability, err := protocol.ParseAuthorization(values[0])
		defer capability.Clear()
		if err != nil || capability.Class() != protocol.RegistrationToken {
			writeProblem(w, 401, "invalid_credentials", requestID)
			return
		}
		token = capability.Token()
	}
	if action == "state" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		if r.Method == "DELETE" {
			err = s.registrations.Cancel(ctx, id, token)
			if err != nil {
				s.registrationError(w, err, requestID)
				return
			}
			w.WriteHeader(204)
			return
		}
		state, err := s.registrations.Get(ctx, id, token)
		if err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		writeRegistrationState(w, 200, state)
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
	maxBytes := 16 << 10
	if action == "material" {
		maxBytes = protocol.MaxJSONRequestBytes
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	defer clear(data)
	if err != nil || len(data) > maxBytes {
		writeProblem(w, 413, "request_too_large", requestID)
		return
	}
	switch action {
	case "create":
		body, err := protocol.DecodeJSON[struct {
			Invitation protocol.Secret `json:"invitation_secret"`
			Email      protocol.Email  `json:"email"`
			Vault      protocol.ID     `json:"vault_id"`
		}](data, maxBytes)
		defer body.Invitation.Clear()
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		grant, err := s.registrations.Create(ctx, body.Invitation, body.Email, body.Vault, ip)
		if err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		defer grant.Token.Clear()
		wire, _ := grant.Token.WireValue()
		expires, _ := protocol.NewTimestamp(grant.Registration.ExpiresAt)
		writeJSON(w, 201, struct {
			ID         protocol.ID        `json:"registration_id"`
			Token      string             `json:"registration_token"`
			Server     protocol.ID        `json:"server_id"`
			Account    protocol.ID        `json:"account_id"`
			Vault      protocol.ID        `json:"vault_id"`
			Expires    protocol.Timestamp `json:"expires_at"`
			Credential string             `json:"credential_generation"`
			Recovery   string             `json:"recovery_generation"`
		}{grant.Registration.ID, wire, s.serverID, grant.Registration.AccountID, grant.Registration.VaultID, expires, "1", "0"})
	case "material":
		if _, err := s.registrations.Get(ctx, id, token); err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		if !s.registrationLimits.allow("material:"+id.String(), 5) {
			w.Header().Set("Retry-After", "60")
			writeProblem(w, 429, "rate_limited", requestID)
			return
		}
		body, err := protocol.DecodeJSON[struct {
			Epoch      protocol.ID     `json:"epoch_id"`
			Descriptor string          `json:"password_descriptor"`
			Secret     protocol.Secret `json:"auth_secret"`
			Envelope   string          `json:"password_envelope"`
		}](data, maxBytes)
		defer body.Secret.Clear()
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		descriptor, dErr := protocol.ParsePasswordDescriptor(body.Descriptor)
		envelope, eErr := protocol.ParseEnvelope(body.Envelope)
		if dErr != nil || eErr != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		state, err := s.registrations.PutMaterial(ctx, id, token, storage.RegistrationMaterial{EpochID: body.Epoch, Descriptor: descriptor, AuthSecret: body.Secret, Envelope: envelope})
		if err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		writeRegistrationState(w, 202, state)
	case "resend":
		if _, err := protocol.DecodeJSON[struct{}](data, maxBytes); err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		state, err := s.registrations.Resend(ctx, id, token)
		if err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		writeRegistrationState(w, 202, state)
	case "verify":
		body, err := protocol.DecodeJSON[struct {
			Code string `json:"code"`
		}](data, maxBytes)
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		if err := s.registrations.Verify(ctx, id, token, body.Code); err != nil {
			s.registrationError(w, err, requestID)
			return
		}
		w.WriteHeader(204)
	}
}

func writeRegistrationState(w http.ResponseWriter, status int, state storage.Registration) {
	expires, _ := protocol.NewTimestamp(state.ExpiresAt)
	writeJSON(w, status, struct {
		Status  string             `json:"status"`
		Expires protocol.Timestamp `json:"expires_at"`
	}{state.Status, expires})
}

func (s *Server) registrationError(w http.ResponseWriter, err error, id protocol.ID) {
	status, code := 503, "temporarily_unavailable"
	switch {
	case errors.Is(err, storage.ErrRegistrationToken), errors.Is(err, storage.ErrInvalidInvitation):
		status, code = 401, "invalid_credentials"
	case errors.Is(err, storage.ErrRegistrationExpired):
		status, code = 410, "registration_expired"
	case errors.Is(err, storage.ErrRegistrationConflict):
		status, code = 409, "state_conflict"
	case errors.Is(err, storage.ErrRegistrationUnavailable):
		status, code = 409, "registration_unavailable"
	case errors.Is(err, storage.ErrRegistrationMaterial):
		status, code = 400, "invalid_request"
	case errors.Is(err, storage.ErrVerificationCode):
		status, code = 400, "invalid_verification_code"
	case errors.Is(err, storage.ErrRegistrationLimit), storage.IsEmailIssueLimited(err):
		status, code = 429, "rate_limited"
	case errors.Is(err, auth.ErrBusy):
		status, code = 503, "temporarily_unavailable"
	}
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	if status == 503 {
		w.Header().Set("Retry-After", "5")
	}
	writeProblem(w, status, code, id)
}
