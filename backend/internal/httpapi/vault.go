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
	"net/url"
	"strconv"
	"strings"
	"time"

	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

func (s *Server) vaultHandler(w http.ResponseWriter, r *http.Request) {
	var requestID protocol.ID
	for requestID.IsZero() {
		_, _ = rand.Read(requestID[:])
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Request-ID", requestID.String())
	if r.URL.EscapedPath() != r.URL.Path {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	action, method := "", "GET"
	var object protocol.ID
	switch r.URL.Path {
	case "/api/v1/vault/state":
		action = "state"
	case "/api/v1/vault/sync":
		action = "sync"
	case "/api/v1/vault/objects":
		action = "create"
		method = "POST"
	default:
		if strings.HasPrefix(r.URL.Path, "/api/v1/vault/objects/") {
			var err error
			object, err = protocol.ParseID(strings.TrimPrefix(r.URL.Path, "/api/v1/vault/objects/"))
			if err == nil {
				action = "object"
				method = "GET, PUT"
			}
		}
	}
	if action == "" {
		writeProblem(w, 404, "not_found", requestID)
		return
	}
	if r.Method != method && !(action == "object" && (r.Method == "GET" || r.Method == "PUT")) {
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
	if !s.registrationLimits.allow("auth:authenticated:ip:"+ip.Unmap().String(), 600) {
		s.authenticationError(w, storage.ErrAuthRate, requestID)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
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
	token := capability.Token()
	defer token.Clear()
	material, err := s.sessions.Material(ctx, token)
	if err != nil {
		s.authenticationError(w, err, requestID)
		return
	}
	if !s.registrationLimits.allow("auth:account:"+material.AccountID.String(), 120) {
		s.authenticationError(w, storage.ErrAuthRate, requestID)
		return
	}
	if action != "sync" && r.URL.RawQuery != "" {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	if r.Method == "GET" {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		switch action {
		case "state":
			state, err := s.sessions.VaultState(ctx, token)
			if err != nil {
				s.vaultError(w, err, requestID)
				return
			}
			writeJSON(w, 200, state)
		case "object":
			item, err := s.sessions.VaultObject(ctx, token, object)
			if err != nil {
				s.vaultError(w, err, requestID)
				return
			}
			w.Header().Set("ETag", (protocol.ObjectETag{EpochID: item.EpochID, Revision: item.Revision}).String())
			writeJSON(w, 200, item)
		case "sync":
			query, err := parseVaultSync(r.URL.RawQuery)
			if err != nil {
				writeProblem(w, 400, "invalid_request", requestID)
				return
			}
			page, err := s.sessions.SyncVault(ctx, token, query)
			if err != nil {
				s.vaultError(w, err, requestID)
				return
			}
			writeJSON(w, 200, page)
		}
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	operation, err := protocol.ParseID(keys[0])
	if err != nil {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	var base *protocol.ObjectETag
	condition := ""
	if r.Method == "PUT" {
		conditions := r.Header.Values("If-Match")
		if len(conditions) == 0 {
			writeProblem(w, 428, "precondition_required", requestID)
			return
		}
		if len(conditions) != 1 {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		parsed, err := protocol.ParseObjectETag(conditions[0])
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		base = &parsed
		condition = conditions[0]
	} else if len(r.Header.Values("If-Match")) != 0 {
		writeProblem(w, 400, "invalid_request", requestID)
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
	const maxBytes = protocol.MaxJSONRequestBytes
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	defer clear(data)
	if err != nil || len(data) > maxBytes {
		writeProblem(w, 413, "payload_too_large", requestID)
		return
	}
	var epoch protocol.ID
	var encoded string
	if action == "create" {
		body, err := protocol.DecodeJSON[struct {
			Epoch    protocol.ID `json:"epoch_id"`
			Object   protocol.ID `json:"object_id"`
			Envelope string      `json:"envelope"`
		}](data, maxBytes)
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		epoch = body.Epoch
		object = body.Object
		encoded = body.Envelope
	} else {
		body, err := protocol.DecodeJSON[struct {
			Epoch    protocol.ID `json:"epoch_id"`
			Envelope string      `json:"envelope"`
		}](data, maxBytes)
		if err != nil {
			writeProblem(w, 400, "invalid_request", requestID)
			return
		}
		epoch = body.Epoch
		encoded = body.Envelope
	}
	envelope, err := protocol.ParseEnvelope(encoded)
	if err != nil {
		writeProblem(w, 400, "invalid_request", requestID)
		return
	}
	result, err := s.sessions.WriteVault(ctx, token, storage.VaultWrite{OperationID: operation, EpochID: epoch, ObjectID: object, Envelope: envelope, Base: base, Fingerprint: storage.VaultFingerprint(r.Method, r.URL.Path, condition, data)})
	if err != nil {
		s.vaultError(w, err, requestID)
		return
	}
	w.Header().Set("ETag", (protocol.ObjectETag{EpochID: result.EpochID, Revision: result.Revision}).String())
	status := 200
	if action == "create" {
		status = 201
	}
	writeJSON(w, status, result)
}
func parseVaultSync(raw string) (storage.VaultSyncRequest, error) {
	invalid := errors.New("httpapi: invalid sync query")
	if len(raw) > 1024 {
		return storage.VaultSyncRequest{}, invalid
	}
	q, err := url.ParseQuery(raw)
	if err != nil || len(q) < 4 || len(q) > 5 {
		return storage.VaultSyncRequest{}, invalid
	}
	for key, values := range q {
		if len(values) != 1 || (key != "epoch_id" && key != "since" && key != "ceiling" && key != "after_sequence" && key != "limit") {
			return storage.VaultSyncRequest{}, invalid
		}
	}
	var r storage.VaultSyncRequest
	r.EpochID, err = protocol.ParseID(q.Get("epoch_id"))
	if err != nil {
		return r, invalid
	}
	r.Since, err = protocol.ParseCounter(q.Get("since"))
	if err != nil {
		return r, invalid
	}
	r.Ceiling, err = protocol.ParseCounter(q.Get("ceiling"))
	if err != nil {
		return r, invalid
	}
	r.After, err = protocol.ParseCounter(q.Get("after_sequence"))
	if err != nil {
		return r, invalid
	}
	r.Limit = 50
	if values, ok := q["limit"]; ok {
		r.Limit, err = strconv.Atoi(values[0])
		if err != nil || strconv.Itoa(r.Limit) != values[0] {
			return r, invalid
		}
	}
	if r.Limit < 1 || r.Limit > 100 || r.Since > r.After || r.After > r.Ceiling {
		return r, invalid
	}
	return r, nil
}
func (s *Server) vaultError(w http.ResponseWriter, err error, id protocol.ID) {
	status, code := 0, ""
	switch {
	case errors.Is(err, storage.ErrVaultNotFound):
		status, code = 404, "not_found"
	case errors.Is(err, storage.ErrVaultConflict):
		status, code = 409, "state_conflict"
	case errors.Is(err, storage.ErrVaultEpoch):
		status, code = 409, "epoch_changed"
	case errors.Is(err, storage.ErrVaultSnapshot):
		status, code = 409, "snapshot_changed"
	case errors.Is(err, storage.ErrVaultPrecondition):
		status, code = 412, "revision_mismatch"
	case errors.Is(err, storage.ErrVaultIdempotency):
		status, code = 409, "idempotency_conflict"
	case errors.Is(err, storage.ErrVaultQuota), errors.Is(err, storage.ErrVaultWriteLimit):
		status, code = 429, "rate_limited"
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, storage.ErrInvalidVault):
		status, code = 400, "invalid_request"
	default:
		s.authenticationError(w, err, id)
		return
	}
	writeProblem(w, status, code, id)
}
