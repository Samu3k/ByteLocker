// Package httpapi exposes discovery, authentication and optional registration.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

type Readiness func(context.Context) error

type Server struct {
	adminStore         *storage.Store
	adminSlots         chan struct{}
	serverID           protocol.ID
	ready              Readiness
	registrations      *storage.Registrations
	sessions           *storage.Sessions
	registrationLimits *registrationLimits
}

func New(serverID protocol.ID, ready Readiness, registrations ...*storage.Registrations) (*Server, error) {
	if serverID.IsZero() || ready == nil {
		return nil, errors.New("httpapi: invalid server configuration")
	}
	if len(registrations) > 1 || (len(registrations) == 1 && registrations[0] == nil) {
		return nil, errors.New("httpapi: invalid registration configuration")
	}
	s := &Server{serverID: serverID, ready: ready, registrationLimits: &registrationLimits{buckets: make(map[string][]time.Time)}}
	if len(registrations) == 1 {
		s.registrations = registrations[0]
	}
	return s, nil
}

type kdfProfile struct {
	MemoryKiB    uint32 `json:"memory_kib"`
	Iterations   uint32 `json:"iterations"`
	Parallelism  uint32 `json:"parallelism"`
	ArgonVersion uint8  `json:"argon_version"`
}

type discovery struct {
	APIVersion            string       `json:"api_version"`
	CryptoProtocol        string       `json:"crypto_protocol"`
	EnvelopeFormat        string       `json:"envelope_format"`
	ServerID              protocol.ID  `json:"server_id"`
	RegistrationMode      string       `json:"registration_mode"`
	EmailVerification     string       `json:"email_verification"`
	KDFProfiles           []kdfProfile `json:"kdf_profiles"`
	DefaultKDFProfile     kdfProfile   `json:"default_kdf_profile"`
	RegistrationAvailable bool         `json:"registration_available"`
	Features              struct {
		OfflineSync  bool `json:"offline_sync"`
		Recovery     bool `json:"recovery"`
		SharedVaults bool `json:"shared_vaults"`
	} `json:"features"`
}

type problem struct {
	Type      string      `json:"type"`
	Title     string      `json:"title"`
	Status    int         `json:"status"`
	Code      string      `json:"code"`
	RequestID protocol.ID `json:"request_id"`
}

// PublicHandler deliberately does not mount the internal health endpoint.
// Exact path matching avoids automatic redirects carrying credentials.
func (s *Server) PublicHandler() http.Handler {
	config := s.handler("/api/v1/config", s.config)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.adminStore != nil && (r.URL.Path == "/" || r.URL.Path == "/brand.png" || r.URL.Path == "/admin" || strings.HasPrefix(r.URL.Path, "/admin/") || strings.HasPrefix(r.URL.Path, "/api/v1/admin/")) {
			s.adminHandler(w, r)
			return
		}
		if s.sessions != nil && strings.HasPrefix(r.URL.Path, "/api/v1/vault/") {
			s.vaultHandler(w, r)
			return
		}
		if s.sessions != nil && (strings.HasPrefix(r.URL.Path, "/api/v1/auth/") || strings.HasPrefix(r.URL.Path, "/api/v1/account/")) {
			s.authenticationHandler(w, r)
			return
		}
		if s.registrations != nil && (r.URL.Path == "/api/v1/registrations" || strings.HasPrefix(r.URL.Path, "/api/v1/registrations/")) {
			s.registrationHandler(w, r)
			return
		}
		config.ServeHTTP(w, r)
	})
}

func (s *Server) InternalHandler() http.Handler {
	return s.handler("/healthz", s.health)
}

func (s *Server) handler(path string, endpoint func(http.ResponseWriter, *http.Request, protocol.ID)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requestID protocol.ID
		for requestID.IsZero() {
			rand.Read(requestID[:])
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Request-ID", requestID.String())
		// Encoded aliases, trailing slashes and other paths are not routes.
		if r.URL.Path != path || r.URL.EscapedPath() != path {
			writeProblem(w, http.StatusNotFound, "not_found", requestID)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeProblem(w, http.StatusMethodNotAllowed, "method_not_allowed", requestID)
			return
		}
		if r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeProblem(w, http.StatusBadRequest, "invalid_request", requestID)
			return
		}
		endpoint(w, r, requestID)
	})
}

func (s *Server) available(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	return s.ready(ctx) == nil
}

func (s *Server) config(w http.ResponseWriter, r *http.Request, requestID protocol.ID) {
	if !s.available(r.Context()) {
		w.Header().Set("Retry-After", "5")
		writeProblem(w, http.StatusServiceUnavailable, "temporarily_unavailable", requestID)
		return
	}
	profiles := []kdfProfile{{65536, 3, 4, 19}, {131072, 3, 4, 19}, {262144, 3, 4, 19}}
	writeJSON(w, http.StatusOK, discovery{
		APIVersion: "1", CryptoProtocol: "PM1", EnvelopeFormat: "PME1", ServerID: s.serverID,
		RegistrationMode: "invitation", EmailVerification: "registration_only",
		KDFProfiles: profiles, DefaultKDFProfile: profiles[0], RegistrationAvailable: s.registrations != nil,
	})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request, requestID protocol.ID) {
	if !s.available(r.Context()) {
		writeProblem(w, http.StatusServiceUnavailable, "temporarily_unavailable", requestID)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func writeProblem(w http.ResponseWriter, status int, code string, requestID protocol.ID) {
	w.Header().Set("Content-Type", "application/problem+json")
	writeJSON(w, status, problem{Type: "about:blank", Title: http.StatusText(status), Status: status, Code: code, RequestID: requestID})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		// Response types contain only validated metadata. This branch guards
		// against future programming mistakes without emitting partial data.
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
