package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"passwordmanager/internal/protocol"
)

func testServer(t *testing.T, ready Readiness) *Server {
	t.Helper()
	var id protocol.ID
	id[0] = 1
	s, err := New(id, ready)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDiscovery(t *testing.T) {
	s := testServer(t, func(ctx context.Context) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("readiness has no deadline")
		}
		return nil
	})
	recorder := httptest.NewRecorder()
	s.PublicHandler().ServeHTTP(recorder, httptest.NewRequest("GET", "/api/v1/config", nil))
	if recorder.Code != 200 || recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatal("invalid discovery response")
	}
	var body discovery
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ServerID != s.serverID || body.APIVersion != "1" || body.RegistrationAvailable || body.Features.OfflineSync || body.Features.Recovery || body.Features.SharedVaults {
		t.Fatal("discovery claims unavailable capabilities")
	}
	if len(body.KDFProfiles) != 3 || body.DefaultKDFProfile != body.KDFProfiles[0] {
		t.Fatal("invalid profiles")
	}
	for _, profile := range body.KDFProfiles {
		d := protocol.PasswordDescriptor{Algorithm: 1, Version: profile.ArgonVersion, MemoryKiB: profile.MemoryKiB, Iterations: profile.Iterations, Parallelism: profile.Parallelism}
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := protocol.ParseID(recorder.Header().Get("X-Request-ID")); err != nil {
		t.Fatal("invalid request ID")
	}
}

func TestRoutingAndErrors(t *testing.T) {
	s := testServer(t, func(context.Context) error { return nil })
	for _, test := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/healthz", "", 404}, {"GET", "/api/v1/config/", "", 404},
		{"GET", "/api/v1/%63onfig", "", 404}, {"GET", "/api/v1/../v1/config", "", 404},
		{"POST", "/api/v1/config", "", 405}, {"HEAD", "/api/v1/config", "", 405},
		{"GET", "/api/v1/config?token=do-not-echo", "", 400}, {"GET", "/api/v1/config", "do-not-echo", 400},
		{"GET", "/api/v1/auth/login", "", 404},
	} {
		r := httptest.NewRecorder()
		s.PublicHandler().ServeHTTP(r, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)))
		if r.Code != test.status || r.Header().Get("Location") != "" || r.Header().Get("Cache-Control") != "no-store" || r.Header().Get("Content-Type") != "application/problem+json" {
			t.Fatalf("unexpected response for %s %s: %d", test.method, test.path, r.Code)
		}
		var p problem
		if err := json.Unmarshal(r.Body.Bytes(), &p); err != nil || p.Status != test.status || p.RequestID.IsZero() || p.Type != "about:blank" {
			t.Fatal("invalid error response")
		}
		if strings.Contains(r.Body.String(), "do-not-echo") {
			t.Fatal("request reflected in error")
		}
	}
	internal := httptest.NewRecorder()
	s.InternalHandler().ServeHTTP(internal, httptest.NewRequest("GET", "/api/v1/config", nil))
	if internal.Code != 404 {
		t.Fatal("API mounted on internal health listener")
	}
	r := httptest.NewRecorder()
	s.InternalHandler().ServeHTTP(r, httptest.NewRequest("GET", "/healthz", nil))
	if r.Code != 200 || r.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatal("internal health failed")
	}
}

func TestUnavailableStorage(t *testing.T) {
	s := testServer(t, func(context.Context) error { return errors.New("private storage details") })
	for path, handler := range map[string]http.Handler{"/api/v1/config": s.PublicHandler(), "/healthz": s.InternalHandler()} {
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, httptest.NewRequest("GET", path, nil))
		if r.Code != 503 || strings.Contains(r.Body.String(), "private") {
			t.Fatal("readiness failure not protected")
		}
	}
	if _, err := New(protocol.ID{}, func(context.Context) error { return nil }); err == nil {
		t.Fatal("zero identity accepted")
	}
	var id protocol.ID
	id[0] = 1
	if _, err := New(id, nil); err == nil {
		t.Fatal("missing readiness accepted")
	}
}
