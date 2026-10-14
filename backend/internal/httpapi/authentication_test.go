package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

func exerciseAuthenticationHTTP(t *testing.T, api *Server, account, vault protocol.ID, secret string) {
	t.Helper()
	request := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		var err error
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.RemoteAddr = "192.0.2.3:4321"
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" {
			t.Fatal("missing auth response protection")
		}
		return w
	}
	w := request("POST", "/api/v1/auth/prelogin", map[string]any{"email": "NEW@example.test"}, "")
	var p struct {
		Account    protocol.ID      `json:"account_id"`
		Vault      protocol.ID      `json:"vault_id"`
		Generation protocol.Counter `json:"credential_generation"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Account != account || p.Vault != vault || p.Generation != 1 {
		t.Fatal("prelogin did not resolve account")
	}
	login := map[string]any{"email": "new@example.test", "account_id": account, "vault_id": vault, "credential_generation": "1", "auth_secret": secret, "device_id": protocol.ID{7}, "device_name": "My PC", "platform": "windows"}
	type grant struct {
		ID             protocol.ID        `json:"session_id"`
		Access         string             `json:"access_token"`
		Refresh        string             `json:"refresh_token"`
		AccessExpires  protocol.Timestamp `json:"access_expires_at"`
		RefreshExpires protocol.Timestamp `json:"refresh_expires_at"`
		SessionExpires protocol.Timestamp `json:"session_expires_at"`
	}
	parse := func(w *httptest.ResponseRecorder) grant {
		t.Helper()
		var g grant
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &g) != nil || len(g.Access) != 43 || len(g.Refresh) != 43 || g.ID.IsZero() {
			t.Fatalf("invalid session response: status %d", w.Code)
		}
		return g
	}
	g := parse(request("POST", "/api/v1/auth/login", login, ""))
	exerciseVaultHTTP(t, api, g.Access, account, vault)
	w = request("GET", "/api/v1/account/material", nil, g.Access)
	var material map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &material) != nil || material["role"] != "admin" || material["password_envelope"] == nil || material["verifier"] != nil || material["auth_secret"] != nil || w.Header().Get("ETag") == "" {
		t.Fatal("invalid authenticated material")
	}
	if _, err := protocol.ParseAccountETag(w.Header().Get("ETag")); err != nil {
		t.Fatal(err)
	}
	w = request("GET", "/api/v1/account/sessions", nil, g.Access)
	var listing struct {
		Items []struct {
			Current bool `json:"current"`
		} `json:"items"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &listing) != nil || len(listing.Items) != 1 || !listing.Items[0].Current {
		t.Fatal("invalid session listing")
	}
	next := parse(request("POST", "/api/v1/auth/refresh", map[string]string{"refresh_token": g.Refresh}, ""))
	if next.ID != g.ID || next.Access == g.Access || next.Refresh == g.Refresh {
		t.Fatal("refresh did not rotate")
	}
	if request("GET", "/api/v1/account/material", nil, g.Access).Code != 401 {
		t.Fatal("old access token retained")
	}
	if request("GET", "/api/v1/account/material", nil, next.Access).Code != 200 {
		t.Fatal("rotated access unusable")
	}
	if request("POST", "/api/v1/auth/refresh", map[string]string{"refresh_token": g.Refresh}, "").Code != 401 {
		t.Fatal("refresh replay accepted")
	}
	if request("GET", "/api/v1/account/material", nil, next.Access).Code != 401 {
		t.Fatal("replay did not invalidate family")
	}
	g = parse(request("POST", "/api/v1/auth/login", login, ""))
	second := parse(request("POST", "/api/v1/auth/login", login, ""))
	if request("DELETE", "/api/v1/account/sessions/"+second.ID.String(), nil, g.Access).Code != 204 {
		t.Fatal("device revocation failed")
	}
	if request("GET", "/api/v1/account/material", nil, second.Access).Code != 401 {
		t.Fatal("revoked device retained access")
	}
	if request("POST", "/api/v1/auth/logout", struct{}{}, g.Access).Code != 204 {
		t.Fatal("logout failed")
	}
	if request("POST", "/api/v1/auth/refresh", map[string]string{"refresh_token": g.Refresh}, "").Code != 401 {
		t.Fatal("logout retained refresh")
	}
	if request("POST", "/api/v1/auth/login", map[string]any{"email": "new@example.test"}, "").Code != 400 {
		t.Fatal("incomplete login accepted")
	}
}

func TestAuthenticationHTTPRejectsAmbiguousRequests(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	sessions, err := storage.NewSessions(store, auth.NewEngine(), protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	api, _ := New(store.Instance().ServerID, store.Ping)
	if err := api.EnableAuthentication(sessions); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, body, media string
		want                      int
	}{
		{"POST", "/api/v1/auth/prelogin", `{"email":"a@example.test","email":"b@example.test"}`, "application/json", 400},
		{"POST", "/api/v1/auth/prelogin", `{"email":"a@example.test","master_password":"forbidden"}`, "application/json", 400},
		{"POST", "/api/v1/auth/prelogin", `{}`, "text/plain", 415},
		{"GET", "/api/v1/auth/login", "", "", 405},
		{"POST", "/api/v1/auth/refresh?token=ignored", "{}", "application/json", 400},
		{"POST", "/api/v1/auth/prelogin/", "{}", "application/json", 404},
		{"POST", "/api/v1/auth/%70relogin", "{}", "application/json", 400},
		{"GET", "/api/v1/account/material", "", "", 401},
		{"GET", "/api/v1/account/credentials", "", "", 404},
	} {
		r := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body))
		r.RemoteAddr = "192.0.2.99:1234"
		r.Header.Set("Content-Type", tc.media)
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d want %d", tc.path, w.Code, tc.want)
		}
	}
	token, _ := protocol.NewSecret().WireValue()
	for _, headers := range [][]string{{"Registration " + token}, {"Bearer " + token, "Bearer " + token}, {"Bearer " + token}} {
		r := httptest.NewRequest("GET", "/api/v1/account/material", nil)
		r.RemoteAddr = "192.0.2.99:1234"
		for _, h := range headers {
			r.Header.Add("Authorization", h)
		}
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal("invalid authorization accepted")
		}
	}
	// Stable synthetic prelogin without creating an account.
	var previous string
	for i := 0; i < 2; i++ {
		r := httptest.NewRequest("POST", "/api/v1/auth/prelogin", bytes.NewBufferString(`{"email":"unknown@example.test"}`))
		r.RemoteAddr = "192.0.2.98:1234"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Code != 200 || (i == 1 && w.Body.String() != previous) {
			t.Fatal("synthetic prelogin unstable")
		}
		previous = w.Body.String()
	}
}
