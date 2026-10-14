package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
	"strings"
	"testing"
	"time"
)

func exerciseAdminPanelHTTP(t *testing.T, api *Server, store *storage.Store, queue *storage.EmailQueue, template []byte, material map[string]any) {
	t.Helper()
	if err := api.EnableAdminPanel(store); err != nil {
		t.Fatal(err)
	}
	secret, err := store.RotateAdminPanelKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Clear()
	key, _ := secret.WireValue()
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/admin", "", 200}, {"/brand.png", "", 200}, {"/admin/app.js", "", 200},
		{"/api/v1/admin/accounts", "", 401}, {"/api/v1/admin/accounts", key, 200},
		{"/api/v1/admin/accounts?after=bad", key, 400}, {"/api/v1/admin/accounts?token=" + key, "", 400},
		{"/admin/unknown", key, 404}, {"/admin?key=" + key, "", 400},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Fatalf("admin response %s: %d want %d", strings.Split(tc.path, "?")[0], w.Code, tc.status)
		}
		if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Fatal("missing security headers")
		}
		if tc.path == "/api/v1/admin/accounts" && tc.status == 200 {
			body := w.Body.String()
			if !strings.Contains(body, "new@example.test") {
				t.Fatal("account missing")
			}
			for _, forbidden := range []string{"verifier", "envelope", "vault_id", "digest", key} {
				if strings.Contains(body, forbidden) {
					t.Fatal("secret or vault material leaked")
				}
			}
		}
	}
	req := httptest.NewRequest("GET", "/api/v1/admin/accounts", nil)
	req.Header.Add("Authorization", "Bearer "+key)
	req.Header.Add("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	api.PublicHandler().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("duplicate auth accepted")
	}
	exerciseAdminMutationsHTTP(t, api, store, queue, key, template, material)
	if err := store.RevokeAdminPanelKey(context.Background()); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/api/v1/admin/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	w = httptest.NewRecorder()
	api.PublicHandler().ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatal("revoked panel key accepted")
	}
	if _, err := parseAdminQuery("after=" + protocol.ID{1}.String() + "&after=" + protocol.ID{2}.String()); err == nil {
		t.Fatal("ambiguous cursor accepted")
	}
}

func exerciseAdminMutationsHTTP(t *testing.T, api *Server, store *storage.Store, queue *storage.EmailQueue, key string, template []byte, material map[string]any) {
	t.Helper()
	request := func(path, body, bearer, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		path, body, bearer, origin string
		status                     int
	}{
		{"/api/v1/admin/invitations", `{"email":"friend@example.test","ttl_hours":24}`, "", "", 401},
		{"/api/v1/admin/invitations", `{"email":"friend@example.test","ttl_hours":24}`, key, "https://evil.test", 403},
		{"/api/v1/admin/invitations", `{"email":"friend@example.test","ttl_hours":24,"scope":"admin"}`, key, "", 400},
		{"/api/v1/admin/invitations", `{"email":"a@example.test","email":"b@example.test","ttl_hours":24}`, key, "", 400},
		{"/api/v1/admin/invitations", `{"email":"friend@example.test","ttl_hours":169}`, key, "", 400},
		{"/api/v1/admin/invitations", `{"email":"new@example.test","ttl_hours":24}`, key, "", 409},
		{"/api/v1/admin/invitations?token=bad", `{}`, key, "", 400},
		{"/api/v1/admin/accounts/delete", `{}`, key, "", 400},
		{"/api/v1/admin/accounts/delete", `{"account_id":"` + protocol.ID{42}.String() + `","confirm_email":"friend@example.test"}`, key, "", 409},
	} {
		if w := request(tc.path, tc.body, tc.bearer, tc.origin); w.Code != tc.status {
			t.Fatalf("admin mutation %s status=%d want=%d", tc.path, w.Code, tc.status)
		}
	}
	items, _, err := store.AdminAccounts(context.Background(), mustPanelSecret(t, key), protocol.ID{})
	if err != nil {
		t.Fatal(err)
	}
	owner := items[0]
	ownerBody, _ := json.Marshal(map[string]any{"account_id": owner.ID, "confirm_email": owner.Email})
	if w := request("/api/v1/admin/accounts/delete", string(ownerBody), key, ""); w.Code != 403 {
		t.Fatal("HTTP administrator deletion accepted")
	}
	w := request("/api/v1/admin/invitations", `{"email":"friend@example.test","ttl_hours":24}`, key, "https://example.com")
	var invite struct {
		Email  protocol.Email  `json:"email"`
		Secret protocol.Secret `json:"invitation_secret"`
	}
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &invite) != nil {
		t.Fatalf("HTTP invite failed: %d", w.Code)
	}
	defer invite.Secret.Clear()
	ctx := context.Background()
	grant, err := api.registrations.Create(ctx, invite.Secret, invite.Email, protocol.ID{98}, netip.MustParseAddr("192.0.2.90"))
	if err != nil {
		t.Fatal(err)
	}
	raw := append([]byte(nil), template...)
	copy(raw[24:40], grant.Registration.AccountID[:])
	copy(raw[40:56], grant.Registration.VaultID[:])
	material["password_envelope"] = base64.RawURLEncoding.EncodeToString(raw)
	data, _ := json.Marshal(material)
	r := httptest.NewRequest("PUT", "/api/v1/registrations/"+grant.Registration.ID.String()+"/material", strings.NewReader(string(data)))
	wire, _ := grant.Token.WireValue()
	r.Header.Set("Authorization", "Registration "+wire)
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	api.PublicHandler().ServeHTTP(w, r)
	if w.Code != 202 {
		t.Fatalf("friend material: %d", w.Code)
	}
	code := ""
	if handled, err := queue.DeliverNext(ctx, verificationSenderFunc(func(_ context.Context, _ protocol.Email, c auth.EmailCode, _ time.Time) error {
		code, _ = c.DeliveryValue()
		return nil
	})); err != nil || !handled {
		t.Fatal("test verification delivery failed")
	}
	if err := api.registrations.Verify(ctx, grant.Registration.ID, grant.Token, code); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"account_id": grant.Registration.AccountID, "confirm_email": "friend@example.test"})
	if w := request("/api/v1/admin/accounts/delete", string(body), key, ""); w.Code != 204 {
		t.Fatalf("HTTP user deletion failed: %d", w.Code)
	}
	if w := request("/api/v1/admin/accounts/delete", string(body), key, ""); w.Code != 409 {
		t.Fatal("HTTP missing user deletion accepted")
	}
	if err := store.RevokeAdminPanelKey(ctx); err != nil {
		t.Fatal(err)
	}
	if w := request("/api/v1/admin/invitations", `{"email":"another@example.test","ttl_hours":24}`, key, ""); w.Code != 401 {
		t.Fatal("revoked key wrote invitation")
	}
}

func mustPanelSecret(t *testing.T, wire string) protocol.Secret {
	t.Helper()
	key, err := protocol.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Clear)
	return key
}
