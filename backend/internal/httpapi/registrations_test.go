package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

type verificationSenderFunc func(context.Context, protocol.Email, auth.EmailCode, time.Time) error

func (f verificationSenderFunc) SendVerification(c context.Context, e protocol.Email, code auth.EmailCode, x time.Time) error {
	return f(c, e, code, x)
}

func TestRegistrationHTTPCompleteFlow(t *testing.T) {
	ctx := context.Background()
	store, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	invite, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	queue, err := storage.NewEmailQueue(store, protocol.NewSecret(), protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine()
	registrations, err := storage.NewRegistrations(store, queue, engine)
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(store.Instance().ServerID, store.Ping, registrations)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := storage.NewSessions(store, engine, protocol.NewSecret(), protocol.NewSecret())
	if err != nil {
		t.Fatal(err)
	}
	if err := api.EnableAuthentication(sessions); err != nil {
		t.Fatal(err)
	}
	handler := api.PublicHandler()
	request := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		r.RemoteAddr = "192.0.2.1:4321"
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if token != "" {
			r.Header.Set("Authorization", "Registration "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := request("GET", "/api/v1/config", nil, "")
	var config struct {
		Available bool `json:"registration_available"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &config); err != nil || !config.Available {
		t.Fatal("registration not advertised")
	}
	wireInvite, _ := invite.Secret.WireValue()
	w = request("POST", "/api/v1/registrations", map[string]any{"invitation_secret": wireInvite, "email": "new@example.test", "vault_id": protocol.ID{1}}, "")
	if w.Code != 201 {
		t.Fatal("HTTP creation failed")
	}
	var grant struct {
		ID      protocol.ID `json:"registration_id"`
		Token   string      `json:"registration_token"`
		Account protocol.ID `json:"account_id"`
		Vault   protocol.ID `json:"vault_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &grant); err != nil || len(grant.Token) != 43 {
		t.Fatal("invalid capability response")
	}
	path := "/api/v1/registrations/" + grant.ID.String()
	if w := request("GET", path, nil, ""); w.Code != 401 {
		t.Fatal("anonymous state access accepted")
	}
	d := protocol.PasswordDescriptor{Algorithm: 1, Version: 19, MemoryKiB: 65536, Iterations: 3, Parallelism: 4, Salt: [16]byte{1}}
	descriptor := d.Bytes()
	epoch := protocol.ID{2}
	raw := make([]byte, 226)
	copy(raw, "PME1")
	raw[4] = 1
	binary.BigEndian.PutUint16(raw[6:8], 1)
	serverID := store.Instance().ServerID
	copy(raw[8:24], serverID[:])
	copy(raw[24:40], grant.Account[:])
	copy(raw[40:56], grant.Vault[:])
	copy(raw[56:72], epoch[:])
	binary.BigEndian.PutUint64(raw[88:96], 1)
	binary.BigEndian.PutUint32(raw[96:100], 32)
	binary.BigEndian.PutUint32(raw[144:148], 30)
	copy(raw[148:178], descriptor[:])
	secret := protocol.NewSecret()
	wireSecret, _ := secret.WireValue()
	material := map[string]any{"epoch_id": epoch, "password_descriptor": base64.RawURLEncoding.EncodeToString(descriptor[:]), "auth_secret": wireSecret, "password_envelope": base64.RawURLEncoding.EncodeToString(raw)}
	for i := 0; i < 2; i++ {
		if w := request("PUT", path+"/material", material, grant.Token); w.Code != 202 {
			t.Fatal("HTTP material or retry failed")
		}
	}
	code := ""
	calls := 0
	if handled, err := queue.DeliverNext(ctx, verificationSenderFunc(func(_ context.Context, to protocol.Email, c auth.EmailCode, _ time.Time) error {
		calls++
		if to.String() != "new@example.test" {
			t.Fatal("wrong email destination")
		}
		code, _ = c.DeliveryValue()
		return nil
	})); err != nil || !handled {
		t.Fatal("queued message not delivered to fake sender")
	}
	if calls != 1 || len(code) != 8 {
		t.Fatal("unexpected email issuance")
	}
	if w := request("POST", path+"/resend", struct{}{}, grant.Token); w.Code != 429 {
		t.Fatal("HTTP resend cooldown not enforced")
	}
	for i := 0; i < 2; i++ {
		if w := request("POST", path+"/verify", map[string]string{"code": code}, grant.Token); w.Code != 204 {
			t.Fatal("HTTP verification or lost-response retry failed")
		}
	}
	w = request("GET", path, nil, grant.Token)
	var state struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil || state.Status != "verified" {
		t.Fatal("verified state missing")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing response protections")
	}
	if w := request("POST", path+"/resend", struct{}{}, grant.Token); w.Code != 409 {
		t.Fatal("verified token could resend")
	}
	exerciseAuthenticationHTTP(t, api, grant.Account, grant.Vault, wireSecret)
	exerciseAdminPanelHTTP(t, api, store, queue, raw, material)
}

func TestRegistrationHTTPRejectsAmbiguousRequests(t *testing.T) {
	store, err := storage.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	queue, _ := storage.NewEmailQueue(store, protocol.NewSecret(), protocol.NewSecret(), protocol.NewSecret())
	registrations, _ := storage.NewRegistrations(store, queue, auth.NewEngine())
	api, _ := New(store.Instance().ServerID, store.Ping, registrations)
	for _, test := range []struct {
		method, path, body, media string
		want                      int
	}{
		{"POST", "/api/v1/registrations", `{"email":"a@example.test","email":"b@example.test"}`, "application/json", 400},
		{"POST", "/api/v1/registrations", `{"unknown":true}`, "application/json", 400},
		{"POST", "/api/v1/registrations", `{}`, "text/plain", 415},
		{"POST", "/api/v1/registrations?token=ignored", `{}`, "application/json", 400},
		{"GET", "/api/v1/registrations", "", "", 405},
		{"POST", "/api/v1/registrations/", "{}", "application/json", 404},
	} {
		r := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
		r.Header.Set("Content-Type", test.media)
		r.RemoteAddr = "192.0.2.2:1234"
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Code != test.want {
			t.Fatalf("unexpected status for %s", test.path)
		}
	}
}
