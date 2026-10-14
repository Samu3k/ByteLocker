package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"passwordmanager/internal/protocol"
)

func exerciseVaultHTTP(t *testing.T, api *Server, token string, account, vault protocol.ID) {
	t.Helper()
	epoch, id := protocol.ID{2}, protocol.ID{31}
	envelope := func(generation uint64) string {
		raw := make([]byte, 196)
		copy(raw, "PME1")
		raw[4] = 3
		binary.BigEndian.PutUint16(raw[6:8], 1)
		copy(raw[8:24], api.serverID[:])
		copy(raw[24:40], account[:])
		copy(raw[40:56], vault[:])
		copy(raw[56:72], epoch[:])
		copy(raw[72:88], id[:])
		binary.BigEndian.PutUint64(raw[88:96], generation)
		binary.BigEndian.PutUint32(raw[96:100], 32)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	request := func(method, path string, body []byte, headers map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.RemoteAddr = "192.0.2.3:4321"
		r.Header.Set("Authorization", "Bearer "+token)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			r.Header.Set(key, value)
		}
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable vault response")
		}
		return w
	}
	basePath := "/api/v1/vault/objects"
	path := basePath + "/" + id.String()
	w := request("GET", "/api/v1/vault/state", nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"collection_revision":"0"`) {
		t.Fatal("empty vault state unavailable")
	}
	create, _ := json.Marshal(map[string]any{"epoch_id": epoch, "object_id": id, "envelope": envelope(1)})
	key := protocol.ID{41}.String()
	headers := map[string]string{"Idempotency-Key": key}
	w = request("POST", basePath, create, headers)
	if w.Code != 201 {
		t.Fatalf("HTTP object creation failed: %d", w.Code)
	}
	response, etag := w.Body.String(), w.Header().Get("ETag")
	if strings.Contains(response, "envelope") || etag == "" {
		t.Fatal("write confirmation exposed blob or omitted ETag")
	}
	retry := request("POST", basePath, create, headers)
	if retry.Code != 201 || retry.Body.String() != response || retry.Header().Get("ETag") != etag {
		t.Fatal("identical HTTP retry changed response")
	}
	retry = request("POST", basePath, append([]byte(" "), create...), headers)
	if retry.Code != 409 || !strings.Contains(retry.Body.String(), "idempotency_conflict") {
		t.Fatal("different original body not rejected")
	}
	read := request("GET", path, nil, nil)
	var object struct {
		Envelope string `json:"envelope"`
	}
	if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &object) != nil || object.Envelope != envelope(1) {
		t.Fatal("HTTP read changed ciphertext")
	}
	update, _ := json.Marshal(map[string]any{"epoch_id": epoch, "envelope": envelope(2)})
	if request("PUT", path, update, map[string]string{"Idempotency-Key": protocol.ID{42}.String()}).Code != 428 {
		t.Fatal("missing If-Match accepted")
	}
	w = request("PUT", path, update, map[string]string{"Idempotency-Key": protocol.ID{42}.String(), "If-Match": etag})
	if w.Code != 200 || w.Header().Get("ETag") == etag {
		t.Fatal("HTTP revision update failed")
	}
	if request("PUT", path, update, map[string]string{"Idempotency-Key": protocol.ID{43}.String(), "If-Match": etag}).Code != 412 {
		t.Fatal("stale update accepted")
	}
	if retry = request("POST", basePath, create, headers); retry.Code != 201 || retry.Body.String() != response {
		t.Fatal("historical HTTP replay changed")
	}
	syncPath := "/api/v1/vault/sync?epoch_id=" + epoch.String() + "&since=0&ceiling=2&after_sequence=0&limit=1"
	w = request("GET", syncPath, nil, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"revision":"2"`) || !strings.Contains(w.Body.String(), `"next_after_sequence":null`) {
		t.Fatal("HTTP sync invalid")
	}
	if request("GET", strings.Replace(syncPath, "ceiling=2", "ceiling=1", 1), nil, nil).Code != 409 {
		t.Fatal("stale snapshot accepted")
	}
	for _, tc := range []struct {
		method, path string
		body         []byte
		headers      map[string]string
		want         int
	}{
		{"DELETE", path, nil, nil, 405},
		{"GET", path + "?token=ignored", nil, nil, 400},
		{"GET", syncPath + "&since=0", nil, nil, 400},
		{"GET", strings.Replace(syncPath, "limit=1", "limit=01", 1), nil, nil, 400},
		{"GET", syncPath + "&unknown=1", nil, nil, 400},
		{"GET", "/api/v1/vault/state", []byte("{}"), nil, 400},
		{"POST", basePath, []byte("{}"), nil, 400},
		{"POST", basePath, []byte(`{"epoch_id":"invalid","epoch_id":"invalid"}`), map[string]string{"Idempotency-Key": protocol.ID{50}.String()}, 400},
		{"GET", path, nil, map[string]string{"Authorization": "Registration " + token}, 401},
		{"GET", basePath + "/" + protocol.ID{99}.String(), nil, nil, 404},
	} {
		w := request(tc.method, tc.path, tc.body, tc.headers)
		if w.Code != tc.want {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
	// Duplicate credentials and preconditions must fail even if values match.
	for _, name := range []string{"Authorization", "Idempotency-Key", "If-Match"} {
		r := httptest.NewRequest("PUT", path, bytes.NewReader(update))
		r.RemoteAddr = "192.0.2.3:4321"
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", protocol.ID{51}.String())
		r.Header.Set("If-Match", etag)
		r.Header.Add(name, r.Header.Get(name))
		w := httptest.NewRecorder()
		api.PublicHandler().ServeHTTP(w, r)
		want := 400
		if name == "Authorization" {
			want = 401
		}
		if w.Code != want {
			t.Fatal("duplicate security header accepted")
		}
	}
}
func TestVaultSyncQueryValidation(t *testing.T) {
	epoch := protocol.ID{1}.String()
	valid := "epoch_id=" + epoch + "&since=0&ceiling=3&after_sequence=1"
	if q, err := parseVaultSync(valid); err != nil || q.Limit != 50 || q.After != 1 {
		t.Fatal("valid query rejected")
	}
	for _, query := range []string{"", valid + "&limit=0", valid + "&limit=101", valid + "&limit=", valid + "&ceiling=3", valid + "&x=1", strings.Replace(valid, "since=0", "since=2", 1), strings.Replace(valid, "after_sequence=1", "after_sequence=4", 1), valid + "&limit=+1", valid + "&limit=1;"} {
		if _, err := parseVaultSync(query); err == nil {
			t.Fatal("malformed sync query accepted")
		}
	}
}
