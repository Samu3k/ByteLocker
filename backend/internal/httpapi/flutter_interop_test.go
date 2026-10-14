package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"passwordmanager/internal/auth"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

// Opt-in cross-language test. Everything, including the email sender, uses
// a temporary instance. The test-only email route is never mounted in the app.
func TestFlutterClientInterop(t *testing.T) {
	flutter := os.Getenv("BYTELOCKER_FLUTTER_PATH")
	clientDir := os.Getenv("BYTELOCKER_CLIENT_DIR")
	if flutter == "" || clientDir == "" {
		t.Skip("set BYTELOCKER_FLUTTER_PATH and BYTELOCKER_CLIENT_DIR for Flutter interoperability")
	}
	if !filepath.IsAbs(flutter) || !filepath.IsAbs(clientDir) {
		t.Fatal("absolute paths required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	store, err := storage.Open(ctx, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	invite, err := store.CreateBootstrapInvitation(ctx, nil, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer invite.Secret.Clear()
	wire, err := invite.Secret.WireValue()
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
	if err = api.EnableAuthentication(sessions); err != nil {
		t.Fatal(err)
	}
	handler := api.PublicHandler()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/__test__/email-code" {
			handler.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		code := ""
		handled, deliveryErr := queue.DeliverNext(ctx, verificationSenderFunc(func(_ context.Context, _ protocol.Email, c auth.EmailCode, _ time.Time) error {
			code, _ = c.DeliveryValue()
			return nil
		}))
		if deliveryErr != nil || !handled {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"code": code})
	}))
	defer server.Close()
	args := []string{"test", "--no-pub", "test/go_backend_interop_test.dart"}
	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.CommandContext(ctx, "cmd.exe", append([]string{"/c", flutter}, args...)...)
	} else {
		command = exec.CommandContext(ctx, flutter, args...)
	}
	command.Dir = clientDir
	command.Env = append(os.Environ(), "BYTELOCKER_TEST_SERVER="+server.URL, "BYTELOCKER_TEST_INVITE="+wire)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Flutter interoperability failed: %v\n%s", err, output)
	}
	t.Log("Flutter/Go: registration, verification, login, vault writes, conflict, tombstone and logout passed")
}
