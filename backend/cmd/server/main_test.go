package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A synchronized writer lets the smoke test discover ephemeral listener ports
// without reserving and releasing a port before the real server can bind it.
type startupOutput struct {
	sync.Mutex
	data bytes.Buffer
}

func (w *startupOutput) Write(data []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	return w.data.Write(data)
}
func (w *startupOutput) String() string { w.Lock(); defer w.Unlock(); return w.data.String() }

func TestServerLifecycle(t *testing.T) {
	directory := t.TempDir()
	var previousID string
	var previousKeys [32]byte
	for boot := 0; boot < 2; boot++ {
		ctx, cancel := context.WithCancel(context.Background())
		output := &startupOutput{}
		finished := make(chan error, 1)
		lookup := func(string) string { return "" }
		if boot == 1 {
			// The empty queue must not open a real Gmail connection. These are
			// synthetic configuration values, not actual account credentials.
			passwordFile := filepath.Join(directory, "smtp-test-password")
			if err := os.WriteFile(passwordFile, []byte("abcdefghijklmnop"), 0600); err != nil {
				t.Fatal(err)
			}
			lookup = func(name string) string {
				switch name {
				case "PM_SMTP_USERNAME":
					return "test@example.test"
				case "PM_SMTP_APP_PASSWORD_FILE":
					return passwordFile
				}
				return ""
			}
		}
		go func() {
			finished <- runWithEnvironment(ctx, []string{"-data-dir", directory, "-api-address", "127.0.0.1:0", "-health-address", "127.0.0.1:0"}, output, lookup)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(output.String(), "Internal health:") && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !strings.Contains(output.String(), "Internal health:") {
			cancel()
			t.Fatal("server did not start")
		}
		lines := strings.Split(output.String(), "\n")
		apiURL := strings.TrimPrefix(lines[0], "Development server running. API: ")
		healthURL := strings.TrimPrefix(lines[1], "Internal health: ")
		client := &http.Client{Timeout: 2 * time.Second}
		response, err := client.Get(apiURL)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		var body struct {
			ServerID     string `json:"server_id"`
			Registration bool   `json:"registration_available"`
		}
		err = json.NewDecoder(response.Body).Decode(&body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || body.ServerID == "" || body.Registration != (boot == 1) {
			cancel()
			t.Fatal("discovery failed")
		}
		if boot > 0 && body.ServerID != previousID {
			cancel()
			t.Fatal("server restart changed ID")
		}
		previousID = body.ServerID
		keyData, err := os.ReadFile(filepath.Join(directory, "secrets", "instance.keys"))
		if err != nil {
			cancel()
			t.Fatal("operational keys missing")
		}
		fingerprint := sha256.Sum256(keyData)
		clear(keyData)
		if boot > 0 && fingerprint != previousKeys {
			cancel()
			t.Fatal("restart replaced operational keys")
		}
		previousKeys = fingerprint
		response, err = client.Get(healthURL)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 200 {
			cancel()
			t.Fatal("health failed")
		}
		cancel()
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(7 * time.Second):
			t.Fatal("shutdown did not finish")
		}
		if boot == 1 && !strings.Contains(output.String(), "Email dispatcher enabled.") {
			t.Fatal("email worker did not start")
		}
	}
	if err := os.Remove(filepath.Join(directory, "secrets", "instance.keys")); err != nil {
		t.Fatal(err)
	}
	if err := runWithEnvironment(context.Background(), []string{"-data-dir", directory}, io.Discard, func(string) string { return "" }); err == nil {
		t.Fatal("lost keys silently regenerated")
	}
}

func TestInvalidSMTPConfigurationRefusesStartup(t *testing.T) {
	err := runWithEnvironment(context.Background(), []string{"-data-dir", t.TempDir()}, io.Discard, func(name string) string {
		if name == "PM_SMTP_USERNAME" {
			return "test@example.test"
		}
		return ""
	})
	if err == nil || err.Error() != "server: invalid email configuration" {
		t.Fatal("incomplete SMTP configuration accepted or disclosed")
	}
}

func TestServerArguments(t *testing.T) {
	for _, args := range [][]string{{"-unknown"}, {"unexpected"}, {"-health-address", "0.0.0.0:8081"}, {"-api-address", "localhost:8080"}, {"-api-address", "127.0.0.1:99999"}} {
		if err := run(context.Background(), args, io.Discard); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if err := run(context.Background(), []string{"-h"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}
