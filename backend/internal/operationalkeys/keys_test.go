package operationalkeys

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"passwordmanager/internal/protocol"
)

func TestStablePrivateKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	id := protocol.ID{1}
	first, err := LoadOrCreate(context.Background(), dir, id, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(context.Background(), dir, id, false)
	if err != nil || first.Fingerprint() != second.Fingerprint() {
		t.Fatal("keys changed after reload")
	}
	if !first.EmailMAC().Valid() || !first.EmailEncryption().Valid() || !first.EmailQuota().Valid() || !first.Prelogin().Valid() {
		t.Fatal("missing keys")
	}
	for i := range first.values {
		for j := 0; j < i; j++ {
			if first.values[i].Equal(first.values[j]) {
				t.Fatal("key reuse")
			}
		}
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, first) != "[REDACTED]" {
			t.Fatal("diagnostic key disclosure")
		}
	}
	data, err := json.Marshal(first)
	if err != nil || string(data) != `"[REDACTED]"` {
		t.Fatal("JSON key disclosure")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != filename {
		t.Fatal("temporary secret file retained")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(dir, filename))
		if info.Mode().Perm() != 0600 {
			t.Fatal("key file is not private")
		}
	}
}

func TestConcurrentKeyPublication(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	var keys [8]Keys
	var failures [8]error
	var group sync.WaitGroup
	for i := range keys {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			keys[i], failures[i] = LoadOrCreate(context.Background(), dir, protocol.ID{2}, true)
		}(i)
	}
	group.Wait()
	for i := range keys {
		if failures[i] != nil || keys[i].Fingerprint() != keys[0].Fingerprint() {
			t.Fatal("concurrent start published different keys")
		}
	}
}

func TestKeyLossAndWrongInstanceFailClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	id := protocol.ID{3}
	if _, err := LoadOrCreate(context.Background(), dir, id, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing keys regenerated")
	}
	first, err := LoadOrCreate(context.Background(), dir, id, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(context.Background(), dir, protocol.ID{4}, true); !errors.Is(err, ErrUnavailable) {
		t.Fatal("keys accepted for different instance")
	}
	again, err := LoadOrCreate(context.Background(), dir, id, false)
	if err != nil || again.Fingerprint() != first.Fingerprint() {
		t.Fatal("wrong-instance attempt replaced keys")
	}
	if err := os.Remove(filepath.Join(dir, filename)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(context.Background(), dir, id, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("lost keys recreated")
	}
}

func TestCorruptKeyFilesRejected(t *testing.T) {
	for _, kind := range []string{"truncated", "oversized", "checksum", "duplicate", "zero", "version"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "secrets")
			id := protocol.ID{5}
			if _, err := LoadOrCreate(context.Background(), dir, id, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, filename)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
			switch kind {
			case "truncated":
				data = data[:len(data)-1]
			case "oversized":
				data = append(data, 0)
			case "checksum":
				data[25] ^= 1
			case "version":
				data[6] = '9'
			case "duplicate":
				copy(data[56:88], data[24:56])
			case "zero":
				clear(data[24:56])
			}
			if kind == "duplicate" || kind == "zero" {
				sum := sha256.Sum256(data[:fileSize-32])
				copy(data[fileSize-32:], sum[:])
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(context.Background(), dir, id, true); !errors.Is(err, ErrUnavailable) {
				t.Fatal("corrupt keys accepted or replaced")
			}
		})
	}
}

func TestKeyFileSymlinkRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	id := protocol.ID{6}
	if _, err := LoadOrCreate(context.Background(), dir, id, true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filename)
	target := filepath.Join(dir, "original")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skip("symlink creation requires platform permission")
	}
	if _, err := LoadOrCreate(context.Background(), dir, id, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("symlink accepted")
	}
}
