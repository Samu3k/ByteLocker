package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (map[string][]byte, Manifest, []byte, ed25519.PublicKey) {
	t.Helper()
	files := map[string][]byte{"ByteLocker.exe": []byte("synthetic executable"), "ByteLockerUpdater.exe": []byte("synthetic helper"), ".bytelocker-install.json": nil}
	// On Windows use valid PE bytes: writing invalid .exe files can cause
	// endpoint security to quarantine/hold the fixture before filesystem tests.
	if runtime.GOOS == "windows" {
		executable, e := os.Executable()
		if e != nil {
			t.Fatal(e)
		}
		data, e := os.ReadFile(executable)
		if e != nil {
			t.Fatal(e)
		}
		files["ByteLocker.exe"] = data
		files["ByteLockerUpdater.exe"] = data
	}
	inventory := Inventory{Schema: 1, App: "ByteLocker"}
	for name := range files {
		inventory.Files = append(inventory.Files, name)
	}
	files[".bytelocker-install.json"], _ = json.Marshal(inventory)
	var zipped bytes.Buffer
	writer := zip.NewWriter(&zipped)
	manifest := Manifest{Schema: 1, Version: "0.4.1", Build: 10, Platform: "windows-x64", Expires: time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339), URL: "https://github.com/Samu3k/ByteLocker/releases/download/v0.4.1/ByteLocker-Windows-0.4.1.zip"}
	for name, data := range files {
		out, _ := writer.Create(name)
		out.Write(data)
		h := sha256.Sum256(data)
		manifest.Files = append(manifest.Files, FileEntry{name, int64(len(data)), hex.EncodeToString(h[:])})
	}
	writer.Close()
	digest := sha256.Sum256(zipped.Bytes())
	manifest.SHA256 = hex.EncodeToString(digest[:])
	manifest.Size = int64(zipped.Len())
	pub, private, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := json.Marshal(manifest)
	envelope, _ := json.Marshal(Envelope{1, base64.StdEncoding.EncodeToString(payload), base64.StdEncoding.EncodeToString(ed25519.Sign(private, payload))})
	return files, manifest, envelope, pub
}
func TestSignatureExpiryAndRollbackProtection(t *testing.T) {
	_, _, data, key := fixture(t)
	if _, e := verifyManifest(data, key, 9, time.Now()); e != nil {
		t.Fatal(e)
	}
	var envelope Envelope
	json.Unmarshal(data, &envelope)
	payload, _ := base64.StdEncoding.DecodeString(envelope.Payload)
	payload[10] ^= 1
	envelope.Payload = base64.StdEncoding.EncodeToString(payload)
	tampered, _ := json.Marshal(envelope)
	if _, e := verifyManifest(tampered, key, 9, time.Now()); e == nil {
		t.Fatal("tampered signature accepted")
	}
	if _, e := verifyManifest(data, key, 10, time.Now()); e == nil {
		t.Fatal("same/older build accepted")
	}
	if _, e := verifyManifest(data, key, 9, time.Now().Add(48*time.Hour)); e == nil {
		t.Fatal("expired manifest accepted")
	}
}
func TestUnsafeWindowsPaths(t *testing.T) {
	for _, name := range []string{"../escape", "/root", "C:/file", "data\\escape", "data/../escape", "data/file:stream", "CON.txt", "data/LPT1", "data/end.", "data/end ", "data//file"} {
		if safePath(name) {
			t.Fatalf("unsafe path accepted: %s", name)
		}
	}
}
func TestExtractionHashAndUnexpectedFile(t *testing.T) {
	files, manifest, _, _ := fixture(t)
	directory := t.TempDir()
	archive := filepath.Join(directory, "package.zip")
	write := func(extra bool) {
		var b bytes.Buffer
		writer := zip.NewWriter(&b)
		for name, data := range files {
			out, _ := writer.Create(name)
			out.Write(data)
		}
		if extra {
			out, _ := writer.Create("../escape")
			out.Write([]byte("unexpected"))
		}
		writer.Close()
		os.WriteFile(archive, b.Bytes(), 0600)
		hash := sha256.Sum256(b.Bytes())
		manifest.Size = int64(b.Len())
		manifest.SHA256 = hex.EncodeToString(hash[:])
	}
	write(false)
	destination := filepath.Join(directory, "new")
	os.Mkdir(destination, 0700)
	if e := extractVerified(archive, destination, manifest); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(destination, "personal.csv"), []byte("synthetic user file"), 0600)
	if auditInstall(destination) == nil {
		t.Fatal("unmanaged user file accepted")
	}
	write(true)
	other := filepath.Join(directory, "other")
	os.Mkdir(other, 0700)
	if extractVerified(archive, other, manifest) == nil {
		t.Fatal("unexpected archive path accepted")
	}
	if _, e := os.Stat(filepath.Join(directory, "escape")); !os.IsNotExist(e) {
		t.Fatal("archive escaped staging")
	}
}
func TestRollbackPreservesOriginalFolder(t *testing.T) {
	files, _, _, _ := fixture(t)
	parent := t.TempDir()
	if runtime.GOOS == "windows" {
		var e error
		parent, e = os.MkdirTemp("", "bytelocker-updater-test-")
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if filepath.Dir(parent) == os.TempDir() && strings.HasPrefix(filepath.Base(parent), "bytelocker-updater-test-") {
				_ = os.RemoveAll(parent)
			}
		})
	}
	old := filepath.Join(parent, "app")
	fresh := filepath.Join(parent, "new")
	os.Mkdir(old, 0700)
	os.Mkdir(fresh, 0700)
	for name, data := range files {
		os.WriteFile(filepath.Join(old, name), data, 0600)
		os.WriteFile(filepath.Join(fresh, name), data, 0600)
	}
	os.WriteFile(filepath.Join(fresh, "ByteLocker.exe"), append(append([]byte{}, files["ByteLocker.exe"]...), []byte("new fixture")...), 0600)
	calls := 0
	_, e := swapInstall(old, fresh, func(string) error {
		calls++
		if calls == 1 {
			return errors.New("synthetic launch failure")
		}
		return nil
	})
	if e == nil || calls != 2 {
		t.Fatalf("failed launch did not restore/restart: calls=%d error=%v", calls, e)
	}
	data, _ := os.ReadFile(filepath.Join(old, "ByteLocker.exe"))
	if !bytes.Equal(data, files["ByteLocker.exe"]) {
		t.Fatal("original app lost")
	}
}

func TestProductionPackageWhenProvided(t *testing.T) {
	manifestPath := os.Getenv("BYTELOCKER_TEST_UPDATE_MANIFEST")
	archive := os.Getenv("BYTELOCKER_TEST_UPDATE_ARCHIVE")
	if manifestPath == "" || archive == "" {
		t.Skip("optional real-package verification")
	}
	data, e := os.ReadFile(manifestPath)
	if e != nil {
		t.Fatal("cannot read supplied package metadata")
	}
	key, e := base64.StdEncoding.DecodeString(trustedKey)
	if e != nil {
		t.Fatal("invalid pinned key")
	}
	manifest, e := verifyManifest(data, key, 0, time.Now())
	if e != nil {
		t.Fatal("real metadata does not verify with the pinned key")
	}
	if e = extractVerified(archive, t.TempDir(), manifest); e != nil {
		t.Fatal("real package hash, contents or inventory did not verify")
	}
}
