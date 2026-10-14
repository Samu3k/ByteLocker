package maintenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"passwordmanager/internal/operationalkeys"
	"passwordmanager/internal/protocol"
	"passwordmanager/internal/storage"
)

func fixture(t *testing.T) (string, storage.BackupReport) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	ctx := context.Background()
	s, err := storage.Open(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	id := s.Instance().ServerID
	keys, err := operationalkeys.LoadOrCreate(ctx, data, id, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.BindOperationalKeys(ctx, keys.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	invitation, err := s.CreateBootstrapInvitation(ctx, nil, storage.DefaultInvitationTTL)
	if err != nil {
		t.Fatal(err)
	}
	invitation.Secret.Clear()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// Synthetic encrypted material only: no user password or real vault data.
	db, err := sql.Open("sqlite", filepath.Join(data, "passwordmanager.db"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		`UPDATE instance SET bootstrap_closed=1 WHERE singleton=1`,
		`INSERT INTO accounts(account_id,email,role,vault_id,epoch_id,descriptor,verifier,password_envelope,created_at_ms) VALUES(zeroblob(16),'backup@example.test','admin',randomblob(16),zeroblob(16),zeroblob(30),zeroblob(63),zeroblob(226),1)`,
		`INSERT INTO vault_state(account_id,epoch_id,revision,object_count,stored_bytes) VALUES(zeroblob(16),zeroblob(16),zeroblob(8),1,32)`,
		`INSERT INTO vault_objects(account_id,object_id,revision,sequence,envelope) VALUES(zeroblob(16),randomblob(16),zeroblob(8),zeroblob(8),x'0102030405')`,
	}
	for _, q := range queries {
		if _, err = db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	for name, value := range map[string]string{"compose.yaml": "services: {}\n", ".env": "PM_SMTP_USERNAME=synthetic@example.test\n", "secrets/gmail-app-password": "test-only-secret\n"} {
		path := filepath.Join(root, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(path), 0700)
		if err = os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, storage.BackupReport{ServerID: id, Accounts: 1, Objects: 1}
}

func TestOfflineBackupRestorePreservesIdentityObjectsKeysAndSettings(t *testing.T) {
	root, want := fixture(t)
	ctx := context.Background()
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	m, err := Create(ctx, root, archive)
	if err != nil || m.Report != want {
		t.Fatalf("backup: %v", err)
	}
	if _, err = Verify(ctx, archive); err != nil {
		t.Fatalf("verify: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored")
	if _, err = Restore(ctx, archive, restored); err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, name := range []string{"data/instance.keys", ".env", "secrets/gmail-app-password", "compose.yaml"} {
		a, _ := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		b, err := os.ReadFile(filepath.Join(restored, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("restore changed file", name)
		}
	}
	db, err := sql.Open("sqlite", filepath.Join(restored, "data/passwordmanager.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var envelope []byte
	if err = db.QueryRow("SELECT envelope FROM vault_objects").Scan(&envelope); err != nil || !bytes.Equal(envelope, []byte{1, 2, 3, 4, 5}) {
		t.Fatal("encrypted object lost")
	}
	if _, err = Restore(ctx, archive, restored); err == nil {
		t.Fatal("overwrote existing destination")
	}
	if _, err = Create(ctx, root, archive); err == nil {
		t.Fatal("overwrote existing archive")
	}
}

func repack(t *testing.T, source, target string, mutate func(*tar.Header, []byte) (*tar.Header, []byte)) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	gz, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out, err := os.Create(target)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(out)
	tw := tar.NewWriter(zw)
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		data := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			t.Fatal(err)
		}
		h, data = mutate(h, data)
		if h == nil {
			continue
		}
		h.Size = int64(len(data))
		if err = tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err = tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	zw.Close()
	out.Close()
}
func TestBackupRefusesCorruptionPathsLinksMissingFilesAndWrongKeys(t *testing.T) {
	root, _ := fixture(t)
	ctx := context.Background()
	valid := filepath.Join(t.TempDir(), "valid.tar.gz")
	if _, err := Create(ctx, root, valid); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*tar.Header, []byte) (*tar.Header, []byte){
		"traversal": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == "compose.yaml" {
				h.Name = "../outside"
			}
			return h, b
		},
		"absolute": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == "compose.yaml" {
				h.Name = "/outside"
			}
			return h, b
		},
		"link": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == "compose.yaml" {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "/etc/passwd"
				b = nil
			}
			return h, b
		},
		"unknown": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == "compose.yaml" {
				h.Name = "server.exe"
			}
			return h, b
		},
		"missing-key": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == "data/instance.keys" {
				return nil, nil
			}
			return h, b
		},
		"hash": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == ".env" {
				b[0] ^= 1
			}
			return h, b
		},
		"instance": func(h *tar.Header, b []byte) (*tar.Header, []byte) {
			if h.Name == manifestName {
				var m Manifest
				json.Unmarshal(b, &m)
				m.Report.ServerID = protocol.ID{99}
				b, _ = json.Marshal(m)
			}
			return h, b
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := filepath.Join(t.TempDir(), "bad.tar.gz")
			repack(t, valid, bad, mutate)
			destination := filepath.Join(t.TempDir(), "new")
			if _, err := Restore(ctx, bad, destination); err == nil {
				t.Fatal("bad archive accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatal("failed restore left files")
			}
		})
	}
	raw, _ := os.ReadFile(valid)
	for _, data := range [][]byte{raw[:len(raw)-4], append(append([]byte{}, raw...), raw...)} {
		bad := filepath.Join(t.TempDir(), "bad.tar.gz")
		os.WriteFile(bad, data, 0600)
		if _, err := Verify(ctx, bad); err == nil {
			t.Fatal("truncated/concatenated gzip accepted")
		}
	}
	os.Remove(filepath.Join(root, "data/instance.keys"))
	if _, err := Create(ctx, root, filepath.Join(t.TempDir(), "missing.tar.gz")); err == nil {
		t.Fatal("missing keys accepted")
	}
}

func TestBackupKeepsWALAndRejectsSourceSymlinks(t *testing.T) {
	root, want := fixture(t)
	ctx := context.Background()
	data := filepath.Join(root, "data")
	s, err := storage.Open(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// A committed change in WAL must survive a paused snapshot even if another
	// connection remains open. Production wrapper stops all application writers.
	email, _ := protocol.ParseEmail("wal@example.test")
	grant, err := s.CreateUserInvitation(ctx, email, storage.DefaultInvitationTTL)
	if err != nil {
		t.Fatal(err)
	}
	defer grant.Secret.Clear()
	wal, err := os.Stat(filepath.Join(data, "passwordmanager.db-wal"))
	if err != nil || wal.Size() == 0 {
		t.Fatal("WAL fixture missing")
	}
	archive := filepath.Join(t.TempDir(), "wal.tar.gz")
	m, err := Create(ctx, root, archive)
	if err != nil || m.Report != want {
		t.Fatalf("WAL snapshot: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restore")
	if _, err = Restore(ctx, archive, restored); err != nil {
		t.Fatal(err)
	}
	copyStore, err := storage.Open(ctx, filepath.Join(restored, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer copyStore.Close()
	list, _, err := copyStore.ListInvitations(ctx, protocol.ID{}, 50)
	if err != nil {
		t.Fatal(err)
	}
	matched := false
	for _, invite := range list {
		if invite.ID == grant.Invitation.ID {
			matched = true
		}
	}
	if !matched {
		t.Fatal("WAL commit lost")
	}
	link := filepath.Join(root, "secrets/gmail-app-password")
	os.Remove(link)
	if err = os.Symlink(filepath.Join(root, ".env"), link); err != nil {
		t.Log("OS disallows symlink fixture")
		return
	}
	if _, err = Create(ctx, root, filepath.Join(t.TempDir(), "link.tar.gz")); err == nil {
		t.Fatal("source symlink accepted")
	}
}
