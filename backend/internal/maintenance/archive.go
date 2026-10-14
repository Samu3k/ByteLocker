// Package maintenance implements offline, private server backups. It never
// decrypts user vaults and never overwrites an existing restore directory.
package maintenance

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"passwordmanager/internal/storage"
)

var ErrBackup = errors.New("maintenance: backup invalid or unavailable")

const manifestName = "manifest.json"
const maxBytes int64 = 2 << 30
const maxSmallFile int64 = 1 << 20

var selected = []string{"data/passwordmanager.db", "data/passwordmanager.db-wal", "data/instance.keys", ".env", "secrets/gmail-app-password", "compose.yaml", "compose.gmail.yaml", "compose.quick-tunnel.yaml", "compose.casaos-panel.yaml"}

type fileRecord struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Format    int                  `json:"format"`
	CreatedAt string               `json:"created_at"`
	Report    storage.BackupReport `json:"instance"`
	Files     []fileRecord         `json:"files"`
}

func allowed(name string) bool {
	for _, s := range selected {
		if name == s {
			return true
		}
	}
	return false
}
func required(name string) bool {
	return name == "data/passwordmanager.db" || name == "data/instance.keys" || name == "compose.yaml"
}
func regular(root, name string) (os.FileInfo, error) {
	current := root
	for _, part := range strings.Split(name, "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrBackup
		}
	}
	info, err := os.Lstat(current)
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrBackup
	}
	return info, nil
}
func dir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrBackup
	}
	return nil
}
func copyFile(root, stage, name string) (fileRecord, error) {
	var record fileRecord
	before, err := regular(root, name)
	if err != nil {
		return record, err
	}
	if before.Size() < 0 || before.Size() > maxBytes || (!strings.HasPrefix(filepath.Base(name), "passwordmanager.db") && before.Size() > maxSmallFile) {
		return record, ErrBackup
	}
	source, err := os.Open(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		return record, err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return record, ErrBackup
	}
	destination := filepath.Join(stage, filepath.FromSlash(name))
	if err = os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return record, err
	}
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return record, err
	}
	defer target.Close()
	digest := sha256.New()
	size, err := io.Copy(io.MultiWriter(target, digest), io.LimitReader(source, before.Size()+1))
	if err != nil || size != before.Size() {
		return record, ErrBackup
	}
	after, err := source.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return record, ErrBackup
	}
	if err = target.Sync(); err != nil {
		return record, err
	}
	return fileRecord{Name: name, Size: size, SHA256: hex.EncodeToString(digest.Sum(nil))}, nil
}

// Create requires the application and all admin commands to be stopped.
func Create(ctx context.Context, root, output string) (Manifest, error) {
	return create(ctx, root, output, "")
}

// CreateWithSnapshot archives an already validated online snapshot and private
// host configuration. Snapshot is produced by the isolated service-UID helper.
func CreateWithSnapshot(ctx context.Context, root, output, snapshot string) (Manifest, error) {
	if snapshot == "" || dir(snapshot) != nil {
		return Manifest{}, ErrBackup
	}
	return create(ctx, root, output, snapshot)
}

func create(ctx context.Context, root, output, snapshot string) (Manifest, error) {
	var m Manifest
	if dir(root) != nil || dir(filepath.Dir(output)) != nil {
		return m, ErrBackup
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return m, ErrBackup
	}
	stage, err := os.MkdirTemp(filepath.Dir(output), ".bytelocker-backup-")
	if err != nil {
		return m, err
	}
	defer os.RemoveAll(stage)
	m.Format = 1
	m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	var total int64
	for _, name := range selected {
		var record fileRecord
		var err error
		if snapshot != "" && strings.HasPrefix(name, "data/") {
			if name == "data/passwordmanager.db-wal" {
				continue
			}
			record, err = copyFile(snapshot, filepath.Join(stage, "data"), strings.TrimPrefix(name, "data/"))
			record.Name = name
		} else {
			record, err = copyFile(root, stage, name)
		}
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && !required(name) {
				continue
			}
			return Manifest{}, ErrBackup
		}
		total += record.Size
		if total > maxBytes {
			return Manifest{}, ErrBackup
		}
		m.Files = append(m.Files, record)
	}
	report, err := storage.CheckBackup(ctx, filepath.Join(stage, "data"))
	if err != nil {
		return Manifest{}, err
	}
	m.Report = report
	manifest, err := json.Marshal(m)
	if err != nil {
		return Manifest{}, err
	}
	// Opening an offline WAL copy may create SHM. Only whitelisted snapshot files
	// enter the archive; the transient SHM is never part of the restore contract.
	packed := filepath.Join(stage, "archive.tmp")
	f, err := os.OpenFile(packed, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return Manifest{}, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, record := range m.Files {
		if err = tw.WriteHeader(&tar.Header{Name: record.Name, Mode: 0600, Size: record.Size, Typeflag: tar.TypeReg}); err != nil {
			return Manifest{}, err
		}
		input, err := os.Open(filepath.Join(stage, filepath.FromSlash(record.Name)))
		if err != nil {
			return Manifest{}, err
		}
		_, err = io.Copy(tw, input)
		input.Close()
		if err != nil {
			return Manifest{}, err
		}
	}
	if err = tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0600, Size: int64(len(manifest)), Typeflag: tar.TypeReg}); err != nil {
		return Manifest{}, err
	}
	if _, err = tw.Write(manifest); err != nil {
		return Manifest{}, err
	}
	if err = tw.Close(); err != nil {
		return Manifest{}, err
	}
	if err = gz.Close(); err != nil {
		return Manifest{}, err
	}
	if err = f.Sync(); err != nil {
		return Manifest{}, err
	}
	if err = f.Close(); err != nil {
		return Manifest{}, err
	}
	// Hard-link publication refuses to replace files, even after a race.
	if err = os.Link(packed, output); err != nil {
		return Manifest{}, err
	}
	if runtime.GOOS != "windows" {
		parent, err := os.Open(filepath.Dir(output))
		if err != nil {
			return Manifest{}, err
		}
		err = parent.Sync()
		parent.Close()
		if err != nil {
			return Manifest{}, err
		}
	}
	return m, nil
}

// Snapshot is executed inside an isolated container as UID 10001. No host
// secrets, Docker socket, SMTP configuration or network are exposed to it.
func Snapshot(ctx context.Context, data, destination string) (storage.BackupReport, error) {
	var report storage.BackupReport
	if dir(data) != nil || dir(filepath.Dir(destination)) != nil {
		return report, ErrBackup
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return report, ErrBackup
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(destination)
		}
	}()
	if err := storage.SnapshotDatabase(ctx, data, filepath.Join(destination, "passwordmanager.db")); err != nil {
		return report, err
	}
	if _, err := copyFile(data, destination, "instance.keys"); err != nil {
		return report, err
	}
	report, err := storage.CheckBackup(ctx, destination)
	if err != nil {
		return report, err
	}
	ok = true
	return report, nil
}

// Restore always creates a new directory, with private files, and removes only
// that owned directory on failure. Untrusted paths and archive links are refused.
func Restore(ctx context.Context, archive, destination string) (m Manifest, result error) {
	if dir(filepath.Dir(destination)) != nil {
		return m, ErrBackup
	}
	if err := os.Mkdir(destination, 0700); err != nil {
		return m, ErrBackup
	}
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(destination)
		}
	}()
	info, err := os.Lstat(archive)
	if err != nil || !info.Mode().IsRegular() {
		return m, ErrBackup
	}
	f, err := os.Open(archive)
	if err != nil {
		return m, ErrBackup
	}
	defer f.Close()
	buffered := bufio.NewReader(f)
	gz, err := gzip.NewReader(buffered)
	if err != nil {
		return m, ErrBackup
	}
	defer gz.Close()
	gz.Multistream(false)
	limited := &io.LimitedReader{R: gz, N: maxBytes + 4*maxSmallFile}
	tr := tar.NewReader(limited)
	found := map[string]fileRecord{}
	var manifest []byte
	var total int64
	for {
		if ctx.Err() != nil {
			return m, ctx.Err()
		}
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, ErrBackup
		}
		name := header.Name
		if header.Typeflag != tar.TypeReg || header.Linkname != "" || len(header.PAXRecords) > 0 || header.Size < 0 {
			return m, ErrBackup
		}
		if name == manifestName {
			if manifest != nil || header.Size > maxSmallFile {
				return m, ErrBackup
			}
			manifest, err = io.ReadAll(tr)
			if err != nil {
				return m, ErrBackup
			}
			continue
		}
		if !allowed(name) || found[name].Name != "" || header.Size > maxBytes || (!strings.HasPrefix(name, "data/passwordmanager.db") && header.Size > maxSmallFile) {
			return m, ErrBackup
		}
		total += header.Size
		if total > maxBytes {
			return m, ErrBackup
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return m, err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return m, err
		}
		hash := sha256.New()
		size, copyErr := io.Copy(io.MultiWriter(out, hash), tr)
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || size != header.Size {
			return m, ErrBackup
		}
		found[name] = fileRecord{Name: name, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil))}
	}
	// Drain to authenticate the gzip CRC/trailer, reject concatenated data, and
	// accept only the zero padding permitted after a tar end marker.
	tail, err := io.ReadAll(io.LimitReader(limited, 8193))
	if err != nil || len(tail) > 8192 || limited.N <= 0 {
		return m, ErrBackup
	}
	for _, b := range tail {
		if b != 0 {
			return m, ErrBackup
		}
	}
	extra := make([]byte, 1)
	if n, _ := gz.Read(extra); n != 0 {
		return m, ErrBackup
	}
	if _, err = buffered.Peek(1); err != io.EOF {
		return m, ErrBackup
	}
	decoder := json.NewDecoder(strings.NewReader(string(manifest)))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&m) != nil || decoder.Decode(new(any)) != io.EOF || m.Format != 1 || len(m.Files) != len(found) {
		return m, ErrBackup
	}
	if _, err = time.Parse(time.RFC3339, m.CreatedAt); err != nil {
		return m, ErrBackup
	}
	seen := map[string]bool{}
	for _, record := range m.Files {
		if seen[record.Name] || found[record.Name] != record {
			return m, ErrBackup
		}
		seen[record.Name] = true
	}
	for _, name := range selected {
		if required(name) && !seen[name] {
			return m, ErrBackup
		}
	}
	report, err := storage.CheckBackup(ctx, filepath.Join(destination, "data"))
	if err != nil || report != m.Report {
		return m, ErrBackup
	}
	ok = true
	return m, nil
}

func Verify(ctx context.Context, archive string) (Manifest, error) {
	parent, err := os.MkdirTemp("", "bytelocker-verify-")
	if err != nil {
		return Manifest{}, err
	}
	defer os.RemoveAll(parent)
	return Restore(ctx, archive, filepath.Join(parent, "restore"))
}
