// Package operationalkeys persists instance secrets outside SQLite. These are
// server operational keys, never user Master Passwords or vault keys.
package operationalkeys

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"passwordmanager/internal/protocol"
)

var ErrUnavailable = errors.New("operationalkeys: protected instance keys unavailable")

const fileSize = 8 + 16 + 4*32 + 32
const filename = "instance.keys"

var magic = []byte("PMKEYS1\x00")

type Keys struct {
	values      [4]protocol.Secret
	fingerprint [32]byte
}

func (k Keys) EmailMAC() protocol.Secret        { return k.values[0] }
func (k Keys) EmailEncryption() protocol.Secret { return k.values[1] }
func (k Keys) EmailQuota() protocol.Secret      { return k.values[2] }
func (k Keys) Prelogin() protocol.Secret        { return k.values[3] }
func (k Keys) Fingerprint() [32]byte            { return k.fingerprint }

// LoadOrCreate never replaces an existing file. Creation is allowed only before
// the database has a key binding. Publication uses an atomic, no-overwrite hard
// link on a local filesystem (a no-replace move on Windows). A crash after
// publication but before DB binding is recoverable by loading the same file.
// Windows deployments must protect directory and file with service-account ACLs;
// mode bits cannot establish Windows ACL isolation.
func LoadOrCreate(ctx context.Context, directory string, serverID protocol.ID, allowCreate bool) (Keys, error) {
	var empty Keys
	if directory == "" || serverID.IsZero() || ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return empty, ErrUnavailable
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !privateMode(info) {
		return empty, ErrUnavailable
	}
	path := filepath.Join(directory, filename)
	if _, err := os.Lstat(path); err == nil {
		return read(path, serverID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return empty, ErrUnavailable
	}
	if !allowCreate {
		return empty, ErrUnavailable
	}
	data := make([]byte, fileSize)
	defer clear(data)
	copy(data, magic)
	copy(data[8:], serverID[:])
	for i := 0; i < 4; i++ {
		secret := protocol.NewSecret()
		raw, _ := secret.Bytes()
		copy(data[24+i*32:], raw[:])
		clear(raw[:])
		secret.Clear()
	}
	checksum := sha256.Sum256(data[:fileSize-32])
	copy(data[fileSize-32:], checksum[:])
	file, err := os.CreateTemp(directory, ".instance-*.tmp")
	if err != nil {
		return empty, ErrUnavailable
	}
	stage := file.Name()
	defer os.Remove(stage)
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return empty, ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		return empty, ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return empty, ErrUnavailable
	}
	if ctx.Err() != nil {
		return empty, ErrUnavailable
	}
	if err := publish(stage, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return empty, ErrUnavailable
		}
	}
	return read(path, serverID)
}

func privateMode(info os.FileInfo) bool {
	return runtime.GOOS == "windows" || info.Mode().Perm()&0077 == 0
}

func read(path string, serverID protocol.ID) (Keys, error) {
	var empty Keys
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !privateMode(before) {
		return empty, ErrUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return empty, ErrUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Size() != fileSize || !privateMode(info) {
		return empty, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(file, fileSize+1))
	defer clear(data)
	if err != nil || len(data) != fileSize || !bytes.Equal(data[:8], magic) || !bytes.Equal(data[8:24], serverID[:]) {
		return empty, ErrUnavailable
	}
	digest := sha256.Sum256(data[:fileSize-32])
	if !bytes.Equal(digest[:], data[fileSize-32:]) {
		return empty, ErrUnavailable
	}
	var result Keys
	for i := range result.values {
		raw := data[24+i*32 : 24+(i+1)*32]
		if bytes.Equal(raw, make([]byte, 32)) {
			return empty, ErrUnavailable
		}
		secret, err := protocol.ParseSecret(base64.RawURLEncoding.EncodeToString(raw))
		if err != nil {
			return empty, ErrUnavailable
		}
		for j := 0; j < i; j++ {
			if result.values[j].Equal(secret) {
				return empty, ErrUnavailable
			}
		}
		result.values[i] = secret
	}
	result.fingerprint = sha256.Sum256(data)
	if runtime.GOOS != "windows" {
		// Also sync when another concurrent process published the file. The
		// database must not bind keys before their directory entry is durable.
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return empty, ErrUnavailable
		}
		err = dir.Sync()
		_ = dir.Close()
		if err != nil {
			return empty, ErrUnavailable
		}
	}
	return result, nil
}

func (k Keys) Format(state fmt.State, verb rune) { _, _ = io.WriteString(state, "[REDACTED]") }
func (k Keys) LogValue() slog.Value              { return slog.StringValue("[REDACTED]") }
func (k Keys) MarshalJSON() ([]byte, error)      { return []byte(`"[REDACTED]"`), nil }
