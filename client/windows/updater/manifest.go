package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxBytes = 128 * 1024 * 1024
const maxExpanded = 512 * 1024 * 1024

var errUpdate = errors.New("update verification failed")

type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema   int         `json:"schema"`
	Version  string      `json:"version"`
	Build    int         `json:"build"`
	Platform string      `json:"platform"`
	URL      string      `json:"url"`
	SHA256   string      `json:"sha256"`
	Size     int64       `json:"size"`
	Expires  string      `json:"expires"`
	Files    []FileEntry `json:"files"`
}
type Envelope struct {
	Schema    int    `json:"schema"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var versionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$`)

func decode(data []byte, value any) error {
	scanner := json.NewDecoder(bytes.NewReader(data))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 16 {
			return errUpdate
		}
		token, e := scanner.Token()
		if e != nil {
			return errUpdate
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				keys := map[string]bool{}
				for scanner.More() {
					raw, e := scanner.Token()
					key, ok := raw.(string)
					if e != nil || !ok || keys[key] {
						return errUpdate
					}
					keys[key] = true
					if scan(depth+1) != nil {
						return errUpdate
					}
				}
				end, e := scanner.Token()
				if e != nil || end != json.Delim('}') {
					return errUpdate
				}
			case '[':
				for scanner.More() {
					if scan(depth+1) != nil {
						return errUpdate
					}
				}
				end, e := scanner.Token()
				if e != nil || end != json.Delim(']') {
					return errUpdate
				}
			default:
				return errUpdate
			}
		}
		return nil
	}
	if scan(0) != nil {
		return errUpdate
	}
	if _, e := scanner.Token(); e != io.EOF {
		return errUpdate
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errUpdate
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errUpdate
	}
	return nil
}
func safePath(name string) bool {
	if len(name) == 0 || len(name) > 1024 || strings.ContainsAny(name, "\\:\x00") || strings.HasPrefix(name, "/") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		for _, c := range part {
			if c < 32 || strings.ContainsRune(`<>"|?*`, c) {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || regexp.MustCompile(`^(COM|LPT)[0-9]$`).MatchString(base) {
			return false
		}
	}
	return true
}
func verifyManifest(data []byte, key []byte, current int, now time.Time) (Manifest, error) {
	var result Manifest
	if len(data) > 2*1024*1024 || len(key) != ed25519.PublicKeySize {
		return result, errUpdate
	}
	var envelope Envelope
	if decode(data, &envelope) != nil || envelope.Schema != 1 {
		return result, errUpdate
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if e != nil {
		return result, errUpdate
	}
	signature, e := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if e != nil || !ed25519.Verify(key, payload, signature) || decode(payload, &result) != nil {
		return Manifest{}, errUpdate
	}
	expires, e := time.Parse(time.RFC3339, result.Expires)
	if e != nil || !expires.After(now) || expires.Sub(now) > 370*24*time.Hour || result.Schema != 1 || result.Platform != "windows-x64" || !versionPattern.MatchString(result.Version) || result.Build <= current || result.Size < 1 || result.Size > maxBytes || !hashPattern.MatchString(result.SHA256) || len(result.Files) < 3 || len(result.Files) > 10000 || result.URL != "https://github.com/Samu3k/ByteLocker/releases/download/v"+result.Version+"/ByteLocker-Windows-"+result.Version+".zip" {
		return Manifest{}, errUpdate
	}
	seen := map[string]bool{}
	var total int64
	for _, file := range result.Files {
		key := strings.ToLower(file.Path)
		if !safePath(file.Path) || seen[key] || file.Size < 0 || file.Size > maxBytes || !hashPattern.MatchString(file.SHA256) {
			return Manifest{}, errUpdate
		}
		seen[key] = true
		total += file.Size
		if total > maxExpanded {
			return Manifest{}, errUpdate
		}
	}
	if !seen["bytelocker.exe"] || !seen["bytelockerupdater.exe"] || !seen[".bytelocker-install.json"] {
		return Manifest{}, errUpdate
	}
	return result, nil
}
func hashFile(path string, limit int64) (string, int64, error) {
	file, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer file.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(file, limit+1))
	if e != nil || n > limit {
		return "", 0, errUpdate
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
func extractVerified(archive, destination string, manifest Manifest) error {
	digest, size, e := hashFile(archive, maxBytes)
	if e != nil || digest != manifest.SHA256 || size != manifest.Size {
		return errUpdate
	}
	zipped, e := zip.OpenReader(archive)
	if e != nil {
		return errUpdate
	}
	defer zipped.Close()
	if len(zipped.File) > 20000 {
		return errUpdate
	}
	expected := map[string]FileEntry{}
	for _, entry := range manifest.Files {
		expected[strings.ToLower(entry.Path)] = entry
	}
	seen := map[string]bool{}
	for _, file := range zipped.File {
		name := file.Name
		if file.FileInfo().IsDir() {
			if !safePath(strings.TrimSuffix(name, "/")) {
				return errUpdate
			}
			continue
		}
		entry, ok := expected[strings.ToLower(name)]
		if !ok || entry.Path != name || seen[strings.ToLower(name)] || !safePath(name) || !file.Mode().IsRegular() || file.Mode()&os.ModeSymlink != 0 || file.UncompressedSize64 != uint64(entry.Size) {
			return errUpdate
		}
		seen[strings.ToLower(name)] = true
		target := filepath.Join(destination, filepath.FromSlash(name))
		relative, relError := filepath.Rel(destination, target)
		if relError != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errUpdate
		}
		if e = os.MkdirAll(filepath.Dir(target), 0700); e != nil {
			return e
		}
		reader, e := file.Open()
		if e != nil {
			return errUpdate
		}
		out, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			reader.Close()
			return e
		}
		h := sha256.New()
		written, copyError := io.Copy(io.MultiWriter(out, h), io.LimitReader(reader, entry.Size+1))
		readerError := reader.Close()
		syncError := out.Sync()
		closeError := out.Close()
		if copyError != nil || readerError != nil || syncError != nil || closeError != nil || written != entry.Size || hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
			return errUpdate
		}
	}
	if len(seen) != len(expected) {
		return errUpdate
	}
	return auditInstall(destination)
}

type Inventory struct {
	Schema int      `json:"schema"`
	App    string   `json:"app"`
	Files  []string `json:"files"`
}

func auditInstall(target string) error {
	info, e := os.Lstat(target)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || checkParents(target) != nil {
		return errUpdate
	}
	file, e := os.Open(filepath.Join(target, ".bytelocker-install.json"))
	if e != nil {
		return errUpdate
	}
	data, e := io.ReadAll(io.LimitReader(file, 2*1024*1024+1))
	file.Close()
	if e != nil || len(data) > 2*1024*1024 {
		return errUpdate
	}
	var inventory Inventory
	if decode(data, &inventory) != nil || inventory.Schema != 1 || inventory.App != "ByteLocker" || len(inventory.Files) < 3 || len(inventory.Files) > 10000 {
		return errUpdate
	}
	allowed := map[string]bool{}
	for _, name := range inventory.Files {
		key := strings.ToLower(name)
		if !safePath(name) || allowed[key] {
			return errUpdate
		}
		allowed[key] = true
	}
	if !allowed[".bytelocker-install.json"] || !allowed["bytelocker.exe"] {
		return errUpdate
	}
	return filepath.WalkDir(target, func(path string, entry os.DirEntry, walkError error) error {
		if walkError != nil {
			return errUpdate
		}
		if path == target {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || checkParents(path) != nil {
			return errUpdate
		}
		if entry.IsDir() {
			return nil
		}
		name, e := filepath.Rel(target, path)
		if e != nil || !allowed[strings.ToLower(filepath.ToSlash(name))] {
			return errUpdate
		}
		return nil
	})
}
