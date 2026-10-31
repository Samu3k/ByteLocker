package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func swapInstall(target, prepared string, start func(string) error) (string, error) {
	target, e := filepath.Abs(target)
	if e != nil || target == filepath.Dir(target) || auditInstall(target) != nil || auditInstall(prepared) != nil || filepath.Dir(prepared) != filepath.Dir(target) {
		return "", errUpdate
	}
	backup, e := os.MkdirTemp(filepath.Dir(target), "."+filepath.Base(target)+".previous-")
	if e != nil {
		return "", e
	}
	if os.Remove(backup) != nil {
		return "", errUpdate
	}
	if e = os.Rename(target, backup); e != nil {
		return "", e
	}
	restore := func() error {
		if _, e := os.Stat(target); e == nil {
			failed, e := os.MkdirTemp(filepath.Dir(target), "."+filepath.Base(target)+".failed-")
			if e != nil {
				return e
			}
			if e = os.Remove(failed); e != nil {
				return e
			}
			if e = os.Rename(target, failed); e != nil {
				return e
			}
		}
		return os.Rename(backup, target)
	}
	if e = os.Rename(prepared, target); e != nil {
		if restore() != nil {
			return backup, errors.New("rollback required")
		}
		return "", e
	}
	if e = start(filepath.Join(target, "ByteLocker.exe")); e != nil {
		if restore() != nil {
			return backup, errors.New("rollback required")
		}
		_ = start(filepath.Join(target, "ByteLocker.exe"))
		return "", e
	}
	// Keep the prior application folder for recovery. Never remove user profiles,
	// Windows registry settings, vault/server data or unrelated directories.
	return backup, nil
}
func writeStatus(status, version string) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return
	}
	directory := filepath.Join(base, "ByteLocker")
	if os.MkdirAll(directory, 0700) != nil {
		return
	}
	data, _ := json.Marshal(map[string]string{"status": status, "version": version})
	_ = os.WriteFile(filepath.Join(directory, "update-result.json"), data, 0600)
}
func run() error {
	flags := flag.NewFlagSet("ByteLockerUpdater", flag.ContinueOnError)
	targetFlag := flags.String("target", "", "")
	archiveFlag := flags.String("archive", "", "")
	manifestFlag := flags.String("manifest", "", "")
	parent := flags.Int("parent-pid", 0, "")
	current := flags.Int("current-build", 0, "")
	readyFlag := flags.String("ready", "", "")
	nonce := flags.String("nonce", "", "")
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 || *parent < 1 || *current < 1 || len(*nonce) != 32 {
		return errUpdate
	}
	target, e := filepath.Abs(*targetFlag)
	if e != nil || target == filepath.Dir(target) || auditInstall(target) != nil {
		return errUpdate
	}
	archive, e := filepath.Abs(*archiveFlag)
	if e != nil {
		return errUpdate
	}
	manifestPath, e := filepath.Abs(*manifestFlag)
	if e != nil {
		return errUpdate
	}
	ready, e := filepath.Abs(*readyFlag)
	if e != nil {
		return errUpdate
	}
	stage := filepath.Dir(archive)
	if !strings.HasPrefix(filepath.Base(stage), "bytelocker-update-") || filepath.Dir(manifestPath) != stage || filepath.Dir(ready) != stage || checkParents(stage) != nil {
		return errUpdate
	}
	if e = os.Chdir(stage); e != nil {
		return errUpdate
	}
	cancel := filepath.Join(stage, "cancel")
	data, e := os.ReadFile(manifestPath)
	if e != nil {
		return errUpdate
	}
	key, e := base64.StdEncoding.DecodeString(trustedKey)
	if e != nil {
		return errUpdate
	}
	manifest, e := verifyManifest(data, key, *current, time.Now())
	if e != nil {
		return e
	}
	prepared, e := os.MkdirTemp(filepath.Dir(target), "."+filepath.Base(target)+".new-")
	if e != nil {
		return e
	}
	// This exact directory was created by this process, next to the checked target.
	// Remove it only while it remains in that parent and has not become a link.
	defer func() {
		if filepath.Dir(prepared) == filepath.Dir(target) {
			if info, e := os.Lstat(prepared); e == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 && checkParents(prepared) == nil {
				_ = os.RemoveAll(prepared)
			}
		}
	}()
	if e = extractVerified(archive, prepared, manifest); e != nil {
		return e
	}
	if e = waitParent(*parent, filepath.Join(target, "ByteLocker.exe"), cancel, 90*time.Second, func() error { return os.WriteFile(ready, []byte(*nonce), 0600) }); e != nil {
		return e
	}
	if _, e = os.Stat(cancel); !os.IsNotExist(e) {
		return errUpdate
	}
	starts := 0
	_, e = swapInstall(target, prepared, func(path string) error { starts++; return startApplication(path) })
	if e != nil {
		if starts == 0 && auditInstall(target) == nil {
			_ = startApplication(filepath.Join(target, "ByteLocker.exe"))
		}
		writeStatus("rolled-back", manifest.Version)
		return e
	}
	writeStatus("installed", manifest.Version)
	for _, name := range []string{archive, manifestPath, ready} {
		_ = os.Remove(name)
	}
	return nil
}
func main() {
	if run() != nil {
		os.Exit(1)
	}
}
