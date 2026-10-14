package storage

import (
	"context"
	"os"
	"passwordmanager/internal/operationalkeys"
	"path/filepath"
	"testing"
)

func TestBackupCheckNeverCreatesOrMigratesDatabase(t *testing.T) {
	ctx := context.Background()
	empty := t.TempDir()
	if _, err := CheckBackup(ctx, empty); err == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(filepath.Join(empty, "passwordmanager.db")); !os.IsNotExist(err) {
		t.Fatal("verification created database")
	}
	for _, mutation := range []string{"DELETE FROM operational_key_binding", "UPDATE operational_key_binding SET fingerprint=zeroblob(32)", "DELETE FROM schema_migrations WHERE version=9", "UPDATE schema_migrations SET checksum='invalid' WHERE version=9", "PRAGMA ignore_check_constraints=ON; UPDATE instance SET server_id=zeroblob(16)"} {
		t.Run(mutation, func(t *testing.T) {
			directory := t.TempDir()
			s, err := Open(ctx, directory)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := operationalkeys.LoadOrCreate(ctx, directory, s.Instance().ServerID, true)
			if err != nil {
				t.Fatal(err)
			}
			if err = s.BindOperationalKeys(ctx, keys.Fingerprint()); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			s.Close()
			before, _ := os.ReadFile(filepath.Join(directory, "passwordmanager.db"))
			if _, err = CheckBackup(ctx, directory); err == nil {
				t.Fatal("invalid copy accepted")
			}
			after, _ := os.ReadFile(filepath.Join(directory, "passwordmanager.db"))
			if string(before) != string(after) {
				t.Fatal("verification changed database")
			}
		})
	}
}
