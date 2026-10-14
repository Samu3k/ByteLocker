package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestPersistentInstance(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "data # + %")
	first, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	identity := first.Instance()
	if identity.ServerID.IsZero() || identity.CreatedAt.IsZero() {
		t.Fatal("missing instance identity")
	}
	for query, want := range map[string]int{"PRAGMA foreign_keys": 1, "PRAGMA synchronous": 2, "PRAGMA trusted_schema": 0} {
		var got int
		if err := first.db.QueryRow(query).Scan(&got); err != nil || got != want {
			t.Fatalf("unsafe connection setting: %s", query)
		}
	}
	var mode string
	if err := first.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatal("WAL disabled")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(first.Ping(context.Background()), ErrUnavailable) {
		t.Fatal("closed database available")
	}
	second, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Instance() != identity {
		t.Fatal("restart changed identity")
	}
	if err := second.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentInitialization(t *testing.T) {
	directory := t.TempDir()
	var stores [2]*Store
	var failures [2]error
	var group sync.WaitGroup
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			stores[index], failures[index] = Open(context.Background(), directory)
		}(i)
	}
	group.Wait()
	for i := range stores {
		if failures[i] != nil {
			t.Fatal(failures[i])
		}
		defer stores[i].Close()
	}
	if stores[0].Instance() != stores[1].Instance() {
		t.Fatal("concurrent boot produced different instances")
	}
}

func TestRejectIncompatibleSchema(t *testing.T) {
	for _, mutation := range []string{
		"UPDATE schema_migrations SET checksum='changed'",
		"INSERT INTO schema_migrations(version,checksum) VALUES(10,'future')",
		"DELETE FROM instance",
	} {
		t.Run(mutation, func(t *testing.T) {
			directory := t.TempDir()
			store, err := Open(context.Background(), directory)
			if err != nil {
				t.Fatal(err)
			}
			identity := store.Instance()
			if _, err := store.db.Exec(mutation); err != nil {
				t.Fatal(err)
			}
			store.Close()
			if reopened, err := Open(context.Background(), directory); !errors.Is(err, ErrSchemaMismatch) {
				if reopened != nil {
					reopened.Close()
				}
				t.Fatal("incompatible database was accepted")
			}
			if identity.ServerID.IsZero() {
				t.Fatal("fixture has no identity")
			}
		})
	}
}

func TestInvalidStorage(t *testing.T) {
	if store, err := Open(context.Background(), " "); !errors.Is(err, ErrInvalidDirectory) || store != nil {
		t.Fatal("empty directory accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), file); !errors.Is(err, ErrInvalidDirectory) {
		t.Fatal("file accepted as directory")
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "passwordmanager.db"), []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	if store, err := Open(context.Background(), directory); err == nil {
		store.Close()
		t.Fatal("corrupt database accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if store, err := Open(ctx, t.TempDir()); err == nil {
		store.Close()
		t.Fatal("cancelled initialization succeeded")
	}
	var nilStore *Store
	if err := nilStore.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(nilStore.Ping(context.Background()), ErrUnavailable) {
		t.Fatal("nil store available")
	}
}
