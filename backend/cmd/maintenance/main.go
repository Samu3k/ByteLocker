// Command maintenance is local operator tooling, never a public API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"passwordmanager/internal/maintenance"
	"time"
)

func run(ctx context.Context, args []string, out io.Writer) error {
	const usage = "Usage: bytelocker-maintenance backup -root DIRECTORY -out ARCHIVE [-snapshot DIRECTORY] | snapshot -data-dir DIRECTORY -destination NEW_DIRECTORY | verify -archive ARCHIVE | restore -archive ARCHIVE -destination NEW_DIRECTORY"
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, usage)
		return err
	}
	command := args[0]
	if command != "backup" && command != "verify" && command != "restore" && command != "snapshot" {
		return errors.New("maintenance: unknown command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var root, output, archive, destination, snapshot string
	if command == "backup" {
		flags.StringVar(&root, "root", "", "Stopped server project directory")
		flags.StringVar(&output, "out", "", "New private archive path")
		flags.StringVar(&snapshot, "snapshot", "", "Private consistent online snapshot directory")
	} else if command == "snapshot" {
		flags.StringVar(&root, "data-dir", "", "Running server data directory")
		flags.StringVar(&destination, "destination", "", "New private snapshot directory")
	} else {
		flags.StringVar(&archive, "archive", "", "Backup archive")
		if command == "restore" {
			flags.StringVar(&destination, "destination", "", "New directory only")
		}
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("maintenance: invalid arguments")
	}
	var m maintenance.Manifest
	var err error
	switch command {
	case "backup":
		if root == "" || output == "" {
			return errors.New("maintenance: root and out required")
		}
		if snapshot != "" {
			m, err = maintenance.CreateWithSnapshot(ctx, root, output, snapshot)
		} else {
			m, err = maintenance.Create(ctx, root, output)
		}
	case "snapshot":
		if root == "" || destination == "" {
			return errors.New("maintenance: data-dir and new destination required")
		}
		m.Report, err = maintenance.Snapshot(ctx, root, destination)
		m.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	case "verify":
		if archive == "" {
			return errors.New("maintenance: archive required")
		}
		m, err = maintenance.Verify(ctx, archive)
	case "restore":
		if archive == "" || destination == "" {
			return errors.New("maintenance: archive and new destination required")
		}
		m, err = maintenance.Restore(ctx, archive, destination)
	}
	if err != nil {
		return errors.New("maintenance: operazione non completata; nessun ripristino sul server attivo")
	}
	return json.NewEncoder(out).Encode(struct {
		Status    string `json:"status"`
		Instance  any    `json:"instance"`
		CreatedAt string `json:"created_at"`
	}{"verified", m.Report, m.CreatedAt})
}
func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
