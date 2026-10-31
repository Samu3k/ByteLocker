//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"time"
)

func checkParents(path string) error {
	for {
		info, e := os.Lstat(path)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return errUpdate
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func waitParent(int, string, string, time.Duration, func() error) error { return errUpdate }
func startApplication(string) error                                     { return errUpdate }
