//go:build !windows

package operationalkeys

import "os"

func publish(stage, target string) error { return os.Link(stage, target) }
