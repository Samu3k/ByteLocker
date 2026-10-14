package operationalkeys

import "syscall"

// MoveFileW, unlike os.Rename on Windows, refuses an existing destination.
// Stage and destination share a directory and therefore a filesystem volume.
func publish(stage, target string) error {
	from, err := syscall.UTF16PtrFromString(stage)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return syscall.MoveFile(from, to)
}
