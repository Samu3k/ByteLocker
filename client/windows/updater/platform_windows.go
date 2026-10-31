package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")

func checkParents(path string) error {
	path, e := filepath.Abs(path)
	if e != nil {
		return errUpdate
	}
	for {
		wide, e := syscall.UTF16PtrFromString(path)
		if e != nil {
			return e
		}
		attrs, e := syscall.GetFileAttributes(wide)
		if e != nil || attrs&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errUpdate
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
func waitParent(pid int, expected, cancel string, timeout time.Duration, ready func() error) error {
	handle, _, _ := kernel.NewProc("OpenProcess").Call(0x100000|0x1000, 0, uintptr(pid))
	if handle == 0 {
		return errUpdate
	}
	defer syscall.CloseHandle(syscall.Handle(handle))
	image := make([]uint16, 32768)
	length := uint32(len(image))
	ok, _, _ := kernel.NewProc("QueryFullProcessImageNameW").Call(handle, 0, uintptr(unsafe.Pointer(&image[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || !strings.EqualFold(filepath.Clean(syscall.UTF16ToString(image[:length])), filepath.Clean(expected)) {
		return errUpdate
	}
	if e := ready(); e != nil {
		return e
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, e := os.Stat(cancel); !os.IsNotExist(e) {
			return errUpdate
		}
		state, e := syscall.WaitForSingleObject(syscall.Handle(handle), 100)
		if e != nil {
			return e
		}
		if state == 0 {
			return nil
		}
	}
	return errUpdate
}
func startApplication(path string) error {
	command := exec.Command(path)
	command.Dir = filepath.Dir(path)
	if e := command.Start(); e != nil {
		return e
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	select {
	case <-exited:
		return errUpdate
	case <-time.After(2 * time.Second):
		return nil
	}
}
