//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package s3cmd

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Walk with directory FDs and O_NOFOLLOW on EVERY component, not a
// vulnerable Lstat/Open pair. O_NONBLOCK also keeps a malicious FIFO from
// hanging before the regular-file check. .. is rejected instead of cleaned.
func openNoFollow(path string) (*os.File, error) {
	anchor := "."
	if filepath.IsAbs(path) {
		anchor = string(filepath.Separator)
	}
	fd, err := unix.Open(anchor, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			unix.Close(fd)
		}
	}()
	parts := strings.Split(path, string(filepath.Separator))
	meaningful := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == ".." {
			return nil, os.ErrInvalid
		}
		if part != "" && part != "." {
			meaningful = append(meaningful, part)
		}
	}
	if len(meaningful) == 0 || strings.HasSuffix(path, string(filepath.Separator)) {
		return nil, os.ErrInvalid
	}
	for i, part := range meaningful {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i != len(meaningful)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, err := unix.Openat(fd, part, flags, 0)
		if err != nil {
			return nil, err
		}
		unix.Close(fd)
		fd = next
	}
	file := os.NewFile(uintptr(fd), "upload-source")
	fd = -1
	return file, nil
}
