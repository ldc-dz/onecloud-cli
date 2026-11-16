//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package s3cmd

import (
	"errors"
	"os"
)

// Fail closed until this platform has a race-safe, no-follow file opener.
func openNoFollow(string) (*os.File, error) {
	return nil, errors.New("safe no-symlink uploads are not supported on this platform")
}
