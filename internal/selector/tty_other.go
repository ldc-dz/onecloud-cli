//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package selector

import "errors"

type tty struct{}

// openTTY: no raw terminal support on this platform; Select reports
// ErrNotInteractive and the caller asks for an explicit target.
func openTTY() (*tty, error) { return nil, errors.New("no /dev/tty") }

func (*tty) Write(p []byte) (int, error) { return len(p), nil }
func (*tty) next() (byte, bool, error)   { return 0, false, errors.New("no /dev/tty") }
func (*tty) Close() error                { return nil }
