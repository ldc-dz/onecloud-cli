//go:build linux || darwin || freebsd || netbsd || openbsd

package selector

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// tty is /dev/tty in raw, non-echo mode with a 0.2 s read timeout.
type tty struct {
	f     *os.File
	saved unix.Termios
	buf   [1]byte
}

func openTTY() (*tty, error) {
	f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	saved, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		f.Close()
		return nil, err
	}
	raw := *saved
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 2
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &raw); err != nil {
		f.Close()
		return nil, err
	}
	return &tty{f: f, saved: *saved}, nil
}

func (t *tty) Write(p []byte) (int, error) { return t.f.Write(p) }

// next maps a zero-byte timed-out read (io.EOF in raw mode, where Ctrl-D is
// a plain byte) to ok=false.
func (t *tty) next() (byte, bool, error) {
	n, err := t.f.Read(t.buf[:])
	if n == 1 {
		return t.buf[0], true, nil
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
		return 0, false, nil
	}
	return 0, false, err
}

func (t *tty) Close() error {
	_ = unix.IoctlSetTermios(int(t.f.Fd()), ioctlSetTermios, &t.saved)
	return t.f.Close()
}
