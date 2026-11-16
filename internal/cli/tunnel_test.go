package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
)

func TestSignedInPageClosesTab(t *testing.T) {
	if !strings.Contains(signedInPage, "window.close()") || !strings.Contains(signedInPage, "Signed in to OneCloud") {
		t.Fatal("the opkssh callback page must try to close the tab and show a fallback message")
	}
}

func TestIsNormalClose(t *testing.T) {
	for _, err := range []error{nil, io.EOF, context.Canceled, net.ErrClosed, fmt.Errorf("read: %w", io.EOF)} {
		if !isNormalClose(err) {
			t.Errorf("%v should be a normal close", err)
		}
	}
	if isNormalClose(errors.New("403 forbidden")) {
		t.Error("a real failure must still be reported")
	}
}

func TestAuthDenied(t *testing.T) {
	denied := "anis-fathallah-2@vm: Permission denied (publickey).\n"
	if !authDenied(exitError{255}, denied) {
		t.Error("exit 255 with Permission denied must trigger a rejoin")
	}
	if authDenied(exitError{1}, denied) || authDenied(exitError{255}, "Connection closed") || authDenied(nil, denied) {
		t.Error("only an authentication refusal may trigger a rejoin")
	}
	var tb tailBuffer
	for i := 0; i < 2000; i++ {
		_, _ = tb.Write([]byte("abc"))
	}
	if len(tb.String()) != 4096 {
		t.Errorf("tail buffer keeps %d bytes", len(tb.String()))
	}
}

func TestTunnelBrowserCommand(t *testing.T) {
	cases := []struct{ flag, goos, want string }{
		{"", "linux", helperMarker},
		{"", "windows", helperMarker},
		// pomerium-cli runs `open -a <cmd> <url>` on macOS: never pass ocd.
		{"", "darwin", ""},
		{"Firefox", "darwin", "Firefox"},
		{"firefox", "linux", "firefox"},
	}
	for _, c := range cases {
		if got := tunnelBrowserCommand(c.flag, c.goos); got != c.want {
			t.Errorf("tunnelBrowserCommand(%q, %q) = %q, want %q", c.flag, c.goos, got, c.want)
		}
	}
}
