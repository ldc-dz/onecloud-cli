package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// refusingGateway is an access-gateway stand-in that answers every CONNECT
// with the given status line (503: the instance cannot be reached).
func refusingGateway(t *testing.T, status string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if _, err := http.ReadRequest(bufio.NewReader(c)); err != nil {
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()
	return ln.Addr().String()
}

// tunnelClientRun sends a first packet through a local tunnel to gateway, as a
// database client does, and returns the client's read error and what ocd
// printed on stderr.
func tunnelClientRun(t *testing.T, gateway string) (readErr error, stderr string) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()

	tun, _, err := newTunnel("uatms01-mssql-000001.tcp.example.com:443", "http://"+gateway, "none")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startTunnel(ctx, tun, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte("prelogin")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, readErr = io.ReadFull(c, make([]byte, 8))
	_ = c.Close()
	srv.wg.Wait()
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return readErr, string(out)
}

// A tunnel that cannot be opened used to be dropped without a word: the
// database client only showed "read: connection reset by peer" (OneCloud
// #2799). ocd must name the cause.
func TestTunnelFailureBeforeConnectIsReported(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := closed.Addr().String()
	closed.Close()
	for name, tc := range map[string]struct{ gateway, want string }{
		"gateway answers 503": {refusingGateway(t, "503 Service Unavailable"), "unavailable"},
		"gateway unreachable": {unreachable, "connection refused"},
	} {
		t.Run(name, func(t *testing.T) {
			readErr, stderr := tunnelClientRun(t, tc.gateway)
			if readErr == nil {
				t.Fatal("the client read succeeded through a tunnel that was never opened")
			}
			if !strings.Contains(stderr, "The access-gateway tunnel could not be opened") || !strings.Contains(stderr, tc.want) {
				t.Fatalf("client failed with %q but ocd did not explain it; stderr: %q", readErr, stderr)
			}
		})
	}
}

// A session that was opened and then ended is not reported as a failed
// opening.
func TestTunnelEndedAfterConnectIsNotReportedAsOpeningFailure(t *testing.T) {
	proxy, _ := fakeConnectProxy(t)
	readErr, stderr := tunnelClientRun(t, proxy)
	if readErr != nil {
		t.Fatalf("echo through the tunnel: %v", readErr)
	}
	if strings.Contains(stderr, "could not be opened") {
		t.Fatalf("working tunnel reported as failed: %q", stderr)
	}
}
