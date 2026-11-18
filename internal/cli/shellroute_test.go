package cli

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
)

// UAT 2026-11 PG-SH-CLI-01 (OneCloud #2638): in OneCloud Shell, ocd psql
// reaches the instance service directly when its name resolves to a private
// address that answers; otherwise it keeps the normal path.
func TestShellServiceAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	open := ln.Addr().(*net.TCPAddr).Port
	restore := lookupHost
	defer func() { lookupHost = restore }()

	answer := func(addrs []string, err error) {
		lookupHost = func(context.Context, string) ([]string, error) { return addrs, err }
	}

	// 127.0.0.1 is not private: never used even when it answers.
	answer([]string{"127.0.0.1"}, nil)
	if got := shellServiceAddress("x.svc", open); got != "" {
		t.Fatalf("loopback accepted: %q", got)
	}
	answer(nil, errors.New("no such host"))
	if got := shellServiceAddress("x.svc", open); got != "" {
		t.Fatalf("unresolved name accepted: %q", got)
	}
	answer([]string{"8.8.8.8"}, nil)
	if got := shellServiceAddress("x.svc", open); got != "" {
		t.Fatalf("public address accepted: %q", got)
	}
	// Private but closed port (reserved test range, nothing listens).
	answer([]string{"10.255.255.1"}, nil)
	if got := shellServiceAddress("x.svc", 1); got != "" {
		t.Fatalf("closed port accepted: %q", got)
	}
	_ = strconv.Itoa(open)
}
