package cli

import (
	"net"
	"testing"
)

func TestLocalTunnelPeerAllowedSameUser(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("loopback listen: %v", err)
	}
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if !peerAllowed(s) {
		t.Fatal("connection from the current user was refused")
	}
}
