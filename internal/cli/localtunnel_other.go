//go:build !linux

package cli

import "net"

// peerOwnedByMe has no portable peer-owner check off Linux; see localtunnel.go.
func peerOwnedByMe(net.Conn) bool { return true }
