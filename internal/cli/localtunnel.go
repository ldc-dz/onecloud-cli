package cli

import "net"

// Local tunnel access control.
//
// The gateway tunnel carries the user's Pomerium session, so a connection
// accepted on the local port acts as that user. A Unix-domain socket in a
// 0700 directory would restrict access, but libpq never negotiates TLS over
// Unix sockets (sslmode is ignored there), which would drop the end-to-end
// verify-full TLS to the instance. The tunnel therefore stays on TCP
// 127.0.0.1 and each accepted connection is checked with peerAllowed:
//   - Linux: the peer socket's owner UID (from /proc/net/tcp{,6}) must equal
//     the current UID; anything else, or an unknown owner, is refused.
//   - other systems: no peer-owner API is used yet, so any local user who can
//     reach the loopback port while psql runs can use it (residual risk).
// Reconnects and psql query cancel (a new connection to the same port) come
// from the same user and keep working.

// peerAllowed reports whether conn may use the tunnel.
func peerAllowed(conn net.Conn) bool { return peerOwnedByMe(conn) }
