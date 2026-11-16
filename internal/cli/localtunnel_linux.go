package cli

import (
	"bufio"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// peerOwnedByMe looks up the client end of a loopback TCP connection in
// /proc/net/tcp{,6} and compares its owner UID with ours. Fails closed.
func peerOwnedByMe(conn net.Conn) bool {
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	la, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if uid, found := procTCPOwner(f, ra, la); found {
			return uid == os.Getuid()
		}
	}
	return false
}

func procTCPOwner(path string, local, remote *net.TCPAddr) (int, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 8 {
			continue
		}
		if procAddrEqual(fs[1], local) && procAddrEqual(fs[2], remote) {
			uid, err := strconv.Atoi(fs[7])
			return uid, err == nil
		}
	}
	return 0, false
}

// procAddrEqual compares a /proc/net/tcp "HEXIP:HEXPORT" field with a.
func procAddrEqual(field string, a *net.TCPAddr) bool {
	ip, port, ok := strings.Cut(field, ":")
	if !ok {
		return false
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil || int(p) != a.Port {
		return false
	}
	raw, err := hex.DecodeString(ip)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return false
	}
	// The kernel prints each 32-bit word in host (little-endian) order.
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return net.IP(raw).Equal(a.IP)
}
