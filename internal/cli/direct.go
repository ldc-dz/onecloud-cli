package cli

// direct.go: OneCloud Shell runs inside the tenant network, where the access
// gateway (which signs in through a browser) is not needed. The SQL commands
// reach the tenant-network endpoint the portal publishes through a loopback
// forwarder, so the native client sees the same 127.0.0.1 port as with the
// gateway tunnel.

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/services"
)

// tenantEndpoint returns the host:port of the tenant-network endpoint the
// portal publishes for an instance ("nativeEndpoint", or "host" + "port").
func tenantEndpoint(e services.Entry) (string, error) {
	endpoint := firstValue(nil, e, "nativeEndpoint")
	if endpoint == "" {
		host, port := firstValue(nil, e, "host"), firstValue(nil, e, "port")
		if host != "" && port != "" {
			endpoint = net.JoinHostPort(host, port)
		}
	}
	if endpoint == "" {
		return "", fmt.Errorf("%s: the portal publishes no tenant-network endpoint", e.Target())
	}
	host, port, err := net.SplitHostPort(endpoint)
	n, perr := strconv.Atoi(port)
	if err != nil || perr != nil || n < 1 || n > 65535 || host == "" || strings.ContainsAny(host, "/@ ") {
		return "", fmt.Errorf("%s: invalid tenant-network endpoint %q", e.Target(), endpoint)
	}
	return endpoint, nil
}

// directTunnel forwards a 127.0.0.1 port to one tenant-network endpoint.
type directTunnel struct {
	ln   net.Listener
	once sync.Once
}

func (d *directTunnel) Port() int { return d.ln.Addr().(*net.TCPAddr).Port }

func (d *directTunnel) Close() error {
	var err error
	d.once.Do(func() { err = d.ln.Close() })
	return err
}

// openDirect listens on loopback only and dials endpoint for each client
// connection.
func openDirect(ctx context.Context, endpoint string) (*directTunnel, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &directTunnel{ln: ln}
	go func() {
		<-ctx.Done()
		_ = d.Close()
	}()
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go forward(client, endpoint)
		}
	}()
	return d, nil
}

func forward(client net.Conn, endpoint string) {
	defer client.Close()
	server, err := net.DialTimeout("tcp", endpoint, 15*time.Second)
	if err != nil {
		return
	}
	defer server.Close()
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
		done <- struct{}{}
	}
	go pipe(server, client)
	go pipe(client, server)
	<-done
	<-done
}
