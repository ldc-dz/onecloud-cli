package cli

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/ldc-dz/onecloud-cli/internal/portal"
	"github.com/ldc-dz/onecloud-cli/internal/services"
)

func entryWith(outputs map[string]any) services.Entry {
	return services.Entry{Kind: services.ClickHouse, Instance: portal.CatalogInstance{
		Tenant: "uat-999002", InstanceName: "uatch02", Outputs: outputs}}
}

// UAT 2026-11 (OneCloud #2754): in OneCloud Shell the SQL commands go to the
// tenant-network endpoint the portal publishes, not through the gateway.
func TestTenantEndpoint(t *testing.T) {
	for _, tc := range []struct {
		outputs map[string]any
		want    string
	}{
		{map[string]any{"nativeEndpoint": "uatch02-ch.tenant-uat-999002-clickhouse.svc.ocd-prd-01.onecloud.internal:9000"},
			"uatch02-ch.tenant-uat-999002-clickhouse.svc.ocd-prd-01.onecloud.internal:9000"},
		{map[string]any{"host": "sql.tenant.svc", "port": "1433"}, "sql.tenant.svc:1433"},
	} {
		got, err := tenantEndpoint(entryWith(tc.outputs))
		if err != nil || got != tc.want {
			t.Fatalf("tenantEndpoint(%v) = %q, %v", tc.outputs, got, err)
		}
	}
	for _, bad := range []map[string]any{
		{},
		{"nativeEndpoint": "no-port"},
		{"nativeEndpoint": "host:99999"},
		{"nativeEndpoint": "user@host:9000"},
	} {
		if _, err := tenantEndpoint(entryWith(bad)); err == nil {
			t.Fatalf("tenantEndpoint(%v) accepted", bad)
		}
	}
}

func TestDirectTunnelForwardsLoopbackOnly(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write([]byte(strings.ToUpper(string(buf))))
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tun, err := openDirect(ctx, backend.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if addr := tun.ln.Addr().(*net.TCPAddr); !addr.IP.IsLoopback() {
		t.Fatalf("listener on %v, want loopback", addr)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tun.Port())))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "PING" {
		t.Fatalf("forwarded %q, %v", got, err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(tun.Port()))); err == nil {
		t.Fatal("listener still open after Close")
	}
}
