package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/portalcache"
)

// fakeSQLClient connects to the loopback port ocd gives it (-S
// 127.0.0.1,<port> for sqlcmd, --port <port> for ClickHouse), sends a probe,
// and records its arguments and whether the password came through the
// environment.
const fakeSQLClient = `#!/bin/bash
if [ "$1" = "--version" ]; then echo "ClickHouse client version 25.8.1.1 (official build)."; exit 0; fi
printf '%s\n' "$@" > "$FAKE_SQL_ARGS"
if [ -n "$SQLCMDPASSWORD$CLICKHOUSE_PASSWORD" ]; then echo env-password >> "$FAKE_SQL_ARGS"; fi
port=""
prev=""
for a in "$@"; do
  case "$prev" in
    -S) port="${a#127.0.0.1,}" ;;
    --port) port="$a" ;;
  esac
  prev="$a"
done
exec 3<>"/dev/tcp/127.0.0.1/$port" || exit 7
printf ping >&3
head -c 4 <&3 >/dev/null || exit 8
`

// sqlDirectEnv starts a fake portal (catalog, reveal, connections with a
// tenant-network address) and a fake tenant-network server on a private IP,
// and returns a channel signalled for each connection that reached it.
func sqlDirectEnv(t *testing.T, engine, client string, publishVPC bool) (accepted chan struct{}, argsFile string, stderr func() string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake SQL client is a bash script")
	}
	privateIP := privateTestAddress(t)
	direct, err := net.Listen("tcp", net.JoinHostPort(privateIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = direct.Close() })
	old := directSQLPorts[engine]
	directSQLPorts[engine] = direct.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() { directSQLPorts[engine] = old })
	accepted = make(chan struct{}, 4)
	go func() {
		for {
			c, err := direct.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				data := make([]byte, 4)
				if _, err := io.ReadFull(c, data); err == nil {
					_, _ = c.Write(data)
					accepted <- struct{}{}
				}
			}()
		}
	}()

	ns := "tenant-demo-000001-" + engine
	vpc := ""
	if publishVPC {
		vpc = privateIP
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/provisioning/instances", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]any{map[string]any{
			"id": "inst-1", "tenant": "demo-000001", "cluster": "ocd-dev-01", "service": engine,
			"instance_name": "db01", "status": "ready", "created_at": "2026-11-19T00:00:00Z"}})
	})
	mux.HandleFunc("/api/provisioning/instances/inst-1/reveal", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "revealed", "password": "fake-test-value"})
	})
	mux.HandleFunc("/api/provisioning/connections", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"nextCursor": nil, "connections": []any{map[string]any{
			"id": "ocd-dev-01/" + ns + "/db01-" + engine, "tenantId": "demo-000001", "cluster": "ocd-dev-01",
			"engine": engine, "instanceName": "db01", "vpcAddress": vpc}}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv("OCD_CLOUD_SHELL", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	cfgDir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", cfgDir)
	// The gateway is unreachable: reaching the fake server proves the direct path.
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("clusters:\n  ocd-dev-01:\n"+
		"    pomeriumURL: http://127.0.0.1:1\n    issuer: "+srv.URL+"/realm\n    portalURL: "+srv.URL+"\n    tcpDomain: tcp.example\n"), 0o600)
	cl := config.Cluster{Name: "ocd-dev-01", Issuer: srv.URL + "/realm", PortalURL: srv.URL, PortalClientID: "dev-01-portal-tui"}
	jwt := "h." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix()))) + ".s"
	if err := (portalcache.Store{Dir: cfgDir}).SaveToken(cl, jwt); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	_ = os.WriteFile(filepath.Join(bin, client), []byte(fakeSQLClient), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCD_BROWSER", "none")
	argsFile = filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKE_SQL_ARGS", argsFile)
	// say() writes to the process stderr, not to the command output.
	errPath := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(errPath)
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = orig; _ = f.Close() })
	stderr = func() string {
		raw, _ := os.ReadFile(errPath)
		return string(raw)
	}
	return accepted, argsFile, stderr
}

// TestSQLCommandsConnectDirectOverTenantNetwork: UAT 2026-11 VPN-MS-01 and
// VPN-CH-01 (OneCloud #2638). With a published, reachable tenant-network
// address, ocd mssql and ocd clickhouse connect directly, keep the password
// in the environment and keep the client TLS options of the gateway path.
func TestSQLCommandsConnectDirectOverTenantNetwork(t *testing.T) {
	for _, tc := range []struct{ engine, client, tlsArg string }{
		{"mssql", "sqlcmd", "-C"},
		{"clickhouse", "clickhouse-client", ""},
	} {
		t.Run(tc.engine, func(t *testing.T) {
			accepted, argsFile, stderr := sqlDirectEnv(t, tc.engine, tc.client, true)
			out, err := run(t, tc.engine, "--cluster", "ocd-dev-01", "demo-000001/db01")
			out += stderr()
			if err != nil {
				t.Fatalf("ocd %s: %v\n%s", tc.engine, err, out)
			}
			if !strings.Contains(out, "directly over your tenant network") {
				t.Fatalf("path not reported as direct: %q", out)
			}
			select {
			case <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("client did not reach the tenant-network address")
			}
			raw, _ := os.ReadFile(argsFile)
			args := string(raw)
			if strings.Contains(args, "fake-test-value") || !strings.Contains(args, "env-password") {
				t.Fatalf("password must be in the environment only: %q", args)
			}
			if tc.tlsArg != "" && !strings.Contains(args, "\n"+tc.tlsArg+"\n") {
				t.Fatalf("client options changed on the direct path: %q", args)
			}
		})
	}
}

// TestSQLCommandsViaDirectNeedsAddress: --via direct without a published
// address fails instead of falling back to the gateway, and --via proxied
// never reads the address.
func TestSQLCommandsViaDirectNeedsAddress(t *testing.T) {
	_, _, stderr := sqlDirectEnv(t, "mssql", "sqlcmd", false)
	_, err := run(t, "--via", "direct", "mssql", "--cluster", "ocd-dev-01", "demo-000001/db01")
	if err == nil || !strings.Contains(err.Error(), "tenant-network address") {
		t.Fatalf("--via direct without address: %v", err)
	}
	out, _ := run(t, "--via", "proxied", "mssql", "--cluster", "ocd-dev-01", "demo-000001/db01")
	out += stderr()
	if strings.Contains(out, "directly over your tenant network") || !strings.Contains(out, "access gateway") {
		t.Fatalf("--via proxied output: %q", out)
	}
}
