package cli

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/portal"
)

// fakeConnectProxy is a plain-HTTP Pomerium stand-in: it accepts CONNECT,
// records the requested destination and echoes the tunnelled bytes back.
func fakeConnectProxy(t *testing.T) (addr string, dsts chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	dsts = make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				dsts <- req.Host
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				_, _ = io.Copy(c, br)
			}(c)
		}
	}()
	return ln.Addr().String(), dsts
}

func writeTestCA(t *testing.T, path string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pgoidc01-pg"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fakePsql answers --version like psql 18, records its arguments and sends
// "ping" through the local tunnel port given in the conninfo, expecting the
// echo back.
const fakePsql = `#!/usr/bin/env bash
if [ "$1" = "--version" ]; then echo "psql (PostgreSQL) 18.6"; exit 0; fi
printf '%s\n' "$@" > "$FAKE_PSQL_ARGS"
port=$(printf '%s' "$1" | sed -n 's/.* port=\([0-9]*\) .*/\1/p')
addr=$(printf '%s' "$1" | sed -n 's/.* hostaddr=\([^ ]*\) .*/\1/p')
exec 3<>/dev/tcp/$addr/$port
printf ping >&3
read -r -n 4 -t 5 reply <&3
[ "$reply" = ping ] || { echo "no echo through database connection: '$reply'" >&2; exit 7; }
exit 0
`

func TestPsqlThroughTunnel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake psql is a bash script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	proxy, dsts := fakeConnectProxy(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	cfgDir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", cfgDir)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"),
		[]byte("clusters:\n  ocd-prd-01:\n    pomeriumURL: http://"+proxy+"\n"), 0o600)

	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "psql"), []byte(fakePsql), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKE_PSQL_ARGS", argsFile)
	wd := t.TempDir()
	t.Chdir(wd)
	writeTestCA(t, filepath.Join(wd, "pgoidc01-ca.crt"))

	if _, err := run(t, "psql", "--via", "proxied", "--cluster", "ocd-prd-01", "--ca", "pgoidc01-ca.crt", "demo-000001/pgoidc01", "--", "-c", "select 1"); err != nil {
		t.Fatalf("ocd psql: %v", err)
	}
	select {
	case dst := <-dsts:
		if dst != "pgoidc01-pg-000001.tcp.access.onecloud.ldc.dz:443" {
			t.Fatalf("tunnel asked Pomerium for %s", dst)
		}
	default:
		t.Fatal("no CONNECT reached the proxy")
	}
	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Split(strings.TrimSpace(string(raw)), "\n")
	stored := filepath.Join(cfgDir, "postgres", "ocd-prd-01", "demo-000001", "pgoidc01-ca.crt")
	for _, want := range []string{
		"host=pgoidc01-pg-access.tenant-demo-000001-postgresql.svc hostaddr=127.0.0.1 port=",
		" dbname=app user=app sslmode=verify-full sslrootcert=" + stored,
		" oauth_issuer=https://auth.onecloud.ldc.dz/realms/prd-01-portal oauth_client_id=prd-01-postgresql",
	} {
		if !strings.Contains(args[0], want) {
			t.Fatalf("conninfo %q lacks %q", args[0], want)
		}
	}
	if len(args) != 3 || args[1] != "-c" || args[2] != "select 1" {
		t.Fatalf("extra psql arguments not passed: %q", args[1:])
	}
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("CA not kept for later runs: %v", err)
	}

	// Second run from another folder: the stored CA is enough. In --via
	// auto, a headless process with no portal token falls back immediately;
	// there is no second sign-in or manual CA step.
	t.Chdir(t.TempDir())
	t.Setenv("OCD_BROWSER", "none")
	if _, err := run(t, "psql", "--via", "auto", "--cluster", "ocd-prd-01", "-U", "analyst", "demo-000001/pgoidc01"); err != nil {
		t.Fatalf("second run: %v", err)
	}
	raw, _ = os.ReadFile(argsFile)
	if !strings.Contains(string(raw), " user=analyst ") {
		t.Fatalf("-U not applied: %s", raw)
	}
}

func TestPsqlWithoutCAExplainsPortalDownload(t *testing.T) {
	// A cluster without a portal: ocd cannot fetch the CA and must explain --ca.
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	cfg := "clusters:\n  lab:\n    enabled: true\n    issuer: https://kc.example/realms/x\n    clientID: c\n" +
		"    tcpDomain: tcp.example\n    postgresIssuer: https://kc.example/realms/x\n    postgresClientID: pg\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	_, err := run(t, "psql", "--cluster", "lab", "demo-000001/pgoidc01")
	if err == nil || !strings.Contains(err.Error(), "TLS CA certificate") || !strings.Contains(err.Error(), "--ca pgoidc01-ca.crt") {
		t.Fatalf("got %v", err)
	}
}

func TestPsqlNeedsTenantSlug(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	_, err := run(t, "psql", "000001/pgoidc01")
	if err == nil || !strings.Contains(err.Error(), "full tenant name") {
		t.Fatalf("got %v", err)
	}
}

func TestSSHOffClusterRefusesVMSSH(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("clusters:\n  ocd-prd-01:\n    ssh: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"login", "--cluster", "ocd-prd-01"}, {"ssh", "--cluster", "ocd-prd-01", "demo-000001/vmsso"}} {
		if _, err := run(t, args...); err == nil || !strings.Contains(err.Error(), "VM SSH sign-on is not available") {
			t.Fatalf("%v: got %v", args, err)
		}
	}
}

func TestNoOAuthHint(t *testing.T) {
	if noOAuthHint("psql: error: no OAuth flows are available (try installing the libpq-oauth package)") == "" {
		t.Fatal("missing libpq-oauth not explained")
	}
	if noOAuthHint("FATAL: database \"x\" does not exist") != "" {
		t.Fatal("unrelated error got the OAuth hint")
	}
}

// fakeBrowser follows the portal authorization URL straight back to the
// loopback redirect_uri with a code, as Keycloak does after a sign-in.
const fakeBrowser = `#!/usr/bin/env bash
q="${1#*\?}"
get() { printf '%s' "$q" | tr '&' '\n' | sed -n "s/^$1=//p"; }
redirect=$(get redirect_uri | sed 's/%3A/:/g; s/%2F/\//g')
state=$(get state)
exec 3<>/dev/tcp/127.0.0.1/$(printf '%s' "$redirect" | sed -n 's#http://127.0.0.1:\([0-9]*\)/.*#\1#p')
printf 'GET /callback?code=c1&state=%s HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' "$state" >&3
cat <&3 >/dev/null
`

// TestPsqlDownloadsCAFromPortal: with no CA anywhere, ocd psql signs in to
// the portal, takes the instance CA from the connection inventory, keeps it
// and connects with it.
func TestPsqlDownloadsCAFromPortal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake psql and browser are bash scripts")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	writeTestCA(t, caPath)
	caPEM, _ := os.ReadFile(caPath)

	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/realm/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": srv.URL + "/realm/auth", "token_endpoint": srv.URL + "/realm/token"})
	})
	mux.HandleFunc("/realm/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "c1" || r.Form.Get("client_id") != "dev-01-portal-tui" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	mux.HandleFunc("/api/provisioning/connections", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"nextCursor": nil, "connections": []any{map[string]any{
			"id": "ocd-dev-01/tenant-demo-000001-postgresql/pgoidc01-pg/pgoidc01-pg-access", "tenantId": "demo",
			"engine": "postgresql", "instanceName": "pgoidc01",
			"sqlAuth": map[string]any{"mode": "postgresql-oauth", "caCertificate": string(caPEM)}}}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	proxy, _ := fakeConnectProxy(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	cfgDir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", cfgDir)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("clusters:\n  ocd-dev-01:\n"+
		"    pomeriumURL: http://"+proxy+"\n    issuer: "+srv.URL+"/realm\n    portalURL: "+srv.URL+"\n"), 0o600)
	bin := t.TempDir()
	_ = os.WriteFile(filepath.Join(bin, "psql"), []byte(fakePsql), 0o755)
	_ = os.WriteFile(filepath.Join(bin, "browser"), []byte(fakeBrowser), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCD_BROWSER", filepath.Join(bin, "browser"))
	argsFile := filepath.Join(t.TempDir(), "args")
	t.Setenv("FAKE_PSQL_ARGS", argsFile)
	t.Chdir(t.TempDir())

	if _, err := run(t, "psql", "--cluster", "ocd-dev-01", "demo-000001/pgoidc01"); err != nil {
		t.Fatalf("ocd psql: %v", err)
	}
	stored := filepath.Join(cfgDir, "postgres", "ocd-dev-01", "demo-000001", "pgoidc01-ca.crt")
	got, err := os.ReadFile(stored)
	if err != nil || string(got) != string(caPEM) {
		t.Fatalf("portal CA not kept: %v", err)
	}
	raw, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(raw), "sslrootcert="+stored) {
		t.Fatalf("psql not given the portal CA: %s", raw)
	}
}

// privateTestAddress returns a local RFC1918 IP for the integration test. Do
// not add addresses to any interface; skip on hosts without a private IP.
func privateTestAddress(t *testing.T) string {
	t.Helper()
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("local private interface unavailable: %v", err)
	}
	var ips []string
	for _, iface := range ifaces {
		addr, ok := iface.(*net.IPNet)
		if ok && addr.IP.To4() != nil && portal.PrivateIPv4(addr.IP.String()) {
			ips = append(ips, addr.IP.String())
		}
	}
	// Prefer VM bridge addresses so this test cannot listen on the host's
	// tenant VPN or publicly routed interface when both are present.
	sort.Slice(ips, func(i, j int) bool {
		return strings.HasPrefix(ips[i], "192.168.") && !strings.HasPrefix(ips[j], "192.168.")
	})
	for _, ip := range ips {
		ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
		if err == nil {
			ln.Close()
			return ip
		}
	}
	t.Skip("no locally bound private IPv4 interface for direct TCP test")
	return ""
}

// TestPsqlDirectFromInventory signs in, resolves the VPC IP from the portal
// connection descriptor and runs fake psql straight to a test listener with the same
// server name, CA and OAuth fields as the gateway path.
func TestPsqlDirectFromInventory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake psql and browser are bash scripts")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	privateIP := privateTestAddress(t)
	direct, err := net.Listen("tcp", net.JoinHostPort(privateIP, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	port := direct.Addr().(*net.TCPAddr).Port
	oldPort := postgresPort
	postgresPort = port
	defer func() { postgresPort = oldPort }()
	accepted := make(chan struct{}, 2)
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

	caPath := filepath.Join(t.TempDir(), "pgoidc01-ca.crt")
	writeTestCA(t, caPath)
	caPEM, _ := os.ReadFile(caPath)
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/realm/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": srv.URL + "/realm/auth", "token_endpoint": srv.URL + "/realm/token"})
	})
	mux.HandleFunc("/realm/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "c1" || r.Form.Get("client_id") != "dev-01-portal-tui" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "h." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix()))) + ".s"})
	})
	var fetches atomic.Int32
	mux.HandleFunc("/api/provisioning/connections", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer h.") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"nextCursor": nil, "connections": []any{map[string]any{
			"id": "ocd-dev-01/tenant-demo-000001-postgresql/pgoidc01-pg/pgoidc01-pg-access", "tenantId": "demo",
			"engine": "postgresql", "instanceName": "pgoidc01", "vpcAddress": privateIP,
			"sqlAuth": map[string]any{"mode": "postgresql-oauth", "caCertificate": string(caPEM)}}}})
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	cfgDir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", cfgDir)
	_ = os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("clusters:\n  ocd-dev-01:\n    issuer: "+srv.URL+"/realm\n    portalURL: "+srv.URL+"\n"), 0o600)
	bin := t.TempDir()
	_ = os.WriteFile(filepath.Join(bin, "psql"), []byte(fakePsql), 0o755)
	_ = os.WriteFile(filepath.Join(bin, "browser"), []byte(fakeBrowser), 0o755)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("OCD_BROWSER", filepath.Join(bin, "browser"))
	t.Setenv("FAKE_PSQL_ARGS", filepath.Join(t.TempDir(), "args"))
	t.Chdir(t.TempDir())
	if _, err := run(t, "psql", "--via", "auto", "--cluster", "ocd-dev-01", "demo-000001/pgoidc01", "--", "-c", "select 1"); err != nil {
		t.Fatalf("ocd psql direct: %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("first run inventory reads = %d, want 1", fetches.Load())
	}
	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("fake psql did not connect directly")
	}
	raw, err := os.ReadFile(os.Getenv("FAKE_PSQL_ARGS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"host=pgoidc01-pg-access.tenant-demo-000001-postgresql.svc hostaddr=" + privateIP + " port=",
		"oauth_issuer=https://auth.dev-01.onecloud.ldc.dz/realms/dev-01-portal oauth_client_id=dev-01-postgresql",
		"sslmode=verify-full sslrootcert=",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("direct psql %q lacks %q", raw, want)
		}
	}
	// Run again without a browser or network inventory: the cached VPC IP
	// and saved CA must be sufficient. A new ocd process reads the same file.
	t.Setenv("OCD_BROWSER", "none")
	srv.Close()
	t.Chdir(t.TempDir())
	if _, err := run(t, "psql", "--via", "auto", "--cluster", "ocd-dev-01", "demo-000001/pgoidc01"); err != nil {
		t.Fatalf("second direct psql run from address/CA cache: %v", err)
	}
	if fetches.Load() != 1 {
		t.Fatalf("second run fetched portal inventory %d times", fetches.Load())
	}
	raw, _ = os.ReadFile(os.Getenv("FAKE_PSQL_ARGS"))
	if !strings.Contains(string(raw), "hostaddr="+privateIP) {
		t.Fatalf("cached direct IP not used: %s", raw)
	}
}
