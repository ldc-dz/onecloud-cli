package cli

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/browser"
)

// fakeGateway is a plain-HTTP access-gateway stand-in with a sign-in: a
// CONNECT without the session answers 302, /.pomerium/api/v1/login returns
// the sign-in address, and a CONNECT carrying the session gets connectStatus
// (200 echoes the tunnelled bytes back).
type fakeGateway struct {
	addr          string
	connectStatus atomic.Int32
	connects      atomic.Int32 // CONNECT requests carrying the session
}

const fakeGatewaySession = "session-from-fake-gateway"

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	g := &fakeGateway{addr: ln.Addr().String()}
	g.connectStatus.Store(http.StatusOK)
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
				if err != nil {
					return
				}
				if req.Method == http.MethodGet && req.URL.Path == "/.pomerium/api/v1/login" {
					body := "http://" + g.addr + "/.pomerium/sign_in?pomerium_redirect_uri=" +
						url.QueryEscape(req.URL.Query().Get("pomerium_redirect_uri"))
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "+
						itoa(len(body))+"\r\n\r\n"+body)
					return
				}
				if req.Method != http.MethodConnect {
					_, _ = io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
					return
				}
				if req.Header.Get("Authorization") != "Pomerium "+fakeGatewaySession {
					_, _ = io.WriteString(c, "HTTP/1.1 302 Found\r\nLocation: /.pomerium/\r\nContent-Length: 0\r\n\r\n")
					return
				}
				g.connects.Add(1)
				status := int(g.connectStatus.Load())
				if status != http.StatusOK {
					_, _ = io.WriteString(c, "HTTP/1.1 "+itoa(status)+" "+http.StatusText(status)+"\r\nContent-Length: 0\r\n\r\n")
					return
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				_, _ = io.Copy(c, br)
			}(c)
		}
	}()
	return g
}

func itoa(n int) string { return strconv.Itoa(n) }

// gatewayTestEnv isolates the gateway session cache and ocd config, makes
// the tunnel's browser command a program that fails the way ocd's own helper
// did on a machine without a browser, and captures what ocd prints.
func gatewayTestEnv(t *testing.T) (stderr func() string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake browser command is a shell script")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	t.Setenv(VerboseEnv, "")
	// pomerium-cli runs `<self> <url>` as its browser command. Under test,
	// self would be the test binary, so a script stands in for the ocd
	// helper, which only acknowledges the call (see
	// TestBrowserHelperAcknowledgesWhenBrowserDisabled for the real one).
	helper := filepath.Join(t.TempDir(), "ocd-helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	old, oldTimeout := selfExecutable, gatewayCheckTimeout
	selfExecutable = func() (string, error) { return helper, nil }
	// A sign-in nobody completes must fail the test, not hang it.
	gatewayCheckTimeout = 15 * time.Second
	t.Cleanup(func() { selfExecutable, gatewayCheckTimeout = old, oldTimeout })

	out := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = f
	t.Cleanup(func() { os.Stderr = orig; f.Close() })
	return func() string {
		raw, _ := os.ReadFile(out)
		return string(raw)
	}
}

var signInAddress = regexp.MustCompile(`open this address in your browser: (http://\S+)`)

// completeSignIn plays the user: it waits for the address ocd prints, then
// ends the sign-in the way the gateway does, by sending the session to the
// loopback address named in it.
func completeSignIn(t *testing.T, stderr func() string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m := signInAddress.FindStringSubmatch(stderr()); m != nil {
			u, err := url.Parse(m[1])
			if err != nil {
				t.Errorf("printed sign-in address is not a URL: %q", m[1])
				return
			}
			resp, err := http.Get(u.Query().Get("pomerium_redirect_uri") + "?pomerium_jwt=" + fakeGatewaySession)
			if err != nil {
				t.Errorf("the sign-in callback was gone when the user finished signing in: %v", err)
				return
			}
			resp.Body.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("ocd printed no access-gateway sign-in address; it printed:\n%s", stderr())
}

// UAT 2026-11 CH-PORTAL-02 (WSL, no browser opener): the gateway sign-in
// address was never shown and the tunnel dropped the client at once, which
// only saw "Connection reset by peer". ocd must print the address, wait for
// the sign-in, and only then hand a working local port to the client.
func TestGatewayTunnelPrintsSignInAddressWithoutBrowser(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) bool{
		// OCD_BROWSER=none: ocd is told to print only.
		"OCD_BROWSER=none": func(t *testing.T) bool { t.Setenv(browser.EnvCommand, "none"); return false },
		// --no-browser on the command.
		"--no-browser": func(t *testing.T) bool { t.Setenv(browser.EnvCommand, ""); return true },
		// No opener on the machine (WSL without wslu, a server): the
		// configured command cannot be started.
		"no opener": func(t *testing.T) bool {
			t.Setenv(browser.EnvCommand, filepath.Join(t.TempDir(), "no-such-browser"))
			return false
		},
	} {
		t.Run(name, func(t *testing.T) {
			stderr := gatewayTestEnv(t)
			noBrowser := setup(t)
			gw := newFakeGateway(t)
			go completeSignIn(t, stderr)

			tun, err := openGatewayTunnel("demo-000001/ch01", "ch01-ch-000001.tcp.example", "http://"+gw.addr, 0, noBrowser)
			if err != nil {
				t.Fatalf("the tunnel must open once the user has signed in: %v\nstderr:\n%s", err, stderr())
			}
			defer tun.Close()
			if !strings.Contains(stderr(), "ch01-ch-000001.tcp.example:443") {
				t.Errorf("the notice must say what is being authorized:\n%s", stderr())
			}
			// The native client's connection reuses the session: no second
			// sign-in, and bytes go through.
			c, err := net.Dial("tcp", "127.0.0.1:"+itoa(tun.Port()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.WriteString(c, "ping"); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("client connection through the tunnel: %q, %v\nstderr:\n%s", buf, err, stderr())
			}
			if n := strings.Count(stderr(), "open this address in your browser"); n != 1 {
				t.Errorf("sign-in asked %d times, want once:\n%s", n, stderr())
			}
		})
	}
}

// A gateway refusal must reach the user as an ocd message before the native
// client starts, not as a reset inside the client.
func TestGatewayTunnelExplainsRefusals(t *testing.T) {
	for status, want := range map[int]string{
		http.StatusForbidden:          "refused demo-000001/ch01 for your account (403)",
		http.StatusServiceUnavailable: "cannot reach demo-000001/ch01 (503)",
		http.StatusNotFound:           "has no route to demo-000001/ch01 yet (404",
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			stderr := gatewayTestEnv(t)
			t.Setenv(browser.EnvCommand, "none")
			gw := newFakeGateway(t)
			gw.connectStatus.Store(int32(status))
			go completeSignIn(t, stderr)
			tun, err := openGatewayTunnel("demo-000001/ch01", "ch01-ch-000001.tcp.example", "http://"+gw.addr, 0, false)
			if err == nil {
				tun.Close()
				t.Fatal("a refused destination must not yield a tunnel")
			}
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("got %q, want it to contain %q", err, want)
			}
			if strings.Contains(strings.ToLower(err.Error()), "pomerium") {
				t.Fatalf("vendor term in a user message: %v", err)
			}
		})
	}
}

func TestGatewayTunnelExplainsUnreachableGateway(t *testing.T) {
	gatewayTestEnv(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // nothing listens there any more
	_, err = openGatewayTunnel("demo-000001/ch01", "ch01-ch-000001.tcp.example", "http://"+addr, 0, false)
	if err == nil || !strings.Contains(err.Error(), "cannot reach the OneCloud access gateway for demo-000001/ch01") {
		t.Fatalf("got %v", err)
	}
}

// A connection that fails after the pre-check (session revoked meanwhile)
// is still explained on stderr by the tunnel server.
func TestTunnelServerReportsLaterFailure(t *testing.T) {
	stderr := gatewayTestEnv(t)
	t.Setenv(browser.EnvCommand, "none")
	gw := newFakeGateway(t)
	go completeSignIn(t, stderr)
	tun, err := openGatewayTunnel("demo-000001/ch01", "ch01-ch-000001.tcp.example", "http://"+gw.addr, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	gw.connectStatus.Store(http.StatusForbidden)
	c, err := net.Dial("tcp", "127.0.0.1:"+itoa(tun.Port()))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.ReadAll(c) // closed by the tunnel server
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(stderr(), "refused demo-000001/ch01 for your account (403)") {
		if time.Now().After(deadline) {
			t.Fatalf("the dropped connection was not explained:\n%s", stderr())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// pomerium-cli abandons the sign-in when its browser command fails. ocd's
// helper used to fail with OCD_BROWSER=none; it must only acknowledge.
func TestBrowserHelperAcknowledgesWhenBrowserDisabled(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	t.Setenv(browser.HelperEnv, "1")
	for _, cmd := range []string{"none", filepath.Join(t.TempDir(), "no-such-browser")} {
		t.Setenv(browser.EnvCommand, cmd)
		if code := Main([]string{"https://access.example/.pomerium/sign_in?x=1"}); code != 0 {
			t.Fatalf("OCD_BROWSER=%s: helper exit code %d would make the gateway sign-in fail", cmd, code)
		}
	}
}

func TestSQLCommandsHaveNoBrowserFlag(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	for _, cmd := range []string{"clickhouse", "mssql"} {
		out, err := run(t, cmd, "--help")
		if err != nil || !strings.Contains(out, "--no-browser") {
			t.Errorf("ocd %s --help lacks --no-browser: %v", cmd, err)
		}
	}
}

// UAT 2026-11 CH-PORTAL-02 (Windows): a third-party client renamed to
// clickhouse-client must be refused before the portal sign-in, the password
// reveal and the tunnel; a missing client likewise.
func TestClickHouseRefusesWrongOrMissingClientBeforeSignIn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake client is a shell script")
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfgDir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", cfgDir)
	t.Setenv("HOME", t.TempDir())
	if err := os.WriteFile(filepath.Join(cfgDir, "config.yaml"), []byte("clusters:\n  ocd-dev-01:\n"+
		"    issuer: "+srv.URL+"/realm\n    portalURL: "+srv.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	_, err := run(t, "clickhouse", "--cluster", "ocd-dev-01", "demo-000001/ch01")
	if err == nil || !strings.Contains(err.Error(), "clickhouse-client not found on PATH") {
		t.Fatalf("missing client: got %v", err)
	}
	fake := filepath.Join(bin, "clickhouse-client")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho 'chcli 0.2.0'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = run(t, "clickhouse", "--cluster", "ocd-dev-01", "demo-000001/ch01")
	if err == nil || !strings.Contains(err.Error(), fake+" is not the official ClickHouse client") || !strings.Contains(err.Error(), `"chcli 0.2.0"`) {
		t.Fatalf("look-alike client: got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("%d portal or sign-in requests were made before the client check", hits.Load())
	}
}
