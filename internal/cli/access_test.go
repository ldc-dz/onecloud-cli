package cli

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/portalcache"
)

func TestAccessPath(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	for _, tc := range []struct {
		via, address, want string
		port               int
	}{
		{"auto", "127.0.0.1", "direct", port},
		{"auto", "", "proxied", port},
		{"auto", "not-an-ip", "proxied", port},
		{"auto", "127.0.0.2", "proxied", port},
		{"proxied", "127.0.0.1", "proxied", port},
		{"direct", "127.0.0.2", "direct", port}, // explicit mode does not probe
		// The portal's tenant-network SSH host name, for explicit direct only.
		{"direct", "vm-ssh.tenant-demo-000001.svc.cluster.local", "direct", port},
		{"auto", "vm-ssh.tenant-demo-000001.svc.cluster.local", "proxied", port},
	} {
		got, err := accessPath(tc.via, tc.address, tc.port)
		if err != nil || got != tc.want {
			t.Errorf("accessPath(%q, %q, %d) = %q, %v; want %s", tc.via, tc.address, tc.port, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ via, address, want string }{
		{"direct", "", "no tenant-network address"},
		{"direct", "http://evil.test:22", "invalid tenant-network address"},
		{"direct", "-oProxyCommand=sh", "invalid tenant-network address"},
		{"direct", "10.0.0.256", "invalid tenant-network address"},
		{"other", "127.0.0.1", "invalid --via"},
	} {
		if _, err := accessPath(tc.via, tc.address, port); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("accessPath(%q, %q) error = %v; want %q", tc.via, tc.address, err, tc.want)
		}
	}
}

func TestDoctorReportsVPNReachability(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	t.Setenv("OCD_VPN_PROBE_ADDRESS", "127.0.0.1")
	t.Setenv("OCD_VPN_PROBE_PORT", strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:"))
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	out, err := run(t, "doctor")
	if err == nil || !strings.Contains(out, "VPN reachability: 127.0.0.1:") || !strings.Contains(out, "accepts TCP") {
		t.Fatalf("doctor output = %q, err=%v", out, err)
	}
	_ = ln.Close()
	out, _ = run(t, "doctor")
	if !strings.Contains(out, "not reachable") || !strings.Contains(out, "OneCloud access gateway") {
		t.Fatalf("unreachable VPN target = %q", out)
	}
}

func TestCloudShellSkipsNativeLoopback(t *testing.T) {
	t.Setenv("OCD_CLOUD_SHELL", "1")
	if nativePortalAvailable() {
		t.Fatal("Cloud Shell must not try native loopback portal sign-in")
	}
	start := time.Now()
	out, err := accessPath("auto", "", 22)
	if err != nil || out != "proxied" || time.Since(start) >= directProbeTimeout {
		t.Fatalf("Cloud Shell fallback: path=%s err=%v", out, err)
	}
	if _, _, _, err := portalInventory(readyTestCluster(), false); err == nil || !strings.Contains(err.Error(), "Cloud Shell") {
		t.Fatalf("native portal must fail immediately in Cloud Shell: %v", err)
	}
}

func readyTestCluster() config.Cluster {
	return config.Cluster{PortalURL: "https://portal.example", PortalClientID: "portal-test"}
}

func TestCloudShellS3UsesPortalKeys(t *testing.T) {
	// The STS sign-in needs a local browser; the Shell reveals the portal keys.
	cl := config.Cluster{S3SSOEndpoint: "https://s3-sso.example"}
	t.Setenv("OCD_CLOUD_SHELL", "")
	if !useS3SSO(cl) {
		t.Fatal("workstation must use the OneCloud sign-in by default")
	}
	t.Setenv("OCD_CLOUD_SHELL", "1")
	if useS3SSO(cl) {
		t.Fatal("Cloud Shell must not start the loopback STS sign-in")
	}
}

func TestHeadlessPortalSkipsWithoutToken(t *testing.T) {
	t.Setenv("OCD_CLOUD_SHELL", "")
	t.Setenv("OCD_BROWSER", "")
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	cl := readyTestCluster()
	start := time.Now()
	_, _, _, err := portalInventory(cl, false)
	if err != errPortalNonInteractive || time.Since(start) > 200*time.Millisecond {
		t.Fatalf("headless portal lookup: %v; elapsed %s", err, time.Since(start))
	}
}

func TestPortalCacheReadsPrivateTenantAddressWithoutBrowser(t *testing.T) {
	t.Setenv("OCD_CLOUD_SHELL", "1")
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	cl := config.Cluster{Name: "ocd-dev-01", Issuer: "https://auth.example/realms/x", PortalURL: "https://portal.example", PortalClientID: "test-client"}
	store := portalcache.Store{Dir: dir}
	jwt := "h." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix()))) + ".s"
	if err := store.SaveToken(cl, jwt); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAddress(cl, jwt, "vm", "demo-000001", "vm1", "10.20.30.40"); err != nil {
		t.Fatal(err)
	}
	address, _, err := portalVPC(cl, "vm", "demo-000001", "vm1", false, false)
	if err != nil || address != "10.20.30.40" {
		t.Fatalf("cached VM address %q, %v", address, err)
	}
	for _, tuple := range [][3]string{{"vm", "other-000001", "vm1"}, {"postgresql", "demo-000001", "vm1"}, {"vm", "demo-000001", "vm2"}} {
		address, err := store.Address(cl, tuple[0], tuple[1], tuple[2])
		if err != nil || address != "" {
			t.Fatalf("cross-tenant/engine/instance cached IP = %q, %v", address, err)
		}
	}
	// The on-disk file must not be readable by another OS user.
	files, err := filepath.Glob(filepath.Join(dir, "portal", "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("cache path %v, %v", files, err)
	}
	info, err := os.Stat(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file mode %v, want 0600", info.Mode())
	}
	directory, err := os.Stat(filepath.Dir(files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("cache directory mode %v, want 0700", directory.Mode())
	}
}

func TestInvalidGlobalVia(t *testing.T) {
	for _, cmd := range []string{"version", "ssh", "psql"} {
		args := []string{"--via", "unsafe", cmd}
		if cmd != "version" {
			args = append(args, "demo-000001/service")
		}
		_, err := run(t, args...)
		if err == nil || !strings.Contains(err.Error(), "invalid --via") {
			t.Fatalf("%s accepted invalid --via: %v", cmd, err)
		}
	}
}
