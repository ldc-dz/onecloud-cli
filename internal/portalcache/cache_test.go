package portalcache

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/config"
)

func token(exp time.Time, subject string) string {
	payload := fmt.Sprintf(`{"exp":%d,"sub":%q}`, exp.Unix(), subject)
	return "header." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".signature"
}

func cluster() config.Cluster {
	return config.Cluster{Name: "ocd-dev-01", Issuer: "https://issuer.example/realms/dev", PortalClientID: "client1", PortalURL: "https://portal.example"}
}

func TestSessionAndAddressExpiryAndScoping(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	s := Store{Dir: t.TempDir(), Now: func() time.Time { return now }}
	cl := cluster()
	first := token(now.Add(time.Hour), "member-a")
	if err := s.SaveToken(cl, first); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveAddress(cl, first, "vm", "demo-000001", "ubuntu01", "10.20.30.40"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Token(cl); err != nil || got != first {
		t.Fatalf("saved token %q, %v", got, err)
	}
	if got, err := s.Address(cl, "vm", "demo-000001", "ubuntu01"); err != nil || got != "10.20.30.40" {
		t.Fatalf("saved address %q, %v", got, err)
	}
	for _, tc := range [][3]string{{"vm", "other-000001", "ubuntu01"}, {"postgresql", "demo-000001", "ubuntu01"}, {"vm", "demo-000001", "ubuntu02"}} {
		if got, err := s.Address(cl, tc[0], tc[1], tc[2]); err != nil || got != "" {
			t.Fatalf("cross-scope leak %v: %q, %v", tc, got, err)
		}
	}
	other := cl
	other.PortalClientID = "client2"
	if got, err := s.Token(other); err != nil || got != "" {
		t.Fatalf("other client reused portal bearer: %q, %v", got, err)
	}
	other = cl
	other.Issuer = "https://issuer.example/realms/other"
	if got, err := s.Token(other); err != nil || got != "" {
		t.Fatalf("other issuer reused portal bearer: %q, %v", got, err)
	}
	now = now.Add(AddressTTL + time.Second)
	if got, err := s.Address(cl, "vm", "demo-000001", "ubuntu01"); err != nil || got != "" {
		t.Fatalf("stale address %q, %v", got, err)
	}
	if got, err := s.Token(cl); err != nil || got != first {
		t.Fatalf("bearer expired before exp: %q, %v", got, err)
	}
	if err := s.SaveAddress(cl, "other-bearer", "vm", "demo-000001", "ubuntu01", "10.0.0.4"); err == nil {
		t.Fatal("address cached under wrong bearer")
	}
	second := token(now.Add(time.Hour), "member-b")
	if err := s.SaveToken(cl, second); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Address(cl, "vm", "demo-000001", "ubuntu01"); err != nil || got != "" {
		t.Fatalf("previous member's address reused: %q, %v", got, err)
	}
	now = now.Add(61 * time.Minute)
	if got, err := s.Token(cl); err != nil || got != "" {
		t.Fatalf("expired bearer returned: %q, %v", got, err)
	}
}

func TestPortalCacheProtectsPermissionsAndAddresses(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	cl := cluster()
	jwt := token(time.Now().Add(time.Hour), "member-a")
	if err := s.SaveToken(cl, jwt); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"8.8.8.8", "127.0.0.1", "100.128.0.1", "fd00::1"} {
		if err := s.SaveAddress(cl, jwt, "vm", "demo-000001", "vm1", bad); err == nil {
			t.Errorf("cached invalid portal address %s", bad)
		}
	}
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	info, err := os.Stat(s.path(cl))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("cache file permissions %v: %v", info, err)
	}
	dir, err := os.Stat(filepath.Dir(s.path(cl)))
	if err != nil || dir.Mode().Perm() != 0o700 {
		t.Fatalf("cache directory permissions %v: %v", dir, err)
	}
	if err := os.Chmod(s.path(cl), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Token(cl); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("world-readable bearer was accepted: %v", err)
	}
	if err := s.SaveToken(cl, jwt); err == nil {
		t.Fatal("overwrote unsafe cache")
	}
	if err := os.Remove(s.path(cl)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", s.path(cl)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Token(cl); err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("symlink cache was accepted: %v", err)
	}
	if err := s.Clear(cl); err == nil {
		t.Fatal("followed or overwrote cache symlink")
	}
}
