package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := NewRoot()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestVersion(t *testing.T) {
	out, err := run(t, "version")
	if err != nil || !strings.HasPrefix(out, "ocd dev") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestPublicHelpAndVersionUseOneCloudTerminology(t *testing.T) {
	for _, command := range [][]string{{"--help"}, {"login", "--help"}, {"ssh", "--help"}, {"psql", "--help"}, {"tunnel", "--help"}, {"version"}} {
		out, err := run(t, command...)
		if err != nil {
			t.Fatalf("ocd %v: %v", command, err)
		}
		if strings.Contains(strings.ToLower(out), "pomerium") {
			t.Fatalf("ocd %v exposes vendor term: %s", command, out)
		}
	}
	out, err := run(t, "tunnel", "--help")
	if err != nil || !strings.Contains(out, "--gateway-url") {
		t.Fatalf("gateway flag missing from public help: %q, %v", out, err)
	}
}

func TestConfigShowIncludesClusters(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	out, err := run(t, "config", "show")
	if err != nil || !strings.Contains(out, "ocd-dev-01") || !strings.Contains(out, "ocd-prd-01") {
		t.Fatalf("%q %v", out, err)
	}
}

func TestSSHRefusesDisabledCluster(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("clusters:\n  ocd-prd-01:\n    enabled: false\n    reason: not available here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := run(t, "ssh", "--cluster", "ocd-prd-01", "demo-000001/vmsso")
	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("want disabled cluster error, got %v", err)
	}
}

func TestSSHRejectsBadTarget(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	_, err := run(t, "ssh", "vmsso")
	if err == nil || !strings.Contains(err.Error(), "<tenant>/<vm>") {
		t.Fatalf("got %v", err)
	}
}

func TestDoctorReportsNotSignedIn(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	out, err := run(t, "doctor")
	if err == nil || !strings.Contains(out, "not signed in") {
		t.Fatalf("%q %v", out, err)
	}
}
