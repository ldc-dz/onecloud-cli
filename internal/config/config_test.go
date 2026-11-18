package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinDefaultIsPrd(t *testing.T) {
	c := Builtin().Merge(Config{})
	cl, err := c.Cluster("")
	if err != nil {
		t.Fatal(err)
	}
	if cl.Name != "ocd-prd-01" || cl.Provider() != "https://auth.onecloud.dz/realms/prd-01-portal,onecloud-ssh" {
		t.Fatalf("unexpected default cluster %+v", cl)
	}
	if cl.PortalURL != "https://portal.onecloud.dz" || cl.PortalClientID != "prd-01-portal-tui" {
		t.Fatalf("unexpected prd portal settings %+v", cl)
	}
	dev, err := c.Cluster("ocd-dev-01")
	if err != nil || dev.Provider() != "https://auth.dev-01.onecloud.ldc.dz/realms/dev-01-portal,onecloud-ssh" {
		t.Fatalf("dev must stay reachable with --cluster: %+v %v", dev, err)
	}
}

func TestPrdSSHAndPostgres(t *testing.T) {
	prd, err := Builtin().Merge(Config{}).Cluster("ocd-prd-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := prd.SSHAvailable(); err != nil {
		t.Fatalf("want VM SSH on prd, got %v", err)
	}
	if prd.Provider() != "https://auth.onecloud.dz/realms/prd-01-portal,onecloud-ssh" {
		t.Fatalf("unexpected prd provider %q", prd.Provider())
	}
	o, _ := Parse([]byte("clusters:\n  ocd-prd-01:\n    ssh: false\n    sshReason: paused\n"))
	off, _ := Builtin().Merge(o).Cluster("ocd-prd-01")
	if err := off.SSHAvailable(); err == nil || !strings.Contains(err.Error(), "paused") {
		t.Fatalf("want ssh: false override to refuse, got %v", err)
	}
	if err := prd.PostgresAvailable(); err != nil {
		t.Fatal(err)
	}
	if prd.PomeriumURL != "https://access.onecloud.ldc.dz:8443" || prd.PostgresClientID != "prd-01-postgresql" {
		t.Fatalf("unexpected prd postgres settings %+v", prd)
	}
	dev, _ := Builtin().Merge(Config{}).Cluster("ocd-dev-01")
	if dev.SSHAvailable() != nil || dev.PomeriumURL != "" || dev.PostgresClientID != "dev-01-postgresql" {
		t.Fatalf("unexpected dev settings %+v", dev)
	}
}

func TestCloudShellUsesShellPortalClient(t *testing.T) {
	// UAT 2026-11 (OneCloud #2754): in OneCloud Shell the portal session is
	// written by the Shell broker and issued to the Shell client.
	t.Setenv("OCD_CLOUD_SHELL", "")
	prd, err := Builtin().Merge(Config{}).Cluster("ocd-prd-01")
	if err != nil || prd.PortalClientID != "prd-01-portal-tui" || prd.ShellClientID != "prd-01-shell" {
		t.Fatalf("workstation prd portal client %+v %v", prd, err)
	}
	t.Setenv("OCD_CLOUD_SHELL", "1")
	for name, want := range map[string]string{"ocd-prd-01": "prd-01-shell", "ocd-dev-01": "dev-01-shell"} {
		cl, err := Builtin().Merge(Config{}).Cluster(name)
		if err != nil || cl.PortalClientID != want {
			t.Fatalf("%s in Cloud Shell: portal client %q, %v", name, cl.PortalClientID, err)
		}
	}
	o, _ := Parse([]byte("clusters:\n  ocd-prd-01:\n    shellClientID: other-shell\n"))
	cl, _ := Builtin().Merge(o).Cluster("ocd-prd-01")
	if cl.PortalClientID != "other-shell" {
		t.Fatalf("shellClientID override: %q", cl.PortalClientID)
	}
}

func TestDisabledClusterRefused(t *testing.T) {
	o, _ := Parse([]byte("clusters:\n  ocd-prd-01:\n    enabled: false\n    reason: maintenance\n"))
	_, err := Builtin().Merge(o).Cluster("ocd-prd-01")
	if err == nil || !strings.Contains(err.Error(), "maintenance") {
		t.Fatalf("want disabled error, got %v", err)
	}
}

func TestOverrideSSHGate(t *testing.T) {
	o, _ := Parse([]byte("clusters:\n  ocd-prd-01:\n    ssh: true\n"))
	prd, err := Builtin().Merge(o).Cluster("ocd-prd-01")
	if err != nil || prd.SSHAvailable() != nil {
		t.Fatalf("ssh override not applied: %v %v", err, prd.SSHAvailable())
	}
}

func TestOverrideMergesFieldByField(t *testing.T) {
	o, err := Parse([]byte("defaultCluster: ocd-prd-01\nclusters:\n  ocd-prd-01:\n    enabled: true\n  lab:\n    enabled: true\n    issuer: https://kc/realms/x\n    clientID: c\n    tcpDomain: tcp.lab\n"))
	if err != nil {
		t.Fatal(err)
	}
	c := Builtin().Merge(o)
	prd, err := c.Cluster("")
	if err != nil {
		t.Fatal(err)
	}
	if prd.Name != "ocd-prd-01" || prd.TCPDomain != "tcp.access.onecloud.ldc.dz" {
		t.Fatalf("builtin fields lost: %+v", prd)
	}
	if _, err := c.Cluster("lab"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Cluster("nope"); err == nil {
		t.Fatal("unknown cluster accepted")
	}
}

func TestIncompleteClusterRejected(t *testing.T) {
	o, _ := Parse([]byte("clusters:\n  half:\n    enabled: true\n    issuer: https://kc\n"))
	if _, err := Builtin().Merge(o).Cluster("half"); err == nil {
		t.Fatal("incomplete cluster accepted")
	}
}

func TestLoadReadsOverrideFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("clusters:\n  ocd-dev-01:\n    tcpDomain: tcp.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Clusters["ocd-dev-01"].TCPDomain; got != "tcp.example" {
		t.Fatalf("override not applied: %s", got)
	}
}

func TestLoadBadYAML(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OCD_CONFIG_DIR", dir)
	_ = os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("clusters: ["), 0o600)
	if _, err := Load(); err == nil {
		t.Fatal("bad yaml accepted")
	}
}

func TestClusterRefusesPlainHTTPEndpoints(t *testing.T) {
	for _, doc := range []string{
		"clusters:\n  ocd-prd-01:\n    issuer: http://auth.example/realms/x\n",
		"clusters:\n  ocd-prd-01:\n    portalURL: http://portal.example\n",
		"clusters:\n  ocd-prd-01:\n    postgresIssuer: ftp://auth.example\n",
		"clusters:\n  ocd-prd-01:\n    pomeriumURL: http://access.example:8443\n",
		"clusters:\n  ocd-prd-01:\n    pomeriumURL: https://access.example:8443/x;id\n",
		"clusters:\n  ocd-prd-01:\n    pomeriumURL: https://u:p@access.example\n",
	} {
		o, err := Parse([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Builtin().Merge(o).Cluster("ocd-prd-01"); err == nil {
			t.Errorf("accepted: %s", doc)
		}
	}
	o, _ := Parse([]byte("clusters:\n  ocd-prd-01:\n    issuer: http://127.0.0.1:8080/realm\n    pomeriumURL: http://[::1]:9000\n"))
	if _, err := Builtin().Merge(o).Cluster("ocd-prd-01"); err != nil {
		t.Fatalf("loopback http refused: %v", err)
	}
}
