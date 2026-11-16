package target

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	for in, host := range map[string]string{
		"demo-000001/vmsso": "vmsso-ssh-000001.tcp.x",
		"000001/vmsso":      "vmsso-ssh-000001.tcp.x",
		"ss-000123/db-01":   "db-01-ssh-000123.tcp.x",
	} {
		tg, err := Parse(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := tg.Host("tcp.x"); got != host {
			t.Fatalf("%s: host %s, want %s", in, got, host)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "vmsso", "demo/vmsso", "demo-000001/", "demo-000001/Bad", "demo-000001/a/b", "demo-1/vm", "x;rm/vm"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestParseInstancePostgresNames(t *testing.T) {
	tg, err := ParseInstance("demo-000001/pgoidc01")
	if err != nil {
		t.Fatal(err)
	}
	if got := tg.PostgresHost("tcp.access.onecloud.ldc.dz"); got != "pgoidc01-pg-000001.tcp.access.onecloud.ldc.dz" {
		t.Fatalf("route host %s", got)
	}
	if got := tg.PostgresServerName(); got != "pgoidc01-pg-access.tenant-demo-000001-postgresql.svc" {
		t.Fatalf("server name %s", got)
	}
	tg, err = ParseInstance("acme-corp-000042/db")
	if err != nil || tg.Slug() != "acme-corp" || tg.PostgresServerName() != "db-pg-access.tenant-acme-corp-000042-postgresql.svc" {
		t.Fatalf("multi-word slug: %+v %v", tg, err)
	}
}

func TestParseInstanceNeedsSlug(t *testing.T) {
	_, err := ParseInstance("000001/pgoidc01")
	if err == nil || !strings.Contains(err.Error(), "demo-000001") && !strings.Contains(err.Error(), "full tenant name") {
		t.Fatalf("bare tenant id accepted: %v", err)
	}
	if _, err := ParseInstance("pgoidc01"); err == nil || !strings.Contains(err.Error(), "<tenant>/<instance>") {
		t.Fatalf("got %v", err)
	}
}
