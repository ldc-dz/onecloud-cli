package services

import (
	"errors"
	"testing"

	"github.com/ldc-dz/onecloud-cli/internal/portal"
)

func inst(id, tenant, cluster, service, name string, status portal.Status) portal.CatalogInstance {
	return portal.CatalogInstance{ID: id, Tenant: tenant, Cluster: cluster, Service: service, InstanceName: name, Status: status}
}

var catalog = []portal.CatalogInstance{
	inst("1", "demo-000001", "ocd-dev-01", "postgresql", "db", portal.StatusReady),
	inst("2", "other-000002", "ocd-dev-01", "postgresql", "db", portal.StatusReady),
	inst("3", "demo-000001", "ocd-prd-01", "postgresql", "db", portal.StatusReady),
	inst("4", "demo-000001", "ocd-dev-01", "mssql", "sql01", portal.StatusDegraded),
	inst("5", "demo-000001", "ocd-dev-01", "clickhouse", "ch01", portal.StatusPROpen),
	inst("6", "demo-000001", "ocd-dev-01", "s3", "bucket", portal.StatusReady),
	inst("7", "demo-000001", "ocd-dev-01", "vm", "bucket", portal.StatusReady),
	inst("8", "demo-000001", "ocd-dev-01", "kafka", "k", portal.StatusReady),
}

func TestKindOf(t *testing.T) {
	for in, want := range map[string]Kind{"postgresql": Postgres, "PG": Postgres, "sqlserver": MSSQL, "clickhouse": ClickHouse, "object-storage": ObjectStorage, "vm": VM} {
		if got, ok := KindOf(in); !ok || got != want {
			t.Errorf("KindOf(%q) = %q %v", in, got, ok)
		}
	}
	if _, ok := KindOf("kafka"); ok {
		t.Fatal("unknown service mapped")
	}
	if Postgres.Engine() != "postgresql" || ObjectStorage.Label() == "" {
		t.Fatal("engine/label")
	}
}

func TestTenantMatches(t *testing.T) {
	for _, c := range []struct {
		ledger, typed string
		want          bool
	}{
		{"demo-000001", "demo-000001", true}, {"demo-000001", "000001", true},
		{"demo-000001", "demo", false}, {"demo-000001", "00001", false},
		{"xdemo-000001", "demo-000001", false}, {"", "", false}, {"demo-a00001", "a00001", false},
	} {
		if got := TenantMatches(c.ledger, c.typed); got != c.want {
			t.Errorf("TenantMatches(%q,%q) = %v", c.ledger, c.typed, got)
		}
	}
}

func TestListScopesAndSorts(t *testing.T) {
	got := List(catalog, "ocd-dev-01", "000001")
	if len(got) != 5 {
		t.Fatalf("list = %+v", got)
	}
	if got[0].Instance.InstanceName != "bucket" || got[0].Kind != ObjectStorage || got[1].Kind != VM {
		t.Fatalf("order = %+v", got)
	}
	if dbs := List(catalog, "ocd-dev-01", "", Postgres); len(dbs) != 2 {
		t.Fatalf("all tenants pg = %+v", dbs)
	}
	if got[2].Describe() == "" || got[2].Target() != "demo-000001/ch01" {
		t.Fatalf("describe %q", got[2].Target())
	}
}

func TestResolve(t *testing.T) {
	e, err := Resolve(catalog, "ocd-dev-01", "demo-000001", "db", Postgres)
	if err != nil || e.Instance.ID != "1" {
		t.Fatalf("pg = %+v, %v", e, err)
	}
	if e, err := Resolve(catalog, "ocd-dev-01", "000001", "sql01", ""); err != nil || e.Kind != MSSQL {
		t.Fatalf("degraded mssql must resolve: %+v %v", e, err)
	}
	if e, err := Resolve(catalog, "ocd-dev-01", "demo-000001", "ch01", ClickHouse); !errors.Is(err, ErrNotReady) || e.Instance.ID != "5" {
		t.Fatalf("pending = %+v %v", e, err)
	}
	if _, err := Resolve(catalog, "ocd-dev-01", "demo-000001", "bucket", ""); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous = %v", err)
	}
	if e, err := Resolve(catalog, "ocd-dev-01", "demo-000001", "bucket", ObjectStorage); err != nil || e.Instance.ID != "6" {
		t.Fatalf("s3 = %+v %v", e, err)
	}
	if _, err := Resolve(catalog, "ocd-dev-01", "demo-000001", "sql01", Postgres); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("wrong kind = %v", err)
	}
	for _, c := range [][3]string{
		{"ocd-dev-01", "third-000003", "db"}, {"ocd-test", "demo-000001", "db"},
		{"ocd-dev-01", "demo-000001", "k"}, {"ocd-dev-01", "demo", "db"},
	} {
		if _, err := Resolve(catalog, c[0], c[1], c[2], ""); !errors.Is(err, ErrNotFound) {
			t.Errorf("Resolve%v = %v, want ErrNotFound", c, err)
		}
	}
}
