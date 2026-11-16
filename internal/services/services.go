// Package services maps portal catalog instances to the managed service
// kinds ocd connects to (PostgreSQL, SQL Server, ClickHouse, S3 object
// storage, VMs) and resolves a <tenant>/<instance> target against the
// signed-in user's catalog. It is pure: no network, no shell, no files.
package services

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/ldc-dz/onecloud-cli/internal/portal"
)

// Kind is a managed service family.
type Kind string

// Supported kinds. The value is the canonical portal service id.
const (
	Postgres      Kind = "postgresql"
	MSSQL         Kind = "mssql"
	ClickHouse    Kind = "clickhouse"
	ObjectStorage Kind = "s3"
	VM            Kind = "vm"
)

// Kinds lists every supported kind in display order.
var Kinds = []Kind{Postgres, MSSQL, ClickHouse, ObjectStorage, VM}

// aliases maps portal service ids (and user spellings) to a kind. Unknown
// services are never guessed: they map to no kind.
var aliases = map[string]Kind{
	"postgresql": Postgres, "postgres": Postgres, "pg": Postgres,
	"mssql": MSSQL, "sqlserver": MSSQL, "sql-server": MSSQL,
	"clickhouse": ClickHouse,
	"s3":         ObjectStorage, "object-storage": ObjectStorage, "objectstorage": ObjectStorage,
	"vm": VM,
}

// KindOf returns the kind of a portal service id or user spelling.
func KindOf(service string) (Kind, bool) {
	k, ok := aliases[strings.ToLower(strings.TrimSpace(service))]
	return k, ok
}

// Label is the human name of a kind.
func (k Kind) Label() string {
	switch k {
	case Postgres:
		return "PostgreSQL"
	case MSSQL:
		return "SQL Server"
	case ClickHouse:
		return "ClickHouse"
	case ObjectStorage:
		return "Object storage (S3)"
	case VM:
		return "Virtual machine"
	}
	return string(k)
}

// Engine is the engine name of the kind in the portal connection inventory
// (portal.Connection.Engine), as used by portal.FindVPCAddress.
func (k Kind) Engine() string { return string(k) }

// Errors returned by Resolve. Callers match them with errors.Is.
var (
	ErrNotFound  = errors.New("no such instance in your portal services")
	ErrAmbiguous = errors.New("several services share this instance name")
	ErrNotReady  = errors.New("the instance is not ready")
	ErrWrongKind = errors.New("the instance is not of the requested service")
)

// TenantMatches reports whether the ledger tenant ("<slug>-<6 digits>")
// matches what the user typed: the full name, or the bare six-digit id.
func TenantMatches(ledgerTenant, typed string) bool {
	if ledgerTenant == "" || typed == "" {
		return false
	}
	return ledgerTenant == typed || (len(typed) == 6 && isDigits(typed) && strings.HasSuffix(ledgerTenant, "-"+typed))
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// Entry is a catalog instance with its resolved kind.
type Entry struct {
	Kind     Kind
	Instance portal.CatalogInstance
}

// Target returns "<tenant>/<instance>" as ocd commands accept it.
func (e Entry) Target() string { return e.Instance.Tenant + "/" + e.Instance.InstanceName }

// Ready reports whether the instance is deployed.
func (e Entry) Ready() bool { return e.Instance.Ready() }

// Describe is a one-line, secret-free summary for lists and selectors.
func (e Entry) Describe() string {
	return fmt.Sprintf("%s  %s  [%s]", e.Target(), e.Kind.Label(), e.Instance.Status)
}

// List keeps the instances of cluster (and tenant, when not empty) whose
// service maps to one of kinds (all kinds when none given), sorted by
// tenant, instance name and kind. Unknown services are dropped.
func List(instances []portal.CatalogInstance, cluster, tenant string, kinds ...Kind) []Entry {
	want := map[Kind]bool{}
	for _, k := range kinds {
		want[k] = true
	}
	var out []Entry
	for _, i := range instances {
		k, ok := KindOf(i.Service)
		if !ok || i.Cluster != cluster || (tenant != "" && !TenantMatches(i.Tenant, tenant)) {
			continue
		}
		if len(want) > 0 && !want[k] {
			continue
		}
		out = append(out, Entry{Kind: k, Instance: i})
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a].Instance, out[b].Instance
		if x.Tenant != y.Tenant {
			return x.Tenant < y.Tenant
		}
		if x.InstanceName != y.InstanceName {
			return x.InstanceName < y.InstanceName
		}
		return out[a].Kind < out[b].Kind
	})
	return out
}

// Resolve finds tenant/name in cluster. With kind set, only that service
// matches (an instance of the same name in another service yields
// ErrWrongKind); with kind empty, the name must be unique across services
// (ErrAmbiguous otherwise). A match that is not deployed yields ErrNotReady
// together with the entry, so callers can show its status. It never
// matches another tenant or cluster, even with an identical instance name.
func Resolve(instances []portal.CatalogInstance, cluster, tenant, name string, kind Kind) (Entry, error) {
	var matches, other []Entry
	for _, e := range List(instances, cluster, tenant) {
		if e.Instance.InstanceName != name {
			continue
		}
		if kind != "" && e.Kind != kind {
			other = append(other, e)
			continue
		}
		matches = append(matches, e)
	}
	switch {
	case len(matches) == 0 && len(other) > 0:
		return Entry{}, fmt.Errorf("%w: %s/%s is %s, not %s", ErrWrongKind, tenant, name, other[0].Kind.Label(), kind.Label())
	case len(matches) == 0:
		return Entry{}, fmt.Errorf("%w: %s/%s on %s", ErrNotFound, tenant, name, cluster)
	case len(matches) > 1:
		labels := make([]string, len(matches))
		for i, m := range matches {
			labels[i] = string(m.Kind)
		}
		return Entry{}, fmt.Errorf("%w: %s/%s (%s)", ErrAmbiguous, tenant, name, strings.Join(labels, ", "))
	}
	e := matches[0]
	if !e.Ready() {
		return e, fmt.Errorf("%w: %s is %s", ErrNotReady, e.Target(), e.Instance.Status)
	}
	return e, nil
}
