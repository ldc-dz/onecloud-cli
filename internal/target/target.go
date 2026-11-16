// Package target resolves "<tenant>/<vm>" into the Pomerium TCP host of the
// VM SSH route.
package target

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	tenantRe = regexp.MustCompile(`^(?:[a-z][a-z0-9-]*-)?([0-9]{6})$`)
	vmRe     = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Target is a resolved VM SSH destination.
type Target struct {
	Tenant   string // as typed, e.g. demo-000001
	TenantID string // six-digit id, e.g. 000001
	VM       string
}

// Parse accepts "demo-000001/vmsso" or "000001/vmsso".
func Parse(s string) (Target, error) {
	return parse(s, "<tenant>/<vm>, e.g. demo-000001/vmsso")
}

// ParseInstance accepts "demo-000001/pgoidc01" for a managed service
// instance. The tenant slug is required: the instance namespace (and so the
// TLS server name) is built from it.
func ParseInstance(s string) (Target, error) {
	t, err := parse(s, "<tenant>/<instance>, e.g. demo-000001/pgoidc01")
	if err != nil {
		return Target{}, err
	}
	if t.Slug() == "" {
		return Target{}, fmt.Errorf("tenant %q: write the full tenant name, e.g. demo-%s", t.Tenant, t.TenantID)
	}
	return t, nil
}

// Slug returns the tenant slug ("demo" for demo-000001), empty for a bare id.
func (t Target) Slug() string {
	return strings.TrimSuffix(strings.TrimSuffix(t.Tenant, t.TenantID), "-")
}

// PostgresHost returns the Pomerium TCP route of a PostgreSQL instance:
// <instance>-pg-<tenant id>.<tcpDomain>.
func (t Target) PostgresHost(tcpDomain string) string {
	return fmt.Sprintf("%s-pg-%s.%s", t.VM, t.TenantID, tcpDomain)
}

// PostgresServerName returns the name in the instance TLS certificate
// (the -access Service): <instance>-pg-access.tenant-<slug>-<id>-postgresql.svc.
func (t Target) PostgresServerName() string {
	return fmt.Sprintf("%s-pg-access.tenant-%s-%s-postgresql.svc", t.VM, t.Slug(), t.TenantID)
}

func parse(s, want string) (Target, error) {
	tenant, vm, ok := strings.Cut(s, "/")
	if !ok || tenant == "" || vm == "" || strings.Contains(vm, "/") {
		return Target{}, fmt.Errorf("target %q: want %s", s, want)
	}
	m := tenantRe.FindStringSubmatch(tenant)
	if m == nil {
		return Target{}, fmt.Errorf("tenant %q: want <slug>-<6 digit id> or the 6 digit id", tenant)
	}
	if !vmRe.MatchString(vm) {
		return Target{}, fmt.Errorf("%q: not a valid instance name", vm)
	}
	return Target{Tenant: tenant, TenantID: m[1], VM: vm}, nil
}

// Host returns <vm>-ssh-<tenant id>.<tcpDomain>.
func (t Target) Host(tcpDomain string) string {
	return fmt.Sprintf("%s-ssh-%s.%s", t.VM, t.TenantID, tcpDomain)
}
