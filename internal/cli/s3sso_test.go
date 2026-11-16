package cli

import (
	"reflect"
	"testing"
)

func TestSSOTargetAndTenantBuckets(t *testing.T) {
	if tn, b := splitSSOTarget("demo-000001/test-12-11-2026"); tn != "demo-000001" || b != "test-12-11-2026" {
		t.Fatalf("split: %q %q", tn, b)
	}
	if tn, b := splitSSOTarget("demo-000001"); tn != "demo-000001" || b != "" {
		t.Fatalf("split tenant only: %q %q", tn, b)
	}
	if got := tenantBucket("demo-000001", "test-12-11-2026"); got != "test-12-11-2026.000001" {
		t.Fatalf("instance to bucket: %q", got)
	}
	if got := tenantBucket("demo-000001", "test-12-11-2026.000001"); got != "test-12-11-2026.000001" {
		t.Fatalf("full bucket kept: %q", got)
	}
	got := filterTenantBuckets("demo-000001", []string{"a.000001", "b.000002", "c000001", "d.000001"})
	if !reflect.DeepEqual(got, []string{"a.000001", "d.000001"}) {
		t.Fatalf("filter: %v", got)
	}
}
