package cli

import (
	"strings"
	"testing"
)

// Unsafe S3 removals are refused before any portal sign-in or network call,
// and the new commands are registered with their help.
func TestNewCommandsGuardsAndHelp(t *testing.T) {
	t.Setenv("OCD_CONFIG_DIR", t.TempDir())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"s3", "rm", "demo-000001/store01", "--prefix", "logs/"}, "recursive"},
		{[]string{"s3", "rm", "demo-000001/store01", "--prefix", "/", "--recursive", "--yes"}, "bucket-root"},
		{[]string{"s3", "rm", "demo-000001/store01", "--key", "logs/", "--yes"}, "folder-like"},
		{[]string{"s3", "rm", "demo-000001/store01", "--key", "a.txt"}, "confirmation"},
	} {
		if _, err := run(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: got %v, want %q", tc.args, err, tc.want)
		}
	}
	for _, cmd := range []string{"clickhouse", "ch", "mssql", "services", "connect", "s3"} {
		out, err := run(t, cmd, "--help")
		if err != nil || strings.Contains(strings.ToLower(out), "pomerium") {
			t.Errorf("ocd %s --help: %v %q", cmd, err, out)
		}
	}
}
