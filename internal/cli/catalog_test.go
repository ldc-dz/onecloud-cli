package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/dbclient"
	"github.com/spf13/cobra"
)

// A machine without the native client gets the install route before the
// cluster is resolved: resolving reads the production issuer over the
// network, and a network error there hid the route (UAT 2026-11
// CH-ANY-CLI-03, Windows runner: "production issuer discovery: ...").
func TestSQLCommandsCheckTheClientBeforeResolvingTheCluster(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for name, newCmd := range map[string]func(func() (config.Cluster, error)) *cobra.Command{
		"clickhouse": newClickHouseCmd,
		"mssql":      newMSSQLCmd,
	} {
		resolved := false
		cmd := newCmd(func() (config.Cluster, error) {
			resolved = true
			return config.Cluster{}, errors.New("production issuer discovery: network down")
		})
		cmd.SetArgs([]string{"demo-000001/db01"})
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err := cmd.Execute()
		var missing *dbclient.MissingClientError
		if !errors.As(err, &missing) {
			t.Errorf("ocd %s without a client: got %v, want the missing-client guidance", name, err)
		}
		if resolved {
			t.Errorf("ocd %s resolved the cluster before checking the client", name)
		}
	}
}

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
