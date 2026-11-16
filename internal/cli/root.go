// Package cli wires the ocd commands.
package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/browser"
	"github.com/ldc-dz/onecloud-cli/internal/config"
)

// Build metadata, set with -ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// exitError carries a child process exit code up to Main.
type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// NewRoot builds the command tree.
func NewRoot() *cobra.Command {
	var cluster, via string
	var verboseFlag bool
	root := &cobra.Command{
		Use:           "ocd",
		Short:         "OneCloud CLI for tenant members",
		Long:          "ocd signs you in with OneCloud SSO and connects you to your tenant services.\nIt uses your tenant network when reachable, otherwise the OneCloud access gateway.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&cluster, "cluster", "", "OneCloud cluster: ocd-prd-01 (default) or ocd-dev-01")
	root.PersistentFlags().StringVar(&via, "via", "auto", "access path for ssh/psql: auto, direct, or proxied")
	root.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "v", false, "show details (identity, key paths, library messages)")
	root.PersistentPreRunE = func(*cobra.Command, []string) error {
		if err := validateVia(via); err != nil {
			return err
		}
		if verboseFlag {
			// Also reaches the ocd tunnel process that ssh starts.
			_ = os.Setenv(VerboseEnv, "1")
		}
		return nil
	}
	clusterFn := func() (config.Cluster, error) {
		c, err := config.Load()
		if err != nil {
			return config.Cluster{}, err
		}
		return c.Cluster(cluster)
	}
	root.AddCommand(
		newLoginCmd(clusterFn),
		newSSHCmd(clusterFn, &via),
		newPsqlCmd(clusterFn, &via),
		newClickHouseCmd(clusterFn),
		newMSSQLCmd(clusterFn),
		newS3Cmd(clusterFn),
		newServicesCmd(clusterFn),
		newConnectCmd(clusterFn),
		newTunnelCmd(),
		newConfigCmd(),
		newDoctorCmd(clusterFn),
		newVersionCmd(),
	)
	return root
}

// Main runs ocd and returns the process exit code.
func Main(args []string) int {
	if os.Getenv(browser.HelperEnv) == "1" {
		c, _ := config.Load()
		if ok, err := browser.HelperMain(args, c.Browser); ok {
			if err != nil {
				fmt.Fprintln(os.Stderr, "ocd:", err)
				return 1
			}
			return 0
		}
	}
	root := NewRoot()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			return ee.code
		}
		// A wrapped *exec.ExitError (e.g. the access tunnel failing to
		// open the browser) must still be printed: only ssh/psql exit codes,
		// already converted to exitError, are passed through silently.
		fmt.Fprintln(os.Stderr, "ocd:", err)
		return 1
	}
	return 0
}
