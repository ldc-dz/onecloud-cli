package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ldc-dz/onecloud-cli/internal/cert"
	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/pgcmd"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Show ocd configuration"}
	cmd.AddCommand(&cobra.Command{
		Use: "show", Short: "Print the effective configuration (built-in + override file)", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			enc := yaml.NewEncoder(c.OutOrStdout())
			enc.SetIndent(2)
			return enc.Encode(cfg)
		},
	}, &cobra.Command{
		Use: "path", Short: "Print the override file path", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			p, err := config.Path()
			if err != nil {
				return err
			}
			fmt.Fprintln(c.OutOrStdout(), p)
			return nil
		},
	})
	return cmd
}

func depVersions() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var parts []string
	for _, d := range bi.Deps {
		if d.Path == "github.com/openpubkey/opkssh" {
			parts = append(parts, "opkssh "+d.Version)
		}
	}
	return strings.Join(parts, ", ")
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print the ocd version", Args: cobra.NoArgs,
		Run: func(c *cobra.Command, _ []string) {
			fmt.Fprintf(c.OutOrStdout(), "ocd %s (commit %s, built %s, %s/%s)\n", Version, Commit, Date, runtime.GOOS, runtime.GOARCH)
			if d := depVersions(); d != "" {
				fmt.Fprintln(c.OutOrStdout(), "embeds:", d)
			}
		},
	}
}

func newDoctorCmd(cluster func() (config.Cluster, error)) *cobra.Command {
	return &cobra.Command{
		Use: "doctor", Short: "Check ocd sign-in, clients, and tenant VPN reachability", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			w := c.OutOrStdout()
			problems := 0
			ok := func(f string, a ...any) { fmt.Fprintf(w, "ok    "+f+"\n", a...) }
			bad := func(f string, a ...any) { problems++; fmt.Fprintf(w, "FAIL  "+f+"\n", a...) }
			note := func(f string, a ...any) { fmt.Fprintf(w, "note  "+f+"\n", a...) }

			if p, err := exec.LookPath("ssh"); err != nil {
				bad("ssh client not found on PATH")
			} else {
				out, _ := exec.Command(p, "-V").CombinedOutput()
				ok("ssh client %s (%s)", p, strings.TrimSpace(string(out)))
			}
			cl, err := cluster()
			if err != nil {
				bad("cluster: %v", err)
				return exitError{1}
			}
			ok("cluster %s (issuer %s)", cl.Name, cl.Issuer)
			vpnHost := os.Getenv("OCD_VPN_PROBE_ADDRESS")
			vpnPort := 22
			if vpnHost != "" {
				if _, err := validAddress(vpnHost); err != nil {
					note("VPN reachability not checked: %v", err)
				} else {
					if p := os.Getenv("OCD_VPN_PROBE_PORT"); p != "" {
						if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
							vpnPort = n
						} else {
							note("VPN reachability not checked: invalid OCD_VPN_PROBE_PORT")
							vpnHost = ""
						}
					}
					if vpnHost != "" && probeTCP(vpnHost, vpnPort) {
						ok("VPN reachability: %s:%d accepts TCP connections (tenant network path available)", vpnHost, vpnPort)
					} else if vpnHost != "" {
						note("VPN reachability: %s:%d not reachable; ocd --via auto will use the OneCloud access gateway", vpnHost, vpnPort)
					}
				}
			} else {
				note("VPN reachability: no probe target set (set OCD_VPN_PROBE_ADDRESS to a tenant VM/database IP and optionally OCD_VPN_PROBE_PORT to 5432)")
			}
			if p, err := exec.LookPath("psql"); err != nil {
				note("psql not found on PATH (only needed for ocd psql)")
			} else {
				out, _ := exec.Command(p, "--version").CombinedOutput()
				if err := pgcmd.CheckVersion(string(out)); err != nil {
					note("%v (only needed for ocd psql)", err)
				} else {
					ok("psql %s (%s)", p, strings.TrimSpace(string(out)))
				}
			}
			if err := cl.SSHAvailable(); err != nil {
				note("%v", err)
				if problems > 0 {
					return exitError{1}
				}
				return nil
			}
			keyPath, err := cl.KeyPath()
			if err != nil {
				bad("home directory: %v", err)
			} else if info, err := cert.ReadPair(keyPath); errors.Is(err, cert.ErrKeyMissing) || errors.Is(err, cert.ErrKeyMismatch) {
				bad("%v (%s): run ocd login", err, keyPath)
			} else if err != nil {
				bad("not signed in (%s-cert.pub missing): run ocd login", keyPath)
			} else if info = info.WithMaxAge(cl.MaxAge()); info.Expired(time.Now()) {
				bad("sign-in expired at %s: run ocd login", info.ValidBefore.Local().Format(time.RFC3339))
			} else {
				ok("signed in, valid until %s", info.ValidBefore.Local().Format(time.RFC3339))
			}
			if _, err := os.Executable(); err != nil {
				bad("cannot locate the ocd binary for the ssh ProxyCommand: %v", err)
			}
			if problems > 0 {
				return exitError{1}
			}
			return nil
		},
	}
}
