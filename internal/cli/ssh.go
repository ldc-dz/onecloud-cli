package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/accounts"
	"github.com/ldc-dz/onecloud-cli/internal/cert"
	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/portal"
	"github.com/ldc-dz/onecloud-cli/internal/sshcmd"
	"github.com/ldc-dz/onecloud-cli/internal/target"
)

func accountStore() (accounts.Store, error) {
	d, err := config.Dir()
	if err != nil {
		return accounts.Store{}, err
	}
	return accounts.Store{Path: filepath.Join(d, "accounts.json")}, nil
}

// ensureLogin signs in again when the certificate is missing or expires soon.
func ensureLogin(cl config.Cluster, keyPath string) error {
	info, err := cert.ReadPair(keyPath)
	switch {
	case err == nil:
		info = info.WithMaxAge(cl.MaxAge())
		if !info.Expired(time.Now().Add(time.Minute)) {
			debugf("signed in as %s until %s", info.KeyID, info.ValidBefore.Local().Format(time.RFC3339))
			return nil
		}
		say("Your sign-in has expired")
	case errors.Is(err, cert.ErrKeyMissing):
		say("Your SSH key is missing, creating a new one")
	case errors.Is(err, cert.ErrKeyMismatch):
		say("Your SSH key does not match your sign-in, creating a new one")
	default:
		debugf("no usable sign-in: %v", err)
		say("You are not signed in yet")
	}
	return login(cl, false)
}

// join runs the onecloud-join step and returns the personal account name.
func join(sshPath string, o sshcmd.Options) (string, error) {
	var out bytes.Buffer
	var tail tailBuffer
	c := exec.Command(sshPath, sshcmd.JoinArgs(o)...)
	c.Stdin = os.Stdin
	c.Stdout = &out
	c.Stderr = io.MultiWriter(os.Stderr, &tail)
	err := c.Run()
	if account, ok := sshcmd.ParseJoinOutput(out.String()); ok {
		return account, nil
	}
	if err != nil && sshcmd.HostKeyChanged(tail.String()) {
		return "", errors.New(sshcmd.HostKeyHint(o.Host, o.KeyPath, o.Windows, o.Address != ""))
	}
	if err != nil {
		return "", fmt.Errorf("could not set up your account on %s (are you a member of this tenant, and is SSO enabled on the VM?): %w", o.Host, err)
	}
	return "", fmt.Errorf("unexpected answer from %s: %q", o.Host, out.String())
}

func newSSHCmd(cluster func() (config.Cluster, error), via *string) *cobra.Command {
	var user, addressOverride string
	var rejoin bool
	var sshOpts []string
	cmd := &cobra.Command{
		Use:     "ssh <tenant>/<vm> [command...]",
		Short:   "Connect to a tenant VM with your OneCloud SSO account",
		Example: "  ocd ssh demo-000001/vmsso\n  ocd ssh --via direct --address 10.0.0.12 demo-000001/vmsso\n  ocd ssh --via proxied demo-000001/vmsso\n  ocd ssh demo-000001/vmsso -- uptime",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cl, err := cluster()
			if err != nil {
				return err
			}
			if err := cl.SSHAvailable(); err != nil {
				return err
			}
			tg, err := target.Parse(args[0])
			if err != nil {
				return err
			}
			if addressOverride != "" && *via != "direct" {
				return errors.New("--address requires --via direct")
			}
			if addressOverride != "" {
				if _, err := validDirectAddress(addressOverride); err != nil {
					return err
				}
				if net.ParseIP(addressOverride) != nil && !portal.PrivateIPv4(addressOverride) {
					say("Warning: --address %s is not a private tenant IPv4 address; connecting only because you explicitly selected --via direct", addressOverride)
				}
			}
			sshPath, err := exec.LookPath("ssh")
			if err != nil {
				return errors.New("ssh client not found on PATH (Windows: enable the OpenSSH Client optional feature)")
			}
			self, err := os.Executable()
			if err != nil {
				return err
			}
			keyPath, err := cl.KeyPath()
			if err != nil {
				return err
			}
			address := addressOverride
			if *via != "proxied" && address == "" && cl.PortalURL != "" && cl.PortalClientID != "" {
				var lookupErr error
				address, _, lookupErr = portalVPC(cl, "vm", tg.Tenant, tg.VM, false, *via == "direct")
				if lookupErr != nil {
					if *via == "direct" {
						return fmt.Errorf("cannot look up the tenant-network address: %w; use --address <ip> if you know it", lookupErr)
					}
					if errors.Is(lookupErr, errPortalNonInteractive) || errors.Is(lookupErr, errCloudShellPortal) {
						say("No saved portal sign-in; skipping address lookup and using the OneCloud access gateway")
					} else {
						debugf("tenant-network address unavailable (%v); using gateway", lookupErr)
					}
				}
			}
			path, err := accessPath(*via, address, 22)
			if err != nil {
				return err
			}
			if path == "proxied" && !nativePortalAvailable() {
				return errCloudShellGateway
			}
			if err := ensureLogin(cl, keyPath); err != nil {
				return err
			}
			sayAccessPath(path)
			remote := args[1:]
			if len(remote) > 0 && remote[0] == "--" {
				remote = remote[1:]
			}
			var extra []string
			for _, o := range sshOpts {
				extra = append(extra, "-o", o)
			}
			o := sshcmd.Options{
				Self: self, KeyPath: keyPath, Host: tg.Host(cl.TCPDomain), PomeriumURL: cl.PomeriumURL,
				Windows: runtime.GOOS == "windows", Extra: extra, Command: remote,
			}
			if path == "direct" {
				o.Address = address
			}
			store, err := accountStore()
			if err != nil {
				return err
			}
			if rejoin {
				_ = store.Forget(o.Host)
			}
			setup := func(reason string) error {
				say("Setting up your account on %s (%s)", tg.Tenant+"/"+tg.VM, reason)
				account, err := join(sshPath, o)
				if err != nil {
					return err
				}
				if err := store.Set(o.Host, account); err != nil {
					say("Warning: could not remember your account: %v", err)
				}
				say("Your account on this VM is %s", account)
				o.User = account
				return nil
			}
			o.User = user
			cached := false
			if o.User == "" {
				if name, ok := store.Get(o.Host); ok {
					o.User, cached = name, true
				} else if err := setup("first connection"); err != nil {
					return err
				}
			}
			var tail tailBuffer
			err = runSSH(sshPath, sshcmd.Args(o), os.Stdin, os.Stdout, io.MultiWriter(os.Stderr, &tail))
			// A remembered account can go stale (VM rebuilt, accounts
			// re-created by the member sync): ask the VM again, once.
			if cached && !sshcmd.HostKeyChanged(tail.String()) && authDenied(err, tail.String()) {
				_ = store.Forget(o.Host)
				if err := setup("the remembered account was refused"); err != nil {
					return err
				}
				return runSSH(sshPath, sshcmd.Args(o), os.Stdin, os.Stdout, os.Stderr)
			}
			if err != nil && sshcmd.HostKeyChanged(tail.String()) {
				return errors.New(sshcmd.HostKeyHint(o.Host, o.KeyPath, o.Windows, o.Address != ""))
			}
			return err
		},
	}
	f := cmd.Flags()
	f.SetInterspersed(false)
	f.StringVarP(&user, "user", "l", "", "log in as this account instead of your personal one")
	f.StringVar(&addressOverride, "address", "", "tenant-network IP address for --via direct (skip portal lookup)")
	f.BoolVar(&rejoin, "rejoin", false, "forget the remembered account and run the join step again")
	f.StringArrayVarP(&sshOpts, "option", "o", nil, "extra ssh -o option (repeatable)")
	return cmd
}

// authDenied reports an ssh run that failed at authentication (exit 255 and
// the client's "Permission denied" message), not a failing remote command.
func authDenied(err error, stderr string) bool {
	var xe exitError
	return errors.As(err, &xe) && xe.code == 255 && strings.Contains(stderr, "Permission denied (publickey")
}

// tailBuffer keeps the last 4 KiB written to it.
type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > 4096 {
		t.b = t.b[len(t.b)-4096:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }

func runSSH(sshPath string, args []string, in io.Reader, out, errw io.Writer) error {
	c := exec.Command(sshPath, args...)
	c.Stdin, c.Stdout, c.Stderr = in, out, errw
	if err := c.Run(); err != nil {
		var xe *exec.ExitError
		if errors.As(err, &xe) {
			return exitError{xe.ExitCode()}
		}
		return err
	}
	return nil
}
