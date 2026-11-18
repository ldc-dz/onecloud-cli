package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pomerium/cli/tunnel"
	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/pgcmd"
	"github.com/ldc-dz/onecloud-cli/internal/portal"
	"github.com/ldc-dz/onecloud-cli/internal/target"
)

// caStore returns where ocd keeps PostgreSQL instance CA certificates.
func caStore() (pgcmd.CAStore, error) {
	d, err := config.Dir()
	if err != nil {
		return pgcmd.CAStore{}, err
	}
	return pgcmd.CAStore{Dir: filepath.Join(d, "postgres")}, nil
}

// tunnelServer accepts local connections and carries each one through tun.
type tunnelServer struct {
	ln  net.Listener
	tun *tunnel.Tunnel
	wg  sync.WaitGroup
}

func (s *tunnelServer) Port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *tunnelServer) serve(ctx context.Context) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !peerAllowed(conn) {
			debugf("local tunnel: refused connection from %s (not owned by this user)", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			_ = s.tun.Run(ctx, conn, quietEvents{tunnel.LogEvents()})
		}()
	}
}

// startTunnel listens on 127.0.0.1:port (0 picks a free port) and tunnels
// every connection to dst through Pomerium until ctx ends. Connections not
// owned by the current user are refused where the OS allows checking
// (see localtunnel.go); TCP is kept because libpq has no TLS over Unix sockets.
func startTunnel(ctx context.Context, tun *tunnel.Tunnel, port int) (*tunnelServer, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("local tunnel port: %w", err)
	}
	s := &tunnelServer{ln: ln, tun: tun}
	go s.serve(ctx)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	return s, nil
}

// noOAuthHint explains a psql/libpq built without the OAuth device flow.
func noOAuthHint(stderr string) string {
	s := strings.ToLower(stderr)
	if strings.Contains(s, "libpq-oauth") || strings.Contains(s, "oauth") && (strings.Contains(s, "not supported") || strings.Contains(s, "no oauth flows")) {
		return "this psql cannot run the OneCloud sign-in (OAuth device flow): on Debian/Ubuntu install the libpq-oauth package, elsewhere use a PostgreSQL 18 client built with libcurl"
	}
	return ""
}

// downloadCA reads the instance CA from an already-authorized connection
// inventory and keeps it in the local store.
func downloadCA(cl config.Cluster, store pgcmd.CAStore, conns []portal.Connection, tenant, instance string) (string, error) {
	pem, err := portal.FindCA(conns, tenant, instance)
	if errors.Is(err, portal.ErrNotFound) {
		return "", fmt.Errorf("%s/%s is not among your PostgreSQL instances in the portal (check the name and that you are a member of the tenant)", tenant, instance)
	}
	if err != nil {
		return "", fmt.Errorf("%s/%s: %w", tenant, instance, err)
	}
	path, err := store.Save(cl.Name, tenant, instance, []byte(pem))
	if err != nil {
		return "", err
	}
	say("CA certificate saved")
	return path, nil
}

func newPsqlCmd(cluster func() (config.Cluster, error), via *string) *cobra.Command {
	var caFile, dbname, user string
	var port int
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "psql <tenant>/<instance> [-- psql arguments...]",
		Short: "Connect to a tenant managed PostgreSQL with your OneCloud SSO account",
		Long: "ocd psql reaches PostgreSQL directly over your tenant network when available, otherwise\n" +
			"via the OneCloud access gateway. Both paths keep OneCloud sign-in (OAuth) and full\n" +
			"TLS verification. psql 18 or newer is needed.\n\n" +
			"The instance CA certificate is fetched from the portal after a browser sign-in the\n" +
			"first time and kept, so later runs need nothing. Where the portal cannot\n" +
			"be reached, download \"TLS CA certificate\" (<instance>-ca.crt) and pass it once with\n" +
			"--ca, or run ocd psql in the folder holding it.",
		Example: "  ocd psql demo-000001/pgoidc01\n" +
			"  ocd psql demo-000001/pgoidc01 -- -c 'select current_user, version()'\n" +
			"  ocd psql --cluster ocd-dev-01 demo-000001/pgoidc01\n" +
			"  ocd psql --ca pgoidc01-ca.crt demo-000001/pgoidc01\n" +
			"  ocd psql -d reports -U analyst demo-000001/pg18oauth000001",
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cl, err := cluster()
			if err != nil {
				return err
			}
			if err := cl.PostgresAvailable(); err != nil {
				return err
			}
			tg, err := target.ParseInstance(args[0])
			if err != nil {
				return err
			}
			extra := args[1:]
			if len(extra) > 0 && extra[0] == "--" {
				extra = extra[1:]
			}
			store, err := caStore()
			if err != nil {
				return err
			}
			ca, src, caErr := store.Resolve(cl.Name, tg.Tenant, tg.VM, caFile)
			if caErr != nil && !errors.Is(caErr, pgcmd.ErrNoCA) {
				return caErr // invalid explicit CA never triggers portal sign-in
			}
			address := ""
			var conns []portal.Connection
			if (*via != "proxied" || errors.Is(caErr, pgcmd.ErrNoCA)) && cl.PortalURL != "" && cl.PortalClientID != "" {
				var lookupErr error
				if *via != "proxied" {
					address, conns, lookupErr = portalVPC(cl, "postgresql", tg.Tenant, tg.VM, errors.Is(caErr, pgcmd.ErrNoCA), *via == "direct")
				} else {
					_, _, conns, lookupErr = portalInventory(cl, false)
				}
				if lookupErr != nil {
					if *via == "direct" {
						return fmt.Errorf("cannot look up the tenant-network address: %w", lookupErr)
					}
					if errors.Is(lookupErr, errPortalNonInteractive) || errors.Is(lookupErr, errCloudShellPortal) {
						if caErr == nil {
							say("No saved portal sign-in; skipping address lookup and using the OneCloud access gateway")
						}
					} else {
						debugf("portal inventory unavailable (%v); using gateway", lookupErr)
					}
				}
			}
			if errors.Is(caErr, pgcmd.ErrNoCA) && conns != nil {
				ca, caErr = downloadCA(cl, store, conns, tg.Tenant, tg.VM)
				src = "portal"
			}
			path, err := accessPath(*via, address, postgresPort)
			if err != nil {
				return err
			}
			// OneCloud Shell sits in the tenant network but cannot sign in to the
			// access gateway (browser only), and portals publish no VPC address
			// for PostgreSQL: reach the instance service directly (UAT 2026-11,
			// PG-SH-CLI-01, OneCloud #2638).
			if path == "proxied" && *via == "auto" && config.InCloudShell() {
				if ip := shellServiceAddress(tg.PostgresServerName(), postgresPort); ip != "" {
					address, path = ip, "direct"
				}
			}
			if errors.Is(caErr, pgcmd.ErrNoCA) {
				return fmt.Errorf("no CA certificate for %s yet: download \"TLS CA certificate\" for %s from the OneCloud portal, then run again with --ca %s-ca.crt",
					args[0], tg.VM, tg.VM)
			}
			if caErr != nil {
				return caErr
			}
			psqlPath, err := exec.LookPath("psql")
			if err != nil {
				return fmt.Errorf("psql not found on PATH: install the PostgreSQL %d client", pgcmd.MinMajor)
			}
			out, _ := exec.Command(psqlPath, "--version").CombinedOutput()
			if err := pgcmd.CheckVersion(string(out)); err != nil {
				return err
			}
			debugf("CA certificate %s (%s)", ca, src)
			sayAccessPath(path)

			var cancel context.CancelFunc = func() {}
			var restore = func() {}
			var dbAddress string
			dbPort := postgresPort
			if path == "direct" {
				dbAddress = address
			} else {
				setupTunnelLogging()
				host := tg.PostgresHost(cl.TCPDomain)
				tun, dst, err := newTunnel(host+":443", cl.PomeriumURL, "")
				if err != nil {
					return err
				}
				ctx, done := context.WithCancel(context.Background())
				cancel = done
				defer cancel()
				srv, err := startTunnel(ctx, tun, port)
				if err != nil {
					return err
				}
				dbPort = srv.Port()
				debugf("tunnel 127.0.0.1:%d -> %s", dbPort, dst)
				restore = filterPomeriumNotice(dst)
			}

			conninfo := pgcmd.ConnInfo(pgcmd.Options{
				ServerName: tg.PostgresServerName(), Address: dbAddress, Port: dbPort,
				Database: dbname, User: user, CAFile: ca,
				Issuer: cl.PostgresIssuer, ClientID: cl.PostgresClientID,
			})
			debugf("psql %q %v", conninfo, extra)
			say("Connecting to %s (authorize database access with the sign-in code shown by psql)", args[0])

			// Ctrl-C belongs to psql (it cancels the running query); when
			// proxied, ocd must keep the tunnel up until psql exits.
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			defer signal.Stop(sig)
			go func() {
				for range sig {
				}
			}()

			psqlStderr := io.Writer(os.Stderr)
			if opener := browserOpener(); !noBrowser && !opener.Disabled() {
				psqlStderr = &deviceCodeWriter{out: os.Stderr, allowedHost: issuerHost(cl.PostgresIssuer), open: func(u string) {
					if err := opener.Open(u); err != nil {
						debugf("device sign-in page not opened: %v", err)
						return
					}
					say("Opened the sign-in page with the code filled in; confirm it in your browser")
				}}
			}
			var tail tailBuffer
			c := exec.Command(psqlPath, append([]string{conninfo}, extra...)...)
			c.Stdin, c.Stdout = os.Stdin, os.Stdout
			c.Stderr = io.MultiWriter(psqlStderr, &tail)
			runErr := c.Run()
			restore()
			cancel()
			if runErr != nil {
				if hint := noOAuthHint(tail.String()); hint != "" {
					say("Hint: %s", hint)
				}
				var xe *exec.ExitError
				if errors.As(runErr, &xe) {
					return exitError{xe.ExitCode()}
				}
				return runErr
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.SetInterspersed(false)
	f.StringVar(&caFile, "ca", "", "instance CA certificate from the portal (kept for later runs)")
	f.BoolVar(&noBrowser, "no-browser", false, "do not open the database sign-in page; only print the link and code")
	f.StringVarP(&dbname, "dbname", "d", "app", "database name")
	f.StringVarP(&user, "username", "U", "app", "database role")
	f.IntVar(&port, "port", 0, "local gateway tunnel port (default: a free port; unused on direct connections)")
	return cmd
}
