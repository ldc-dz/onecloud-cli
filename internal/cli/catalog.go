package cli

// catalog.go connects the portal service catalog to the ClickHouse, SQL
// Server, S3, services and connect commands. Credentials are revealed on
// demand, kept in process memory and wiped when the command ends.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/browser"
	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/dbclient"
	"github.com/ldc-dz/onecloud-cli/internal/portal"
	"github.com/ldc-dz/onecloud-cli/internal/procmem"
	"github.com/ldc-dz/onecloud-cli/internal/selector"
	"github.com/ldc-dz/onecloud-cli/internal/services"
	"github.com/ldc-dz/onecloud-cli/internal/sqlcmd"
	"github.com/ldc-dz/onecloud-cli/internal/target"
)

// portalSession is a signed-in portal client and its bearer.
type portalSession struct {
	client portal.Client
	token  string
}

func newPortalClient(cl config.Cluster) portal.Client {
	opener := browserOpener()
	return portal.Client{
		PortalURL: cl.PortalURL, Issuer: cl.Issuer, ClientID: cl.PortalClientID,
		CallbackHTML: signedInPage,
		Open: func(u string) error {
			if opener.Disabled() || opener.Open(u) != nil {
				say("Open this address in your browser: %s", u)
			} else {
				say("If no browser tab opened, visit: %s", u)
			}
			return nil
		},
	}
}

// portalCatalog returns the instances the signed-in user may see. A saved
// portal session is reused; a revoked one is dropped and signed in again.
func portalCatalog(ctx context.Context, cl config.Cluster) (portalSession, []portal.CatalogInstance, error) {
	if cl.PortalURL == "" || cl.PortalClientID == "" {
		return portalSession{}, nil, fmt.Errorf("the portal is not configured for cluster %s", cl.Name)
	}
	store, err := portalStore()
	if err != nil {
		return portalSession{}, nil, err
	}
	c := newPortalClient(cl)
	cached, err := store.Token(cl)
	if err != nil {
		return portalSession{}, nil, err
	}
	if cached != "" {
		inst, err := c.Catalog(ctx, cached)
		if err == nil {
			return portalSession{c, cached}, inst, nil
		}
		if !errors.Is(err, portal.ErrUnauthorized) {
			return portalSession{}, nil, err
		}
		if err := store.Clear(cl); err != nil {
			return portalSession{}, nil, err
		}
	}
	if !nativePortalAvailable() {
		return portalSession{}, nil, errCloudShellPortal
	}
	if !maySignInPortal(false) {
		return portalSession{}, nil, errPortalNonInteractive
	}
	say("Reading your OneCloud services (sign in in your browser)")
	token, err := c.SignInWithExpiry(ctx, func(token string, _ time.Time) {
		if err := store.SaveToken(cl, token); err != nil {
			say("Warning: could not save the portal session for later runs: %v", err)
		}
	})
	if err != nil {
		return portalSession{}, nil, err
	}
	inst, err := c.Catalog(ctx, token)
	return portalSession{c, token}, inst, err
}

// pickService resolves an explicit <tenant>/<instance>, or asks on the
// terminal when target is empty. Scripts without a terminal get an error
// naming the argument to pass; they never wait for input.
func pickService(ctx context.Context, cl config.Cluster, typed, command string, kinds ...services.Kind) (portalSession, services.Entry, error) {
	sess, inst, err := portalCatalog(ctx, cl)
	if err != nil {
		return portalSession{}, services.Entry{}, err
	}
	if typed != "" {
		tg, err := target.ParseInstance(typed)
		if err != nil {
			return portalSession{}, services.Entry{}, err
		}
		kind := services.Kind("")
		if len(kinds) == 1 {
			kind = kinds[0]
		}
		e, err := services.Resolve(inst, cl.Name, tg.Tenant, tg.VM, kind)
		return sess, e, err
	}
	entries := services.List(inst, cl.Name, "", kinds...)
	if len(entries) == 0 {
		return portalSession{}, services.Entry{}, fmt.Errorf("no matching instances on %s", cl.Name)
	}
	items := make([]selector.Item, len(entries))
	for i, e := range entries {
		items[i] = selector.Item{Label: e.Target(), Detail: e.Kind.Label() + "  " + string(e.Instance.Status), Disabled: !e.Ready()}
	}
	idx, err := selector.Select(ctx, "Choose an instance", items)
	if errors.Is(err, selector.ErrNotInteractive) {
		return portalSession{}, services.Entry{}, fmt.Errorf("%w, e.g. ocd %s <tenant>/<instance> (see ocd services)", err, command)
	}
	if err != nil {
		return portalSession{}, services.Entry{}, err
	}
	return sess, entries[idx], nil
}

// reveal fetches an instance's credentials into process memory.
func (s portalSession) reveal(ctx context.Context, cl config.Cluster, e services.Entry) (*procmem.Values, error) {
	vals, err := s.client.Reveal(ctx, s.token, e.Instance.ID)
	if errors.Is(err, portal.ErrUnauthorized) {
		if store, serr := portalStore(); serr == nil {
			_ = store.Clear(cl)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.Target(), err)
	}
	return vals, nil
}

// firstValue returns the first revealed key present, else the public output.
func firstValue(vals *procmem.Values, e services.Entry, keys ...string) string {
	for _, k := range keys {
		if vals != nil && vals.Has(k) {
			if v, err := vals.String(k); err == nil && v != "" {
				return v
			}
		}
	}
	for _, k := range keys {
		if v, ok := e.Instance.Output(k); ok && v != "" {
			return v
		}
	}
	return ""
}

// splitTarget separates an optional leading target from forwarded client
// arguments; "ocd ch -- --query x" has no target.
func splitTarget(cmd *cobra.Command, args []string) (string, []string) {
	if cmd.ArgsLenAtDash() == 0 || len(args) == 0 {
		return "", args
	}
	extra := args[1:]
	if len(extra) > 0 && extra[0] == "--" {
		extra = extra[1:]
	}
	return args[0], extra
}

// sqlEngine describes one native SQL command. inventory is the engine name
// of the portal connections inventory (the one ocd psql reads).
type sqlEngine struct {
	use, short, route, defaultDB, defaultUser, inventory string
	aliases                                              []string
	kind                                                 services.Kind
	engine                                               sqlcmd.Engine
}

// directSQLPorts are the tenant-network ports the native clients speak to
// (SQL Server TDS, ClickHouse native). Tests substitute ephemeral listeners.
var directSQLPorts = map[string]int{"mssql": 1433, "clickhouse": 9000}

// sqlDirectEndpoint picks the path of ocd mssql / ocd clickhouse outside
// OneCloud Shell, like ocd psql: the tenant-network (VPC) address published
// in the portal connections inventory when --via allows it and, in auto
// mode, when it accepts TCP; otherwise the access gateway (empty endpoint).
func sqlDirectEndpoint(cl config.Cluster, s sqlEngine, via, tenant, instance string) (string, error) {
	if via == "proxied" {
		return "", nil
	}
	port := directSQLPorts[s.inventory]
	address, _, err := portalVPC(cl, s.inventory, tenant, instance, false, via == "direct")
	if err != nil {
		if via == "direct" {
			return "", fmt.Errorf("cannot look up the tenant-network address: %w", err)
		}
		debugf("no tenant-network address for %s/%s (%v); using the access gateway", tenant, instance, err)
		return "", nil
	}
	path, err := accessPath(via, address, port)
	if err != nil {
		return "", err
	}
	if path != "direct" {
		debugf("tenant-network address %s:%d not reachable; using the access gateway", address, port)
		return "", nil
	}
	debugf("tenant-network address %s:%d from the portal inventory", address, port)
	return net.JoinHostPort(address, strconv.Itoa(port)), nil
}

func newSQLCmd(cluster func() (config.Cluster, error), via *string, s sqlEngine) *cobra.Command {
	var dbname, user string
	var noBrowser bool
	cmd := &cobra.Command{
		Use:     s.use + " [<tenant>/<instance>] [-- client arguments...]",
		Aliases: s.aliases,
		Short:   s.short,
		Long: s.short + " directly over your tenant network when the portal\n" +
			"publishes a tenant-network address that answers (VPN), otherwise through the\n" +
			"OneCloud access gateway. --via auto (default), direct or proxied forces the path;\n" +
			"-v prints which address was chosen and why.\n" +
			"Without a target, ocd lists your instances and lets you choose one.\n" +
			"The database password is read from the portal for this session only and is\n" +
			"given to the client through its environment, never on the command line.",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// Before any network call, sign-in or password reveal: the native
			// client must be there and be the real one (a look-alike ignores
			// the password ocd passes and fails with a misleading database
			// error; UAT 2026-11 CH-PORTAL-02). Resolving the cluster reads
			// the production issuer over the network: a machine without the
			// client must get the install route, not a network error
			// (UAT 2026-11 CH-ANY-CLI-03).
			if _, err := dbclient.Check(context.Background(), s.engine); err != nil {
				return err
			}
			cl, err := cluster()
			if err != nil {
				return err
			}
			typed, extra := splitTarget(c, args)
			if noBrowser {
				// Portal and access-gateway sign-in pages are only printed.
				_ = os.Setenv(browser.EnvCommand, "none")
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
			sess, e, err := pickService(ctx, cl, typed, s.use, s.kind)
			if err != nil {
				stop()
				return err
			}
			vals, err := sess.reveal(ctx, cl, e)
			stop()
			if err != nil {
				return err
			}
			defer vals.Wipe()
			tg, err := target.ParseInstance(e.Target())
			if err != nil {
				return err
			}
			u := user
			if u == "" {
				u = firstValue(vals, e, "username", "user")
			}
			if u == "" {
				u = s.defaultUser
			}
			password := firstValue(vals, e, "password")
			if password == "" {
				return fmt.Errorf("%s: the portal returned no database password", e.Target())
			}
			host := fmt.Sprintf("%s-%s-%s.%s", tg.VM, s.route, tg.TenantID, cl.TCPDomain)
			var endpoint string
			if config.InCloudShell() {
				// The Shell is in the tenant network: no gateway sign-in.
				if endpoint, err = tenantEndpoint(e); err != nil {
					return err
				}
			} else if endpoint, err = sqlDirectEndpoint(cl, s, *via, tg.Tenant, tg.VM); err != nil {
				// UAT 2026-11 VPN-MS-01 / VPN-CH-01 (OneCloud #2638): a VPN
				// client reaches the published tenant-network address.
				return err
			}
			open := func(ctx context.Context) (dbclient.Tunnel, error) {
				if endpoint != "" {
					return openDirect(ctx, endpoint)
				}
				gw, err := openGatewayTunnel(e.Target(), host, cl.PomeriumURL, 0, noBrowser)
				if err != nil {
					return nil, err
				}
				return gw, nil
			}
			if endpoint != "" {
				say("Connecting to %s directly over your tenant network", e.Target())
			} else {
				say("Connecting to %s via the OneCloud access gateway", e.Target())
			}
			// Ctrl-C belongs to the client (it cancels the running query).
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt)
			defer signal.Stop(sig)
			go func() {
				for range sig {
				}
			}()
			db := dbname
			if db == "" {
				db = s.defaultDB
			}
			err = dbclient.Connect(context.Background(), s.engine,
				sqlcmd.Options{User: u, Password: password, Database: db, Extra: extra}, open,
				dbclient.Streams{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Notice: os.Stderr})
			var xe *dbclient.ExitCodeError
			if errors.As(err, &xe) {
				return exitError{xe.Code}
			}
			return err
		},
	}
	f := cmd.Flags()
	f.SetInterspersed(false)
	f.StringVarP(&dbname, "dbname", "d", "", "database name (default: "+map[bool]string{true: "the server default", false: s.defaultDB}[s.defaultDB == ""]+")")
	f.StringVarP(&user, "username", "U", "", "database user (default: the one published by the portal)")
	f.BoolVar(&noBrowser, "no-browser", false, "do not open the sign-in pages; only print their addresses")
	return cmd
}

func newClickHouseCmd(cluster func() (config.Cluster, error), via *string) *cobra.Command {
	return newSQLCmd(cluster, via, sqlEngine{
		use: "clickhouse", aliases: []string{"ch"}, short: "Connect the ClickHouse client to a tenant managed ClickHouse",
		route: "ch", defaultUser: "default", inventory: "clickhouse", kind: services.ClickHouse, engine: sqlcmd.ClickHouseEngine,
	})
}

func newMSSQLCmd(cluster func() (config.Cluster, error), via *string) *cobra.Command {
	return newSQLCmd(cluster, via, sqlEngine{
		use: "mssql", aliases: []string{"sqlserver"}, short: "Connect sqlcmd to a tenant managed SQL Server",
		route: "mssql", defaultDB: "master", defaultUser: "sa", inventory: "mssql", kind: services.MSSQL, engine: sqlcmd.MSSQLEngine,
	})
}

// serviceRow is the secret-free listing format (also the --json schema).
type serviceRow struct {
	Type     string `json:"type"`
	Tenant   string `json:"tenant"`
	Instance string `json:"instance"`
	Status   string `json:"status"`
	Cluster  string `json:"cluster"`
	Ready    bool   `json:"ready"`
}

func newServicesCmd(cluster func() (config.Cluster, error)) *cobra.Command {
	var asJSON bool
	var kind, tenant string
	cmd := &cobra.Command{
		Use:     "services",
		Aliases: []string{"ls"},
		Short:   "List the managed services you can reach (PostgreSQL, SQL Server, ClickHouse, S3, VMs)",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			cl, err := cluster()
			if err != nil {
				return err
			}
			var kinds []services.Kind
			if kind != "" {
				k, ok := services.KindOf(kind)
				if !ok {
					return fmt.Errorf("unknown --type %q: use postgresql, mssql, clickhouse, s3 or vm", kind)
				}
				kinds = append(kinds, k)
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
			defer stop()
			_, inst, err := portalCatalog(ctx, cl)
			if err != nil {
				return err
			}
			rows := []serviceRow{}
			for _, e := range services.List(inst, cl.Name, tenant, kinds...) {
				rows = append(rows, serviceRow{Type: string(e.Kind), Tenant: e.Instance.Tenant, Instance: e.Instance.InstanceName,
					Status: string(e.Instance.Status), Cluster: e.Instance.Cluster, Ready: e.Ready()})
			}
			return printServices(c, rows, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON (data only on stdout)")
	cmd.Flags().StringVar(&kind, "type", "", "only this service: postgresql, mssql, clickhouse, s3 or vm")
	cmd.Flags().StringVar(&tenant, "tenant", "", "only this tenant (full name or 6 digit id)")
	return cmd
}

func printServices(c *cobra.Command, rows []serviceRow, asJSON bool) error {
	if asJSON {
		enc := json.NewEncoder(c.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}
	if len(rows) == 0 {
		say("No services found")
		return nil
	}
	w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TYPE\tTARGET\tSTATUS\tCLUSTER")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s/%s\t%s\t%s\n", display(r.Type), display(r.Tenant), display(r.Instance), display(r.Status), display(r.Cluster))
	}
	return w.Flush()
}

// connectCommand maps a service kind to the ocd command that opens it.
var connectCommand = map[services.Kind]string{
	services.Postgres: "psql", services.MSSQL: "mssql", services.ClickHouse: "clickhouse", services.VM: "ssh",
}

func newConnectCmd(cluster func() (config.Cluster, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "connect [<tenant>/<instance>]",
		Short: "Choose one of your services and connect to it",
		Long: "ocd connect lists your PostgreSQL, SQL Server, ClickHouse and VM instances,\n" +
			"lets you pick one with the arrow keys, then runs ocd psql, mssql, clickhouse or ssh.\n" +
			"Use ocd s3 for object storage.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			cl, err := cluster()
			if err != nil {
				return err
			}
			typed := ""
			if len(args) == 1 {
				typed = args[0]
			}
			ctx, stop := context.WithTimeout(context.Background(), 5*time.Minute)
			_, e, err := pickService(ctx, cl, typed, "connect", services.Postgres, services.MSSQL, services.ClickHouse, services.VM)
			stop()
			if err != nil {
				return err
			}
			sub, ok := connectCommand[e.Kind]
			if !ok {
				return fmt.Errorf("%s is %s: use ocd s3", e.Target(), e.Kind.Label())
			}
			self, err := os.Executable()
			if err != nil {
				return err
			}
			return runSSH(self, []string{"--cluster", cl.Name, sub, e.Target()}, os.Stdin, os.Stdout, os.Stderr)
		},
	}
}
