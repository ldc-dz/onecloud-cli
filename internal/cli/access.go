package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mattn/go-isatty"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/portal"
	"github.com/ldc-dz/onecloud-cli/internal/portalcache"
)

const directProbeTimeout = 1500 * time.Millisecond

// PostgreSQL always speaks on 5432 in production. Tests substitute an
// ephemeral listener to exercise end-to-end direct psql without privileged
// ports or a local PostgreSQL server.
var postgresPort = 5432

// Cloud Shell's SSO callback is on the browser-facing shell server, not on
// the toolbox loopback. Cached portal sessions are still usable but fresh
// native loopback portal sign-ins must never run inside a remote shell.
func nativePortalAvailable() bool { return os.Getenv("OCD_CLOUD_SHELL") != "1" }

var errPortalNonInteractive = errors.New("portal lookup skipped: no saved portal session and no local interactive terminal/browser")

// errCloudShellGateway: the access gateway signs in through a browser
// callback, which OneCloud Shell cannot receive.
var errCloudShellGateway = errors.New("OneCloud Shell cannot sign in to the access gateway (it needs a browser); connect over your tenant network instead: ocd ssh --via direct --address <SSH host shown in the portal> <tenant>/<vm>")
var errCloudShellPortal = errors.New("Cloud Shell cannot complete the portal's localhost callback; use an existing session or --via proxied")

func maySignInPortal(force bool) bool {
	if !nativePortalAvailable() {
		return false
	}
	if force {
		return true
	}
	// Explicitly configured browser commands can work without a TTY (e.g.
	// a desktop launcher); a headless script must not accidentally launch
	// the browser or block on a loopback callback. 'none' is headless too.
	opener := browserOpener()
	return isatty.IsTerminal(os.Stdin.Fd()) || (opener.Command != "" && !opener.Disabled())
}

func portalStore() (portalcache.Store, error) {
	dir, err := config.Dir()
	return portalcache.Store{Dir: dir}, err
}

func validateVia(via string) error {
	switch via {
	case "auto", "direct", "proxied":
		return nil
	default:
		return fmt.Errorf("invalid --via %q: use auto, direct, or proxied", via)
	}
}

// validAddress accepts only IP addresses; the portal address and user override
// must never be treated as shell commands or public gateway hostnames.
func validAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if net.ParseIP(address) == nil {
		return "", fmt.Errorf("invalid tenant-network IP address %q", address)
	}
	return address, nil
}

// directHostName is a DNS host name (letters, digits, '-' and '.', no
// trailing dot): the tenant-network SSH host the portal shows, e.g.
// vm-ssh.tenant-x.svc.cluster.local. A numeric last label would be an IP
// literal to the resolver, so it is refused here and left to validAddress.
var directHostName = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// validDirectAddress accepts what an explicit --via direct may dial: a
// tenant-network IP, or a host name the user typed or copied from the
// portal. Portal lookups and the auto probe stay IP-only (validAddress).
func validDirectAddress(address string) (string, error) {
	address = strings.TrimSpace(address)
	if net.ParseIP(address) != nil {
		return address, nil
	}
	labels := strings.Split(address, ".")
	if len(address) <= 253 && directHostName.MatchString(address) && strings.Trim(labels[len(labels)-1], "0123456789") != "" {
		return address, nil
	}
	return "", fmt.Errorf("invalid tenant-network address %q: use an IP address or a host name", address)
}

// probeTCP checks that the chosen service port actually accepts a TCP
// connection. A successful dial says only that the network path is up; SSH
// or PostgreSQL still verifies the server independently.
func probeTCP(address string, port int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), directProbeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(address, fmt.Sprint(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// accessPath returns "direct" or "proxied"; explicit direct never silently
// fails over to the gateway, even when the address does not answer.
func accessPath(via, address string, port int) (string, error) {
	if err := validateVia(via); err != nil {
		return "", err
	}
	if via == "proxied" {
		return "proxied", nil
	}
	if address == "" {
		if via == "direct" {
			return "", errors.New("no tenant-network address published for this instance; provide --address for SSH or use --via proxied")
		}
		return "proxied", nil
	}
	if via == "direct" {
		if _, err := validDirectAddress(address); err != nil {
			return "", err
		}
		return "direct", nil
	}
	if _, err := validAddress(address); err != nil {
		return "proxied", nil
	}
	if via == "auto" && !probeTCP(address, port) {
		return "proxied", nil
	}
	return "direct", nil
}

func sayAccessPath(path string) {
	if path == "direct" {
		say("Connecting directly over your tenant network")
	} else {
		say("Connecting via the OneCloud access gateway")
	}
}

// portalInventory prefers a time-limited, mode-0600 bearer cache. A headless
// process with no saved token never opens an interactive sign-in unless the
// caller explicitly requested --via direct. It falls back to the gateway
// immediately in auto mode. The portal still scopes every GET.
func portalInventory(cl config.Cluster, force bool) (portal.Client, string, []portal.Connection, error) {
	if cl.PortalURL == "" || cl.PortalClientID == "" {
		return portal.Client{}, "", nil, errors.New("portal inventory not configured on this cluster")
	}
	store, err := portalStore()
	if err != nil {
		return portal.Client{}, "", nil, err
	}
	opener := browserOpener()
	c := portal.Client{
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cached, err := store.Token(cl)
	if err != nil {
		return c, "", nil, err
	}
	if cached != "" {
		conns, err := c.Connections(ctx, cached)
		if err == nil {
			return c, cached, conns, nil
		}
		if !errors.Is(err, portal.ErrUnauthorized) {
			return c, "", nil, err
		}
		if err := store.Clear(cl); err != nil {
			return c, "", nil, err
		}
	}
	if !nativePortalAvailable() {
		return c, "", nil, errCloudShellPortal
	}
	if !maySignInPortal(force) {
		return c, "", nil, errPortalNonInteractive
	}
	say("Reading your OneCloud connections (sign in in your browser)")
	token, err := c.SignInWithExpiry(ctx, func(token string, _ time.Time) {
		if err := store.SaveToken(cl, token); err != nil {
			say("Warning: could not save the portal session for later runs: %v", err)
		}
	})
	if err != nil {
		return c, "", nil, err
	}
	conns, err := c.Connections(ctx, token)
	if errors.Is(err, portal.ErrUnauthorized) {
		if clearErr := store.Clear(cl); clearErr != nil {
			return c, "", nil, clearErr
		}
	}
	return c, token, conns, err
}

// portalVPC first checks a two-minute, tenant-scoped address cache. A saved
// CA is independent of that cache, so a caller needing the first CA can ask
// for an inventory even when the address is already cached.
func portalVPC(cl config.Cluster, engine, tenant, instance string, needInventory, force bool) (string, []portal.Connection, error) {
	store, err := portalStore()
	if err != nil {
		return "", nil, err
	}
	address, err := store.Address(cl, engine, tenant, instance)
	if err != nil {
		return "", nil, err
	}
	if address != "" && !needInventory {
		return address, nil, nil
	}
	client, token, conns, err := portalInventory(cl, force)
	if err != nil {
		return "", nil, err
	}
	if address == "" {
		if engine == "vm" {
			address, err = instanceVPC(client, token, conns, cl, engine, tenant, instance)
		} else {
			address, err = portal.FindVPCAddress(conns, cl.Name, engine, tenant, instance)
		}
		if err == nil {
			if saveErr := store.SaveAddress(cl, token, engine, tenant, instance, address); saveErr != nil {
				debugf("could not save tenant-network address: %v", saveErr)
			}
		}
	}
	return address, conns, err
}

// instanceVPC first uses the canonical connection descriptor field. VM
// connection descriptors are not available on all portal versions, so fall
// back to the tenant-scoped provisioning ledger's vpc.address facade output.
func instanceVPC(c portal.Client, token string, conns []portal.Connection, cl config.Cluster, engine, tenant, instance string) (string, error) {
	address, err := portal.FindVPCAddress(conns, cl.Name, engine, tenant, instance)
	if err == nil || engine != "vm" || (!errors.Is(err, portal.ErrNotFound) && !errors.Is(err, portal.ErrNoVPC)) {
		return address, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	instances, fetchErr := c.Instances(ctx, token)
	if fetchErr != nil {
		if errors.Is(fetchErr, portal.ErrUnauthorized) {
			if store, err := portalStore(); err == nil {
				if clearErr := store.Clear(cl); clearErr != nil {
					debugf("could not clear revoked portal session: %v", clearErr)
				}
			}
		}
		return "", fetchErr
	}
	return portal.FindInstanceVPC(instances, cl.Name, tenant, instance)
}
