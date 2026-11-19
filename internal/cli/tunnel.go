package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/cli/tunnel"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/browser"
	"github.com/ldc-dz/onecloud-cli/internal/config"
)

type stdio struct {
	io.Reader
	io.Writer
}

// quietEvents keeps pomerium-cli's event logging but does not report a
// normal end of session (ssh closing the tunnel) as an error.
type quietEvents struct{ tunnel.EventSink }

func (q quietEvents) OnDisconnected(ctx context.Context, err error) {
	if isNormalClose(err) {
		log.Ctx(ctx).Debug().Msg("disconnected")
		return
	}
	q.EventSink.OnDisconnected(ctx, err)
}

func isNormalClose(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) ||
		errors.Is(err, net.ErrClosed)
}

// setupTunnelLogging sends pomerium-cli's zerolog output to stderr at warn
// level (debug with -v, OCD_LOG_LEVEL wins).
func setupTunnelLogging() {
	level := zerolog.WarnLevel
	if verbose() {
		level = zerolog.DebugLevel
	}
	if raw := os.Getenv("OCD_LOG_LEVEL"); raw != "" {
		if l, err := zerolog.ParseLevel(raw); err == nil {
			level = l
		}
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: true}).Level(level)
	zerolog.DefaultContextLogger = &log.Logger
}

// accessTunnel is a Pomerium TCP tunnel to dst and how its sign-in page is
// shown.
type accessTunnel struct {
	*tunnel.Tunnel
	dst string
	// ocdOpens: ocd shows the gateway sign-in page itself (announceSignIn)
	// and pomerium-cli is given a browser command that does nothing. When
	// false, pomerium-cli opens the page (macOS default opener, or the
	// --browser-cmd application) and prints its own notice.
	ocdOpens bool
}

// selfExecutable is replaced in tests, where the running binary is the test
// binary and must not be started as the browser command.
var selfExecutable = os.Executable

// newTunnel builds a Pomerium TCP tunnel to dst ("host:port"), through the
// CONNECT endpoint pomeriumURL when set. An empty browserCmd opens the
// Pomerium sign-in page the same way as the opkssh one.
func newTunnel(dst, pomeriumURL, browserCmd string) (*accessTunnel, string, error) {
	// --gateway-url comes from the command line (ssh ProxyCommand), not only
	// from the validated config: refuse plain http to a remote gateway, which
	// would carry the gateway session without TLS.
	if err := config.CheckEndpoint(pomeriumURL, true); err != nil {
		return nil, "", fmt.Errorf("--gateway-url: %w", err)
	}
	dstHost, proxyURL, err := tunnel.ParseURLs(dst, pomeriumURL)
	if err != nil {
		return nil, "", err
	}
	var tlsConfig *tls.Config
	if proxyURL.Scheme == "https" {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	ocdOpens := false
	browserCmd = tunnelBrowserCommand(browserCmd, runtime.GOOS)
	if browserCmd == helperMarker {
		browserCmd = ""
		// Pomerium runs `<browser command> <url>` and gives up the sign-in
		// when that command fails, which is what happens on a machine with
		// no browser opener (WSL, a server) or with OCD_BROWSER=none. Point
		// it at ocd itself, which only acknowledges the call (see
		// browser.HelperMain): ocd shows the page from announceSignIn.
		if self, err := selfExecutable(); err == nil {
			_ = os.Setenv(browser.HelperEnv, "1")
			browserCmd = self
			ocdOpens = true
		}
	}
	return &accessTunnel{
		Tunnel: tunnel.New(
			tunnel.WithBrowserCommand(browserCmd),
			tunnel.WithDestinationHost(dstHost),
			tunnel.WithProxyHost(proxyURL.Host),
			tunnel.WithTLSConfig(tlsConfig),
		),
		dst:      dstHost,
		ocdOpens: ocdOpens,
	}, dstHost, nil
}

// announceSignIn shows the access-gateway sign-in page: it opens the browser
// when one can be opened, and always prints the address, so a headless
// machine (WSL without a browser opener, a server, OCD_BROWSER=none,
// --no-browser) is never left waiting on a page nobody can see.
func (t *accessTunnel) announceSignIn(authURL string, noBrowser bool) {
	if !t.ocdOpens {
		return // pomerium-cli opens the page and prints its own notice
	}
	opener := browserOpener()
	if noBrowser || opener.Disabled() {
		say("Authorize access to %s: open this address in your browser: %s", t.dst, authURL)
		return
	}
	if err := opener.Open(authURL); err != nil {
		debugf("access-gateway sign-in page not opened: %v", err)
		say("Authorize access to %s: no browser could be opened from here, open this address in your browser: %s", t.dst, authURL)
		return
	}
	say("Authorizing access to %s (in your browser)", t.dst)
	say("If no browser tab opened, visit: %s", authURL)
}

// filterNotice hides pomerium-cli's own "Your browser has been opened" block
// until the returned function is called. When ocd announces the sign-in
// itself the block is dropped, otherwise it becomes one short line.
func (t *accessTunnel) filterNotice() func() {
	if t.ocdOpens {
		return filterPomeriumNotice("")
	}
	return filterPomeriumNotice(t.dst)
}

// gatewayEvents is the event sink of one tunnelled connection.
type gatewayEvents struct {
	tunnel.EventSink
	tun       *accessTunnel
	noBrowser bool
	connected atomic.Bool
	onConnect func()
}

func (t *accessTunnel) events(noBrowser bool) *gatewayEvents {
	return &gatewayEvents{EventSink: quietEvents{tunnel.LogEvents()}, tun: t, noBrowser: noBrowser}
}

func (g *gatewayEvents) OnAuthRequired(ctx context.Context, authURL string) {
	g.EventSink.OnAuthRequired(ctx, authURL)
	g.tun.announceSignIn(authURL, g.noBrowser)
}

func (g *gatewayEvents) OnConnected(ctx context.Context) {
	g.connected.Store(true)
	g.EventSink.OnConnected(ctx)
	if g.onConnect != nil {
		g.onConnect()
	}
}

// gatewayCheckTimeout bounds the gateway sign-in wait of check (shortened in
// tests).
var gatewayCheckTimeout = 5 * time.Minute

// idleConn is the local end of the check connection: it sends nothing and
// reads as closed once done is closed. Ending the check with a clean close
// (not a cancelled context) matters: pomerium-cli drops the saved gateway
// session when a tunnel ends with an error, which would ask the user to sign
// in a second time for the client's own connection.
type idleConn struct{ done <-chan struct{} }

func (c idleConn) Read([]byte) (int, error)    { <-c.done; return 0, io.EOF }
func (c idleConn) Write(p []byte) (int, error) { return len(p), nil }

// check signs in to the access gateway when needed and proves that the
// destination answers through it, before any native client is started. The
// client would otherwise only see its local connection being reset, with no
// word about the gateway. target is what the user typed (tenant/instance).
// The gateway session obtained here is cached and reused by the client's
// connections.
func (t *accessTunnel) check(ctx context.Context, target string, noBrowser bool) error {
	ctx, cancel := context.WithTimeout(ctx, gatewayCheckTimeout)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()
	established := make(chan struct{})
	var once sync.Once
	closeLocal := func() { once.Do(func() { close(established) }) }
	// A failed attempt never reads the local end; release it anyway.
	defer closeLocal()
	ev := t.events(noBrowser)
	ev.onConnect = closeLocal
	err := t.Run(ctx, idleConn{established}, ev)
	if ev.connected.Load() {
		return nil
	}
	return gatewayError(target, t.dst, err)
}

// gatewayError turns a pomerium-cli tunnel failure into what failed and what
// to do. pomerium-cli does not export its error values, so the text decides.
func gatewayError(target, dst string, err error) error {
	if err == nil {
		return fmt.Errorf("the OneCloud access gateway closed the connection to %s before it was established; run the command again", target)
	}
	text := err.Error()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("access to %s was not authorized in time: the access-gateway sign-in was not completed within %s; run the command again and open the address ocd prints in a browser on this machine",
			target, gatewayCheckTimeout)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("access to %s was not authorized: the access-gateway sign-in was interrupted", target)
	case strings.Contains(text, "failed to open browser url"):
		return fmt.Errorf("access to %s was not authorized: the access-gateway sign-in page could not be opened (%v); set OCD_BROWSER=none to have ocd print the address, then open it in a browser on this machine", target, err)
	case strings.Contains(text, "failed to get authentication JWT"):
		return fmt.Errorf("access to %s was not authorized: the access-gateway sign-in failed (%v); run the command again", target, err)
	case strings.Contains(text, "unauthorized"):
		return fmt.Errorf("the OneCloud access gateway refused %s for your account (403): check that you are a member of the tenant and may use this instance", target)
	case strings.Contains(text, "unavailable"):
		return fmt.Errorf("the OneCloud access gateway cannot reach %s (503): the instance is stopped or still starting; check its status in the portal and try again in a few minutes", target)
	case strings.Contains(text, "invalid http response code: 404"):
		return fmt.Errorf("the OneCloud access gateway has no route to %s yet (404 for %s): check in the portal that the instance is ready, then try again in a few minutes", target, dst)
	case strings.Contains(text, "failed to establish connection to proxy"):
		return fmt.Errorf("cannot reach the OneCloud access gateway for %s (%v): check your internet connection and that outbound TCP to the gateway is allowed", target, err)
	}
	return fmt.Errorf("cannot reach %s through the OneCloud access gateway: %v", target, err)
}

// helperMarker means "use ocd itself as the Pomerium browser command".
const helperMarker = "\x00ocd-helper"

// tunnelBrowserCommand picks the browser command handed to pomerium-cli.
// pomerium-cli runs a custom command as `open -a <command> <url>` on macOS,
// which only accepts an application name: the ocd binary cannot be used
// there, so macOS keeps the system default opener (or the --browser-cmd
// application, e.g. "Firefox"). Elsewhere ocd opens the page itself.
func tunnelBrowserCommand(flag, goos string) string {
	if flag != "" {
		return flag
	}
	if goos == "darwin" {
		return ""
	}
	return helperMarker
}

func newTunnelCmd() *cobra.Command {
	var browserCmd, pomeriumURL string
	cmd := &cobra.Command{
		Use:   "tunnel <host:port>",
		Short: "Open a OneCloud access-gateway TCP tunnel on stdin/stdout (used by SSH)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			setupTunnelLogging()
			tun, dst, err := newTunnel(args[0], pomeriumURL, browserCmd)
			if err != nil {
				return err
			}
			ctx, cancel := signalContext()
			defer cancel()
			restore := tun.filterNotice()
			defer restore()
			ev := tun.events(false)
			if err := tun.Run(ctx, stdio{os.Stdin, os.Stdout}, ev); err != nil {
				if !ev.connected.Load() {
					// Never connected: say why (sign-in, route, membership)
					// instead of a bare transport error under ssh.
					return gatewayError(dst, dst, err)
				}
				return fmt.Errorf("tunnel to %s failed: %w", dst, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&browserCmd, "browser-cmd", "", "command used to open the access-gateway sign-in page (default: ocd's background opener)")
	cmd.Flags().StringVar(&pomeriumURL, "gateway-url", "", "shared OneCloud access-gateway endpoint, e.g. https://access.onecloud.ldc.dz:8443")
	// Preserve scripts using the original internal transport flag without
	// exposing a vendor name in user-facing command help.
	cmd.Flags().StringVar(&pomeriumURL, "pomerium-url", "", "deprecated: use --gateway-url")
	_ = cmd.Flags().MarkHidden("pomerium-url")
	return cmd
}
