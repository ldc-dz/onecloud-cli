package cli

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"

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

// newTunnel builds a Pomerium TCP tunnel to dst ("host:port"), through the
// CONNECT endpoint pomeriumURL when set. An empty browserCmd opens the
// Pomerium sign-in page the same way as the opkssh one.
func newTunnel(dst, pomeriumURL, browserCmd string) (*tunnel.Tunnel, string, error) {
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
	browserCmd = tunnelBrowserCommand(browserCmd, runtime.GOOS)
	if browserCmd == helperMarker {
		browserCmd = ""
		// Pomerium runs `<browser command> <url>`: point it back at ocd.
		if self, err := os.Executable(); err == nil {
			_ = os.Setenv(browser.HelperEnv, "1")
			browserCmd = self
		}
	}
	return tunnel.New(
		tunnel.WithBrowserCommand(browserCmd),
		tunnel.WithDestinationHost(dstHost),
		tunnel.WithProxyHost(proxyURL.Host),
		tunnel.WithTLSConfig(tlsConfig),
	), dstHost, nil
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
			restore := filterPomeriumNotice(dst)
			defer restore()
			if err := tun.Run(ctx, stdio{os.Stdin, os.Stdout}, quietEvents{tunnel.LogEvents()}); err != nil {
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
