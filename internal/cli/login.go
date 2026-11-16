package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	simpleoidc "github.com/openpubkey/openpubkey/oidc"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/providers"
	opkcmd "github.com/openpubkey/opkssh/commands"
	opkconfig "github.com/openpubkey/opkssh/commands/config"
	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/browser"
	"github.com/ldc-dz/onecloud-cli/internal/cert"
	"github.com/ldc-dz/onecloud-cli/internal/config"
)

// signedInPage replaces opkssh's "You may now close this window" page. It
// closes the tab when the browser allows it (Chrome/Brave allow it for a tab
// with a single history entry, Firefox never does) and otherwise tells the
// user to go back to the terminal.
const signedInPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>OneCloud - signed in</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:90vh;margin:0;color:#1f2937}
main{text-align:center}h1{font-size:1.4rem;margin:0 0 .5rem}p{margin:0;color:#4b5563}</style></head>
<body><main><h1>Signed in to OneCloud</h1><p>You can go back to your terminal.</p></main>
<script>window.close();setTimeout(function(){window.close()},300)</script></body></html>`

// testOpenURL replaces the browser in tests.
var testOpenURL func(string) error

// browserOpener opens sign-in pages per the ocd config and OCD_BROWSER.
func browserOpener() browser.Opener {
	c, err := config.Load()
	if err != nil {
		return browser.New("")
	}
	return browser.New(c.Browser)
}

// login runs the embedded opkssh sign-in for cl and writes the key pair to
// cl.KeyPath() (+ "-cert.pub"). Browser mode is local-loopback only; device
// mode uses the issuer's RFC 8628 endpoint, no local listener, and a bounded
// 3-minute poll. The same provider verifies the ID token and binds the cert.
func login(cl config.Cluster, noBrowser bool) error { return loginWithMode(cl, noBrowser, false) }

const loginTimeout = 3 * time.Minute

func loginWithMode(cl config.Cluster, noBrowser, device bool) error {
	if os.Getenv("OCD_CLOUD_SHELL") == "1" && !device {
		return cloudShellLoginHint()
	}
	keyPath, err := cl.KeyPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	// Device sign-in uses the dedicated device-only client: the browser
	// client enforces PKCE, which the device request does not carry.
	clientID := cl.ClientID
	if device && cl.DeviceClientID != "" {
		clientID = cl.DeviceClientID
	}
	l := opkcmd.NewLogin(false, "", false, false, "", false, noBrowser, false,
		cl.Issuer+","+clientID, false, keyPath, "", opkcmd.ECDSA, "", false, nil, "")
	cc, err := opkconfig.NewClientConfig(opkconfig.DefaultClientConfig)
	if err != nil {
		return fmt.Errorf("opkssh client config: %w", err)
	}
	// Register the cluster issuer so opkssh finds it in its client config
	// (otherwise it warns "could not find issuer ... in client config").
	cc.Providers = append(cc.Providers, opkconfig.ProviderConfig{
		Issuer:       cl.Issuer,
		ClientID:     clientID,
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURIs: []string{"http://localhost:3000/login-callback", "http://localhost:10001/login-callback", "http://localhost:11110/login-callback"},
		DeviceFlow:   device,
	})
	l.Config = cc
	pc := opkconfig.ProviderConfig{
		Issuer: cl.Issuer, ClientID: clientID,
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURIs: cc.Providers[len(cc.Providers)-1].RedirectURIs,
		DeviceFlow:   device,
	}
	// opkssh's own opener would bring the browser forward; open the page
	// ourselves (in the background where possible). opkssh's own messages
	// only show with -v.
	provider, err := pc.ToProvider(false)
	if err != nil {
		return fmt.Errorf("opkssh provider: %w", err)
	}
	if sop, ok := provider.(*providers.StandardOp); ok {
		sop.OpenBrowser = false
		if device {
			// The upstream provider prints the verification URL and user code
			// via OutWriter. Never suppress these messages in device mode.
			sop.SetOutWriter(os.Stderr)
			sop.SetErrWriter(os.Stderr)
		} else {
			sop.SetOutWriter(libOutput())
			sop.SetErrWriter(libOutput())
			// Plain callback page: opkssh's HookHTTPSession shuts the
			// local server down before the default page reaches the browser.
			sop.CallbackHTML = signedInPage
			opener := browserOpener()
			sop.SetLoginURIHook(func(uri string) error {
				debugf("sign-in page %s", uri)
				if testOpenURL != nil {
					go func() { _ = testOpenURL(uri) }()
					return nil
				}
				if noBrowser || opener.Disabled() {
					say("Open this address in your browser: %s", uri)
					return nil
				}
				if err := opener.Open(uri); err != nil {
					say("Could not open your browser (%v). Open this address: %s", err, uri)
				}
				return nil
			})
		}
	}
	l.OutWriter = libOutput()
	l.ErrWriter = libOutput()
	signalCtx, stop := signalContext()
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, loginTimeout)
	defer cancel()
	if device {
		say("Signing in to %s with a device code (expires in %s)", cl.Name, loginTimeout)
	} else {
		say("Signing in to %s (in your browser)", cl.Name)
	}
	if sop, ok := provider.(*providers.StandardOp); ok {
		provider = progressOp{sop}
	}
	// Embedded opkssh also prints a non-sensitive identity to stdout;
	// continue to suppress it while keeping the device URL/code on stderr.
	if err := quietStdout(func() error { return l.Login(ctx, provider, false, keyPath) }); err != nil {
		if device {
			return fmt.Errorf("device sign-in failed (Keycloak client %s must enable the device grant): %w", clientID, err)
		}
		return fmt.Errorf("sign-in failed: %w", err)
	}
	say("SSH keys generated successfully")
	if info, err := cert.Read(keyPath); err == nil {
		info = info.WithMaxAge(cl.MaxAge())
		debugf("identity %s, key %s, valid until %s", info.KeyID, keyPath, info.ValidBefore.Local().Format(time.RFC3339))
	}
	return nil
}

// cloudShellLoginHint fails immediately rather than waiting for an OAuth
// callback that can only reach the user's laptop, not the pod's loopback.
func cloudShellLoginHint() error {
	return fmt.Errorf("Cloud Shell cannot use localhost browser callbacks. Run ocd login --device and enter the printed code in your own browser. Login expires after %s", loginTimeout)
}

func newLoginCmd(cluster func() (config.Cluster, error)) *cobra.Command {
	var noBrowser, device bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in with OneCloud SSO (opkssh) and write a short-lived SSH certificate",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cl, err := cluster()
			if err != nil {
				return err
			}
			if err := cl.SSHAvailable(); err != nil {
				return err
			}
			if noBrowser && device {
				return fmt.Errorf("--device and --no-browser cannot be combined; device sign-in always prints the link and code")
			}
			return loginWithMode(cl, noBrowser, device)
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the sign-in URL instead of opening a browser")
	cmd.Flags().BoolVar(&device, "device", false, "use an expiring device code without a localhost browser callback (Cloud Shell)")
	return cmd
}

// progressOp reports the end of the browser step: RequestTokens returns once
// Keycloak has redirected back with a code and the tokens were exchanged.
type progressOp struct{ *providers.StandardOp }

func (p progressOp) RequestTokens(ctx context.Context, cic *clientinstance.Claims) (*simpleoidc.Tokens, error) {
	t, err := p.StandardOp.RequestTokens(ctx, cic)
	if err == nil {
		say("Signed in successfully")
		say("Generating SSH keys")
	}
	return t, err
}
