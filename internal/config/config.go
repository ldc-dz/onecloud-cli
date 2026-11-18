// Package config holds the cluster settings ocd needs: the Keycloak issuer and
// client used for SSH sign-in, and the domain under which Pomerium publishes
// tenant TCP routes. Clusters are built in; a local YAML file can override them.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Cluster is one OneCloud cluster as seen by ocd.
type Cluster struct {
	Name string `yaml:"-"`
	// Enabled gates whether ocd will talk to this cluster.
	Enabled *bool `yaml:"enabled,omitempty"`
	// Issuer is the Keycloak realm URL used for the opkssh sign-in.
	Issuer string `yaml:"issuer,omitempty"`
	// ClientID is the public PKCE client used for the opkssh sign-in.
	ClientID string `yaml:"clientID,omitempty"`
	// DeviceClientID is the public device-only client used by
	// `ocd login --device` (Keycloak refuses device requests without PKCE on
	// the PKCE client). Empty: device sign-in falls back to ClientID.
	DeviceClientID string `yaml:"deviceClientID,omitempty"`
	// TCPDomain is the Pomerium TCP route domain; VM SSH hosts are
	// <vm>-ssh-<tenant id>.<TCPDomain>.
	TCPDomain string `yaml:"tcpDomain,omitempty"`
	// Reason explains why a disabled cluster is disabled.
	Reason string `yaml:"reason,omitempty"`
	// TokenMaxAge mirrors the VM opkssh expiration policy (ssoAccess.tokenExpiry):
	// a sign-in is accepted for this long after the ID token was issued, whatever
	// its exp says. "oidc" means the token exp is the limit. Default "12h".
	TokenMaxAge string `yaml:"tokenMaxAge,omitempty"`
	// SSH gates VM SSH sign-on (ocd login, ocd ssh) on an enabled cluster.
	// Unset means enabled.
	SSH *bool `yaml:"ssh,omitempty"`
	// SSHReason explains why VM SSH sign-on is off.
	SSHReason string `yaml:"sshReason,omitempty"`
	// PomeriumURL is the shared Pomerium CONNECT endpoint for TCP routes
	// (pomerium-cli --pomerium-url). Empty: the route host itself answers.
	PomeriumURL string `yaml:"pomeriumURL,omitempty"`
	// PostgresIssuer and PostgresClientID are the OAuth settings libpq uses
	// for managed PostgreSQL sign-on (oauth_issuer, oauth_client_id).
	PostgresIssuer   string `yaml:"postgresIssuer,omitempty"`
	PostgresClientID string `yaml:"postgresClientID,omitempty"`
	// PortalURL and PortalClientID let ocd read the portal connection
	// inventory (instance CA certificates) after a browser sign-in with the
	// portal public client, in the Issuer realm. Empty: no download.
	PortalURL      string `yaml:"portalURL,omitempty"`
	PortalClientID string `yaml:"portalClientID,omitempty"`
	// ShellClientID is the Keycloak client of OneCloud Shell. Inside the
	// Shell (OCD_CLOUD_SHELL=1) no loopback sign-in is possible: the Shell
	// broker writes the user's portal session, issued to this client, into
	// the ocd portal cache, and ocd reads the inventory with it.
	ShellClientID string `yaml:"shellClientID,omitempty"`
	// S3SSOEndpoint is the object-storage gateway that accepts a OneCloud
	// Portal sign-in (STS AssumeRoleWithWebIdentity). Empty: ocd s3 uses the
	// static keys published by the portal.
	S3SSOEndpoint string `yaml:"s3SSOEndpoint,omitempty"`
	// S3SSOClientID is the Keycloak client whose ID token the gateway trusts.
	S3SSOClientID string `yaml:"s3SSOClientID,omitempty"`
	// S3SSOFlow is "pkce" (browser sign-in, silent with an open Keycloak
	// session) or "device" (code to approve). Default "device"; dev uses pkce.
	S3SSOFlow string `yaml:"s3SSOFlow,omitempty"`
}

// SSHAvailable reports whether VM SSH sign-on may be used on this cluster.
func (c Cluster) SSHAvailable() error {
	if c.SSH == nil || *c.SSH {
		return nil
	}
	reason := c.SSHReason
	if reason == "" {
		reason = "disabled in ocd config"
	}
	return fmt.Errorf("VM SSH sign-on is not available on %s: %s", c.Name, reason)
}

// PostgresAvailable reports whether managed PostgreSQL sign-on is configured.
func (c Cluster) PostgresAvailable() error {
	if c.PostgresIssuer == "" || c.PostgresClientID == "" {
		return fmt.Errorf("PostgreSQL sign-on is not configured on %s (postgresIssuer, postgresClientID)", c.Name)
	}
	return nil
}

// MaxAge returns the sign-in lifetime the VMs accept, or 0 when the ID token
// exp claim is the limit ("oidc").
func (c Cluster) MaxAge() time.Duration {
	switch c.TokenMaxAge {
	case "", "12h":
		return 12 * time.Hour
	case "24h":
		return 24 * time.Hour
	case "48h":
		return 48 * time.Hour
	case "1week":
		return 7 * 24 * time.Hour
	default:
		return 0
	}
}

// IsEnabled reports whether the cluster may be used.
func (c Cluster) IsEnabled() bool { return c.Enabled != nil && *c.Enabled }

// Config is the effective ocd configuration.
type Config struct {
	DefaultCluster string             `yaml:"defaultCluster,omitempty"`
	Clusters       map[string]Cluster `yaml:"clusters,omitempty"`
	// Browser is the command that opens sign-in pages ("{url}" is replaced
	// by the address, "none" only prints it). Empty: open them in the
	// background where the platform allows it. OCD_BROWSER overrides it.
	Browser string `yaml:"browser,omitempty"`
}

func boolPtr(b bool) *bool { return &b }

// Builtin returns the clusters compiled into ocd.
func Builtin() Config {
	return Config{
		DefaultCluster: "ocd-prd-01",
		Clusters: map[string]Cluster{
			"ocd-dev-01": {
				Enabled:          boolPtr(true),
				Issuer:           "https://auth.dev-01.onecloud.ldc.dz/realms/dev-01-portal",
				ClientID:         "onecloud-ssh",
				DeviceClientID:   "onecloud-ssh-device",
				TCPDomain:        "tcp.access.dev-01.onecloud.ldc.dz",
				PostgresIssuer:   "https://auth.dev-01.onecloud.ldc.dz/realms/dev-01-portal",
				PostgresClientID: "dev-01-postgresql",
				PortalURL:        "https://portal.dev-01.onecloud.ldc.dz",
				PortalClientID:   "dev-01-portal-tui",
				ShellClientID:    "dev-01-shell",
				S3SSOEndpoint:    "https://s3-sso.dev-01.onecloud.ldc.dz",
				S3SSOClientID:    "onecloud-s3",
				S3SSOFlow:        "pkce",
			},
			"ocd-prd-01": {
				Enabled:          boolPtr(true),
				Issuer:           productionIssuer,
				ClientID:         "onecloud-ssh",
				DeviceClientID:   "onecloud-ssh-device",
				TCPDomain:        "tcp.access.onecloud.ldc.dz",
				PomeriumURL:      "https://access.onecloud.ldc.dz:8443",
				PostgresIssuer:   productionIssuer,
				PostgresClientID: "prd-01-postgresql",
				PortalURL:        productionPortal,
				PortalClientID:   "prd-01-portal-tui",
				ShellClientID:    "prd-01-shell",
				S3SSOEndpoint:    "https://s3-sso.onecloud.ldc.dz",
				S3SSOClientID:    "onecloud-s3",
				S3SSOFlow:        "pkce",
			},
		},
	}
}

// Dir returns the ocd config directory (~/.config/ocd, %APPDATA%\ocd on Windows).
func Dir() (string, error) {
	if d := os.Getenv("OCD_CONFIG_DIR"); d != "" {
		return d, nil
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "ocd"), nil
}

// Path returns the override file path.
func Path() (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "config.yaml"), nil
}

// Merge overlays o on top of c, field by field.
func (c Config) Merge(o Config) Config {
	out := Config{DefaultCluster: c.DefaultCluster, Browser: c.Browser, Clusters: map[string]Cluster{}}
	if o.Browser != "" {
		out.Browser = o.Browser
	}
	for k, v := range c.Clusters {
		out.Clusters[k] = v
	}
	if o.DefaultCluster != "" {
		out.DefaultCluster = o.DefaultCluster
	}
	for k, v := range o.Clusters {
		base := out.Clusters[k]
		if v.Enabled != nil {
			base.Enabled = v.Enabled
		}
		if v.Issuer != "" {
			base.Issuer = v.Issuer
		}
		if v.ClientID != "" {
			base.ClientID = v.ClientID
		}
		if v.DeviceClientID != "" {
			base.DeviceClientID = v.DeviceClientID
		}
		if v.TCPDomain != "" {
			base.TCPDomain = v.TCPDomain
		}
		if v.Reason != "" {
			base.Reason = v.Reason
		}
		if v.TokenMaxAge != "" {
			base.TokenMaxAge = v.TokenMaxAge
		}
		if v.SSH != nil {
			base.SSH = v.SSH
		}
		if v.SSHReason != "" {
			base.SSHReason = v.SSHReason
		}
		if v.PomeriumURL != "" {
			base.PomeriumURL = v.PomeriumURL
		}
		if v.PostgresIssuer != "" {
			base.PostgresIssuer = v.PostgresIssuer
		}
		if v.PostgresClientID != "" {
			base.PostgresClientID = v.PostgresClientID
		}
		if v.PortalURL != "" {
			base.PortalURL = v.PortalURL
		}
		if v.PortalClientID != "" {
			base.PortalClientID = v.PortalClientID
		}
		if v.S3SSOEndpoint != "" {
			base.S3SSOEndpoint = v.S3SSOEndpoint
		}
		if v.S3SSOClientID != "" {
			base.S3SSOClientID = v.S3SSOClientID
		}
		if v.S3SSOFlow != "" {
			base.S3SSOFlow = v.S3SSOFlow
		}
		if v.ShellClientID != "" {
			base.ShellClientID = v.ShellClientID
		}
		out.Clusters[k] = base
	}
	for k, v := range out.Clusters {
		v.Name = k
		out.Clusters[k] = v
	}
	return out
}

// Parse reads an override document.
func Parse(data []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse ocd config: %w", err)
	}
	return c, nil
}

// Load returns the built-in config merged with the override file, if any.
func Load() (Config, error) {
	c := Builtin().Merge(Config{})
	p, err := Path()
	if err != nil {
		return c, nil
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return Config{}, err
	}
	o, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", p, err)
	}
	return c.Merge(o), nil
}

// Cluster returns the named (or default) cluster, refusing disabled ones.
func (c Config) Cluster(name string) (Cluster, error) {
	if name == "" {
		name = c.DefaultCluster
	}
	cl, ok := c.Clusters[name]
	if !ok {
		return Cluster{}, fmt.Errorf("unknown cluster %q (known: %v)", name, c.Names())
	}
	if !cl.IsEnabled() {
		reason := cl.Reason
		if reason == "" {
			reason = "disabled in ocd config"
		}
		return Cluster{}, fmt.Errorf("cluster %s is not available: %s", name, reason)
	}
	if cl.Issuer == "" || cl.ClientID == "" || cl.TCPDomain == "" {
		return Cluster{}, fmt.Errorf("cluster %s is missing issuer, clientID or tcpDomain", name)
	}
	for _, f := range []struct{ field, value string }{
		{"issuer", cl.Issuer}, {"postgresIssuer", cl.PostgresIssuer}, {"portalURL", cl.PortalURL},
	} {
		if err := CheckEndpoint(f.value, false); err != nil {
			return Cluster{}, fmt.Errorf("cluster %s: %s: %w", name, f.field, err)
		}
	}
	if err := CheckEndpoint(cl.S3SSOEndpoint, true); err != nil {
		return Cluster{}, fmt.Errorf("cluster %s: s3SSOEndpoint: %w", name, err)
	}
	if err := CheckEndpoint(cl.PomeriumURL, true); err != nil {
		return Cluster{}, fmt.Errorf("cluster %s: pomeriumURL: %w", name, err)
	}
	// In OneCloud Shell the portal session comes from the Shell broker, so it
	// is issued to the Shell client, not to the loopback CLI client.
	if InCloudShell() && cl.ShellClientID != "" {
		cl.PortalClientID = cl.ShellClientID
	}
	return cl, nil
}

// InCloudShell reports whether ocd runs in a OneCloud Shell session.
func InCloudShell() bool { return os.Getenv("OCD_CLOUD_SHELL") == "1" }

// CheckEndpoint accepts an empty value or an https URL. Plain http is only
// accepted towards a loopback address (local tests and development). With
// hostOnly the URL must be scheme://host[:port] (no path, query or user).
func CheckEndpoint(raw string, hostOnly bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	if u.User != nil {
		return fmt.Errorf("URL %q must not hold credentials", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); !(u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
			return fmt.Errorf("URL %q must use https", raw)
		}
	default:
		return fmt.Errorf("URL %q must use https", raw)
	}
	if hostOnly && (strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "") {
		return fmt.Errorf("URL %q must be scheme://host[:port] only", raw)
	}
	return nil
}

// Names lists the known clusters, sorted.
func (c Config) Names() []string {
	n := make([]string, 0, len(c.Clusters))
	for k := range c.Clusters {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// Provider returns the opkssh provider string "<issuer>,<client id>".
func (c Cluster) Provider() string { return c.Issuer + "," + c.ClientID }

// KeyPath returns the per-cluster opkssh key path (~/.ssh/ocd-<cluster>).
// The certificate sits next to it as <KeyPath>-cert.pub.
func (c Cluster) KeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "ocd-"+c.Name), nil
}
