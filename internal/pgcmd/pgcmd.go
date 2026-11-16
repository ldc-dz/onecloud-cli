// Package pgcmd builds the psql invocation for a OneCloud managed PostgreSQL
// instance reached over a tenant network or gateway, and keeps the instance CA
// certificates ocd was given.
package pgcmd

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// MinMajor is the first psql/libpq release with OAuth (device flow) sign-in.
const MinMajor = 18

// Options describe one connection.
type Options struct {
	ServerName string // name in the instance certificate (host=)
	Port       int    // local tunnel port or PostgreSQL service port
	Address    string // hostaddr: tenant VPC IP for direct; empty uses 127.0.0.1
	Database   string
	User       string
	CAFile     string
	Issuer     string
	ClientID   string
}

// ConnInfo returns the libpq keyword/value connection string. host is the
// certificate name and hostaddr the VPC address (or the local gateway
// tunnel), so sslmode=verify-full verifies the real server on either path.
func ConnInfo(o Options) string {
	address := o.Address
	if address == "" {
		address = "127.0.0.1"
	}
	kv := [][2]string{
		{"host", o.ServerName},
		{"hostaddr", address},
		{"port", strconv.Itoa(o.Port)},
		{"dbname", o.Database},
		{"user", o.User},
		{"sslmode", "verify-full"},
		{"sslrootcert", o.CAFile},
		{"oauth_issuer", o.Issuer},
		{"oauth_client_id", o.ClientID},
	}
	parts := make([]string, 0, len(kv))
	for _, p := range kv {
		parts = append(parts, p[0]+"="+quote(p[1]))
	}
	return strings.Join(parts, " ")
}

// quote applies libpq conninfo quoting when a value needs it.
func quote(v string) string {
	if v != "" && !strings.ContainsAny(v, " \t'\\") {
		return v
	}
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
}

var versionRe = regexp.MustCompile(`\(PostgreSQL\)\s+(\d+)`)

// Major parses the major version from `psql --version` output.
func Major(versionOutput string) (int, error) {
	m := versionRe.FindStringSubmatch(versionOutput)
	if m == nil {
		return 0, fmt.Errorf("cannot read the psql version from %q", strings.TrimSpace(versionOutput))
	}
	return strconv.Atoi(m[1])
}

// CheckVersion refuses a psql older than MinMajor.
func CheckVersion(versionOutput string) error {
	major, err := Major(versionOutput)
	if err != nil {
		return err
	}
	if major < MinMajor {
		return fmt.Errorf("psql %d found, but OneCloud sign-in needs psql %d or newer (%s)", major, MinMajor, strings.TrimSpace(versionOutput))
	}
	return nil
}

// ErrNoCA means ocd has no CA certificate for the instance yet.
var ErrNoCA = errors.New("no CA certificate for this instance")

// CAStore keeps instance CA certificates under <dir>/<cluster>/<tenant>/<instance>-ca.crt.
type CAStore struct{ Dir string }

// Path returns where the CA of an instance is kept.
func (s CAStore) Path(cluster, tenant, instance string) string {
	return filepath.Join(s.Dir, cluster, tenant, instance+"-ca.crt")
}

// Resolve returns the CA file to use: explicit (the --ca flag) first, then
// the stored copy. An explicit file is validated and copied into the store
// so later runs need nothing.
//
// A trust anchor is never picked up implicitly from the working directory:
// a certificate planted in a shared or cloned directory must not become the
// TLS root. Without --ca or a stored copy the caller downloads the CA from
// the authenticated portal (ErrNoCA).
func (s CAStore) Resolve(cluster, tenant, instance, explicit string) (path string, source string, err error) {
	stored := s.Path(cluster, tenant, instance)
	if explicit != "" {
		data, err := os.ReadFile(explicit)
		if err != nil {
			return "", "", fmt.Errorf("CA certificate: %w", err)
		}
		if err := validCA(data); err != nil {
			return "", "", fmt.Errorf("%s: %w", explicit, err)
		}
		if err := os.MkdirAll(filepath.Dir(stored), 0o700); err != nil {
			return "", "", err
		}
		if err := os.WriteFile(stored, data, 0o600); err != nil {
			return "", "", err
		}
		return stored, "given", nil
	}
	data, err := os.ReadFile(stored)
	if errors.Is(err, os.ErrNotExist) {
		return "", "", ErrNoCA
	}
	if err != nil {
		return "", "", err
	}
	if err := validCA(data); err != nil {
		return "", "", fmt.Errorf("%s: %w", stored, err)
	}
	return stored, "stored", nil
}

// Save validates a CA certificate (e.g. downloaded from the portal) and keeps
// it as the stored copy of the instance.
func (s CAStore) Save(cluster, tenant, instance string, data []byte) (string, error) {
	if err := validCA(data); err != nil {
		return "", fmt.Errorf("CA certificate from the portal: %w", err)
	}
	stored := s.Path(cluster, tenant, instance)
	if err := os.MkdirAll(filepath.Dir(stored), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(stored, data, 0o600); err != nil {
		return "", err
	}
	return stored, nil
}

// validCA accepts PEM data holding at least one CA certificate.
func validCA(data []byte) error {
	found := false
	for {
		var b *pem.Block
		b, data = pem.Decode(data)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			return fmt.Errorf("unexpected PEM block %q (want only CERTIFICATE)", b.Type)
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return fmt.Errorf("not a valid certificate: %w", err)
		}
		if !c.IsCA {
			return fmt.Errorf("certificate %q is not a CA certificate", c.Subject.String())
		}
		found = true
	}
	if !found {
		return errors.New("no PEM certificate found")
	}
	return nil
}
