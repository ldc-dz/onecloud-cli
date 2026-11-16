// Package portalcache keeps the portal's short-lived access token and resolved
// tenant addresses in the user's private ocd configuration directory. This is
// only a performance and UX cache: the portal still authorizes bearer requests.
package portalcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/portal"
)

// AddressTTL is deliberately short: membership/address changes must not keep
// direct connections pointing at a stale tenant VM indefinitely.
const AddressTTL = 2 * time.Minute

// Store uses config.Dir()/portal as a 0700 directory and a per-cluster 0600
// file. Tests may override Now to exercise expiry without sleeping.
type Store struct {
	Dir string
	Now func() time.Time
}

type address struct {
	Value string    `json:"value"`
	Until time.Time `json:"until"`
}

type state struct {
	Issuer    string             `json:"issuer"`
	ClientID  string             `json:"clientId"`
	PortalURL string             `json:"portalUrl"`
	Token     string             `json:"token"`
	ExpiresAt time.Time          `json:"expiresAt"`
	Addresses map[string]address `json:"addresses,omitempty"`
}

func (s Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s Store) path(cl config.Cluster) string {
	h := sha256.Sum256([]byte(cl.Name))
	return filepath.Join(s.Dir, "portal", hex.EncodeToString(h[:16])+".json")
}

func (s Store) read(cl config.Cluster) (state, error) {
	var entry state
	path := s.path(cl)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return entry, nil
	}
	if err != nil {
		return entry, err
	}
	if !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return entry, fmt.Errorf("portal session %s is not a private regular file (want mode 0600)", path)
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return entry, err
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && dirInfo.Mode().Perm()&0o077 != 0) {
		return entry, errors.New("portal cache directory is not private (want mode 0700)")
	}
	file, err := os.Open(path)
	if err != nil {
		return entry, err
	}
	defer file.Close()
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&entry); err != nil {
		return state{}, fmt.Errorf("portal session: %w", err)
	}
	if entry.Issuer != cl.Issuer || entry.ClientID != cl.PortalClientID || entry.PortalURL != cl.PortalURL {
		return state{}, nil
	}
	// Never trust the serialised expiry independently of the bearer JWT. A
	// locally corrupted/old entry is treated as a cache miss, not re-used.
	jwtExpiry, err := portal.AccessTokenExpiry(entry.Token)
	if err != nil || !entry.ExpiresAt.Equal(jwtExpiry) || !s.now().Before(entry.ExpiresAt.Add(-30*time.Second)) {
		return state{}, nil
	}
	return entry, nil
}

// Token returns a still-valid token for this exact issuer, client and portal.
func (s Store) Token(cl config.Cluster) (string, error) {
	entry, err := s.read(cl)
	return entry.Token, err
}

// Address returns a still-valid private IPv4 address bound to the cached
// bearer and scoped to this cluster/engine/full-tenant/instance tuple.
func (s Store) Address(cl config.Cluster, engine, tenant, instance string) (string, error) {
	entry, err := s.read(cl)
	if err != nil || entry.Token == "" {
		return "", err
	}
	a := entry.Addresses[key(engine, tenant, instance)]
	if !s.now().Before(a.Until) || !portal.PrivateIPv4(a.Value) {
		return "", nil
	}
	return a.Value, nil
}

func key(engine, tenant, instance string) string { return engine + "\x00" + tenant + "\x00" + instance }

// SaveToken replaces the address cache on an account switch and saves no
// non-JWT/expired bearer. A network reply's expires_in is not an authority
// over the signed exp; token validation remains the portal's responsibility.
func (s Store) SaveToken(cl config.Cluster, token string) error {
	exp, err := portal.AccessTokenExpiry(token)
	if err != nil || !s.now().Before(exp.Add(-30*time.Second)) {
		return errors.New("portal access token has no valid remaining lifetime")
	}
	entry, err := s.read(cl)
	if err != nil {
		return err
	}
	if entry.Token != token {
		entry.Addresses = nil
	}
	entry.Issuer, entry.ClientID, entry.PortalURL = cl.Issuer, cl.PortalClientID, cl.PortalURL
	entry.Token, entry.ExpiresAt = token, exp
	return s.write(cl, entry)
}

// SaveAddress writes only validated portal data, never an arbitrary hostname.
// The bearer must be unchanged since the authenticated inventory response;
// otherwise a concurrent account switch could bind the old user's address to
// the new user's session.
func (s Store) SaveAddress(cl config.Cluster, token, engine, tenant, instance, value string) error {
	if !portal.PrivateIPv4(value) {
		return errors.New("not a private tenant IPv4 address")
	}
	entry, err := s.read(cl)
	if err != nil {
		return err
	}
	if entry.Token == "" || entry.Token != token {
		return errors.New("portal session changed; cannot cache tenant address")
	}
	if entry.Addresses == nil {
		entry.Addresses = make(map[string]address)
	}
	until := s.now().Add(AddressTTL)
	if until.After(entry.ExpiresAt) {
		until = entry.ExpiresAt
	}
	entry.Addresses[key(engine, tenant, instance)] = address{value, until}
	return s.write(cl, entry)
}

// Clear drops a revoked bearer and its associated address entries. Do not
// overwrite an unexpected symlink or world-readable session file.
func (s Store) Clear(cl config.Cluster) error {
	if _, err := s.read(cl); err != nil {
		return err
	}
	return s.write(cl, state{})
}

func (s Store) write(cl config.Cluster, entry state) error {
	path := s.path(cl)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return errors.New("portal cache directory is not private (want mode 0700)")
	}
	if current, err := os.Lstat(path); err == nil {
		if !current.Mode().IsRegular() || (runtime.GOOS != "windows" && current.Mode().Perm()&0o077 != 0) {
			return fmt.Errorf("portal session %s is not a private regular file (want mode 0600)", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(dir, ".session-*")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err := json.NewEncoder(file).Encode(entry); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	// Windows Rename cannot replace an existing file, whereas POSIX rename
	// atomically replaces it. On Windows, remove the old path before rename.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(tmp, path)
}
