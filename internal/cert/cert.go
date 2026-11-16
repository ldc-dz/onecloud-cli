// Package cert reads the opkssh SSH certificate written by ocd login.
package cert

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Info is what ocd needs to know about the current sign-in.
type Info struct {
	KeyID       string
	ValidBefore time.Time
	// IssuedAt is the iat of the ID token in the certificate (zero if absent).
	IssuedAt time.Time

	sshValidBefore time.Time
	key            ssh.PublicKey
}

// ErrKeyMissing means the certificate is there but its private key is gone
// (deleted by hand, for example): ssh cannot use the sign-in.
var ErrKeyMissing = errors.New("SSH private key missing")

// ErrKeyMismatch means the private key on disk does not belong to the
// certificate (one of the two files was replaced).
var ErrKeyMismatch = errors.New("SSH private key does not match the certificate")

// WithMaxAge applies an opkssh max-age expiration policy ("12h", ...): the
// VM accepts the sign-in until IssuedAt+maxAge, ignoring the ID token exp
// (Keycloak issues short-lived ID tokens, a few minutes). maxAge 0 keeps the
// exp-based limit.
func (i Info) WithMaxAge(maxAge time.Duration) Info {
	if maxAge <= 0 || i.IssuedAt.IsZero() {
		return i
	}
	vb := i.IssuedAt.Add(maxAge)
	if !i.sshValidBefore.IsZero() && i.sshValidBefore.Before(vb) {
		vb = i.sshValidBefore
	}
	i.ValidBefore = vb
	return i
}

// Expired reports whether the certificate is no longer valid at now.
func (i Info) Expired(now time.Time) bool { return !now.Before(i.ValidBefore) }

// Parse decodes an authorized_keys-format certificate.
func Parse(data []byte) (Info, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return Info{}, fmt.Errorf("parse certificate: %w", err)
	}
	c, ok := pub.(*ssh.Certificate)
	if !ok {
		return Info{}, fmt.Errorf("not an SSH certificate")
	}
	vb := time.Unix(int64(c.ValidBefore), 0)
	if c.ValidBefore == ssh.CertTimeInfinity {
		vb = time.Unix(1<<62, 0)
	}
	info := Info{KeyID: c.KeyId, ValidBefore: vb, sshValidBefore: vb, key: c.Key}
	// opkssh certificates are "valid forever" at the SSH layer; the real
	// lifetime comes from the ID token carried in openpubkey-pkt (its exp, or
	// iat + the VM max-age policy, see WithMaxAge).
	if pkt, ok := c.Extensions["openpubkey-pkt"]; ok {
		exp, iat, err := pktTimes(pkt)
		if err != nil {
			return Info{}, err
		}
		if exp.Before(info.ValidBefore) {
			info.ValidBefore = exp
		}
		info.IssuedAt = iat
	}
	return info, nil
}

// pktExpiry returns the ID token expiry of a compact PK token.
func pktExpiry(compact string) (time.Time, error) {
	exp, _, err := pktTimes(compact)
	return exp, err
}

// pktTimes returns the ID token exp and iat of a compact PK token
// (payload:prot:sig[...][.freshIDToken]); a refreshed ID token wins.
// The iat always comes from the original token: that is what the opkssh
// max-age policies check on the VM.
func pktTimes(compact string) (time.Time, time.Time, error) {
	tokens, fresh, _ := strings.Cut(compact, ".")
	orig, err := tokenClaims(strings.SplitN(tokens, ":", 2)[0])
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expClaims := orig
	if fresh != "" {
		parts := strings.Split(fresh, ".")
		if len(parts) != 3 {
			return time.Time{}, time.Time{}, fmt.Errorf("openpubkey-pkt: invalid refreshed ID token")
		}
		if expClaims, err = tokenClaims(parts[1]); err != nil {
			return time.Time{}, time.Time{}, err
		}
	}
	if expClaims.Exp == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("openpubkey-pkt: no exp claim")
	}
	var iat time.Time
	if orig.Iat != 0 {
		iat = time.Unix(orig.Iat, 0)
	}
	return time.Unix(expClaims.Exp, 0), iat, nil
}

type idClaims struct {
	Exp int64 `json:"exp"`
	Iat int64 `json:"iat"`
}

func tokenClaims(payload string) (idClaims, error) {
	var c idClaims
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(payload, "="))
	if err != nil {
		return c, fmt.Errorf("openpubkey-pkt payload: %w", err)
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("openpubkey-pkt payload: %w", err)
	}
	return c, nil
}

// Read loads <keyPath>-cert.pub.
func Read(keyPath string) (Info, error) {
	data, err := os.ReadFile(keyPath + "-cert.pub")
	if err != nil {
		return Info{}, err
	}
	return Parse(data)
}

// ReadPair reads the certificate like Read and also checks that the private
// key at keyPath exists and belongs to it. It returns ErrKeyMissing or
// ErrKeyMismatch (with the certificate Info) when the pair is not usable.
func ReadPair(keyPath string) (Info, error) {
	info, err := Read(keyPath)
	if err != nil {
		return Info{}, err
	}
	raw, err := os.ReadFile(keyPath)
	if errors.Is(err, os.ErrNotExist) {
		return info, ErrKeyMissing
	}
	if err != nil {
		return info, fmt.Errorf("read SSH private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return info, fmt.Errorf("%w: %v", ErrKeyMismatch, err)
	}
	if info.key == nil || !bytes.Equal(signer.PublicKey().Marshal(), info.key.Marshal()) {
		return info, ErrKeyMismatch
	}
	return info, nil
}
