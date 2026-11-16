package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func makeCert(t *testing.T, validBefore time.Time) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	signer, _ := ssh.NewSignerFromKey(k)
	c := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "anis@example", ValidAfter: 0, ValidBefore: uint64(validBefore.Unix())}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(c)
}

func TestReadAndExpiry(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ocd-x")
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	if err := os.WriteFile(key+"-cert.pub", makeCert(t, exp), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Read(key)
	if err != nil {
		t.Fatal(err)
	}
	if info.KeyID != "anis@example" || !info.ValidBefore.Equal(exp) {
		t.Fatalf("unexpected %+v", info)
	}
	if info.Expired(time.Now()) || !info.Expired(exp.Add(time.Second)) {
		t.Fatal("expiry logic wrong")
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func TestOpksshForeverCertUsesIDTokenExp(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	signer, _ := ssh.NewSignerFromKey(k)
	exp := time.Now().Add(-time.Hour).Truncate(time.Second)
	pkt := b64(fmt.Sprintf(`{"exp":%d}`, exp.Unix())) + ":" + b64(`{"alg":"RS256"}`) + ":" + b64("sig")
	c := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{Extensions: map[string]string{"openpubkey-pkt": pkt}}}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	info, err := Parse(ssh.MarshalAuthorizedKey(c))
	if err != nil {
		t.Fatal(err)
	}
	if !info.ValidBefore.Equal(exp) || !info.Expired(time.Now()) {
		t.Fatalf("want expired at %v, got %+v", exp, info)
	}
	later := time.Now().Add(time.Hour).Truncate(time.Second)
	fresh := b64(`{"alg":"RS256"}`) + "." + b64(fmt.Sprintf(`{"exp":%d}`, later.Unix())) + "." + b64("sig")
	got, err := pktExpiry(pkt + "." + fresh)
	if err != nil || !got.Equal(later) {
		t.Fatalf("fresh token: %v %v", got, err)
	}
}

func TestParseRejectsPlainKey(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	if _, err := Parse(ssh.MarshalAuthorizedKey(pub)); err == nil {
		t.Fatal("plain key accepted as certificate")
	}
}

func TestMaxAgePolicyOverridesShortIDTokenExp(t *testing.T) {
	// Keycloak ID tokens live minutes; the VM opkssh "12h" policy checks iat.
	iat := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	exp := iat.Add(5 * time.Minute)
	pkt := b64(fmt.Sprintf(`{"exp":%d,"iat":%d}`, exp.Unix(), iat.Unix())) + ":" + b64(`{"alg":"RS256"}`) + ":" + b64("sig")
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	signer, _ := ssh.NewSignerFromKey(k)
	c := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, ValidBefore: ssh.CertTimeInfinity,
		Permissions: ssh.Permissions{Extensions: map[string]string{"openpubkey-pkt": pkt}}}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	info, err := Parse(ssh.MarshalAuthorizedKey(c))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Expired(time.Now()) {
		t.Fatal("without a policy the exp claim is the limit")
	}
	got := info.WithMaxAge(12 * time.Hour)
	if got.Expired(time.Now()) || !got.ValidBefore.Equal(iat.Add(12*time.Hour)) {
		t.Fatalf("12h policy: got %+v", got)
	}
	if !info.WithMaxAge(0).ValidBefore.Equal(exp) {
		t.Fatal("max age 0 must keep the exp limit")
	}
}

// writePair writes an OpenSSH private key and a certificate for it.
func writePair(t *testing.T, keyPath string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := ssh.NewPublicKey(&k.PublicKey)
	signer, _ := ssh.NewSignerFromKey(k)
	c := &ssh.Certificate{Key: pub, CertType: ssh.UserCert, KeyId: "anis@example", ValidBefore: ssh.CertTimeInfinity}
	if err := c.SignCert(rand.Reader, signer); err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(k, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath+"-cert.pub", ssh.MarshalAuthorizedKey(c), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadPair(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "ocd-x")
	writePair(t, key)
	if _, err := ReadPair(key); err != nil {
		t.Fatalf("matching pair: %v", err)
	}

	// Private key replaced by another key: mismatch.
	other := filepath.Join(dir, "other")
	writePair(t, other)
	raw, _ := os.ReadFile(other)
	if err := os.WriteFile(key, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPair(key); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("replaced key: got %v, want ErrKeyMismatch", err)
	}

	// Private key deleted, certificate left: missing.
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	info, err := ReadPair(key)
	if !errors.Is(err, ErrKeyMissing) {
		t.Fatalf("deleted key: got %v, want ErrKeyMissing", err)
	}
	if info.KeyID != "anis@example" {
		t.Fatalf("certificate info should still be returned, got %+v", info)
	}

	// Both gone: plain not-exist error, not a key error.
	_ = os.Remove(key + "-cert.pub")
	if _, err := ReadPair(key); err == nil || errors.Is(err, ErrKeyMissing) {
		t.Fatalf("no files: got %v", err)
	}
}
