package pgcmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConnInfoMatchesPortalCommand(t *testing.T) {
	got := ConnInfo(Options{
		ServerName: "pgoidc01-pg-access.tenant-demo-000001-postgresql.svc", Port: 15433,
		Database: "app", User: "app", CAFile: "/home/u/.config/ocd/postgres/ocd-prd-01/demo-000001/pgoidc01-ca.crt",
		Issuer: "https://auth.onecloud.ldc.dz/realms/prd-01-portal", ClientID: "prd-01-postgresql",
	})
	want := "host=pgoidc01-pg-access.tenant-demo-000001-postgresql.svc hostaddr=127.0.0.1 port=15433 dbname=app user=app " +
		"sslmode=verify-full sslrootcert=/home/u/.config/ocd/postgres/ocd-prd-01/demo-000001/pgoidc01-ca.crt " +
		"oauth_issuer=https://auth.onecloud.ldc.dz/realms/prd-01-portal oauth_client_id=prd-01-postgresql"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestConnInfoQuotesWindowsPaths(t *testing.T) {
	got := ConnInfo(Options{CAFile: `C:\Users\Jane Doe\ocd\x-ca.crt`, Database: "it's"})
	if !strings.Contains(got, `sslrootcert='C:\\Users\\Jane Doe\\ocd\\x-ca.crt'`) || !strings.Contains(got, `dbname='it\'s'`) {
		t.Fatalf("bad quoting: %s", got)
	}
	if !strings.Contains(ConnInfo(Options{}), "user=''") {
		t.Fatal("empty values must be quoted")
	}
}

func TestCheckVersion(t *testing.T) {
	if err := CheckVersion("psql (PostgreSQL) 18.6\n"); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion("psql (PostgreSQL) 19devel"); err != nil {
		t.Fatal(err)
	}
	if err := CheckVersion("psql (PostgreSQL) 16.4 (Ubuntu 16.4-1)"); err == nil || !strings.Contains(err.Error(), "psql 18 or newer") {
		t.Fatalf("old psql accepted: %v", err)
	}
	if err := CheckVersion("garbage"); err == nil {
		t.Fatal("unparseable version accepted")
	}
}

func writeCert(t *testing.T, path string, isCA bool) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pgoidc01-pg"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestCAStoreResolve(t *testing.T) {
	store := CAStore{Dir: t.TempDir()}
	wd := t.TempDir()
	t.Chdir(wd)

	if _, _, err := store.Resolve("c", "demo-000001", "pgoidc01", ""); !errors.Is(err, ErrNoCA) {
		t.Fatalf("want ErrNoCA, got %v", err)
	}
	// A CA file in the working directory is never trusted implicitly, not
	// even before any CA is stored.
	writeCert(t, filepath.Join(wd, "pgoidc01-ca.crt"), true)
	if _, _, err := store.Resolve("c", "demo-000001", "pgoidc01", ""); !errors.Is(err, ErrNoCA) {
		t.Fatalf("working-directory CA picked up implicitly: %v", err)
	}
	if _, err := os.Stat(store.Path("c", "demo-000001", "pgoidc01")); !os.IsNotExist(err) {
		t.Fatal("working-directory CA was stored")
	}
	// The portal download path stores the CA; later runs use the stored copy.
	first := filepath.Join(t.TempDir(), "portal-ca.crt")
	data := writeCert(t, first, true)
	p, err := store.Save("c", "demo-000001", "pgoidc01", data)
	if err != nil || p != store.Path("c", "demo-000001", "pgoidc01") {
		t.Fatalf("%s %v", p, err)
	}
	if _, src, err := store.Resolve("c", "demo-000001", "pgoidc01", ""); err != nil || src != "stored" {
		t.Fatalf("%s %v", src, err)
	}
	// A different CA planted in the working directory never replaces the
	// stored one; only an explicit --ca does.
	planted := writeCert(t, filepath.Join(wd, "pgoidc01-ca.crt"), true)
	if _, src, err := store.Resolve("c", "demo-000001", "pgoidc01", ""); err != nil || src != "stored" {
		t.Fatalf("planted CA used: %s %v", src, err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(data) {
		t.Fatal("planted CA replaced the stored copy")
	}
	if _, src, err := store.Resolve("c", "demo-000001", "pgoidc01", filepath.Join(wd, "pgoidc01-ca.crt")); err != nil || src != "given" {
		t.Fatalf("explicit --ca not used: %s %v", src, err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(planted) {
		t.Fatal("explicit --ca did not replace the stored copy")
	}
	// An explicit file that is missing is an error, not a silent fallback.
	if _, _, err := store.Resolve("c", "demo-000001", "pgoidc01", filepath.Join(wd, "nope.crt")); err == nil {
		t.Fatal("missing --ca accepted")
	}
}

func TestCAStoreRejectsNonCA(t *testing.T) {
	store := CAStore{Dir: t.TempDir()}
	dir := t.TempDir()
	leaf := filepath.Join(dir, "leaf.crt")
	writeCert(t, leaf, false)
	if _, _, err := store.Resolve("c", "t-000001", "db", leaf); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("leaf accepted: %v", err)
	}
	junk := filepath.Join(dir, "junk.crt")
	_ = os.WriteFile(junk, []byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), 0o600)
	if _, _, err := store.Resolve("c", "t-000001", "db", junk); err == nil {
		t.Fatal("private key accepted as CA")
	}
	if _, err := os.Stat(store.Path("c", "t-000001", "db")); !os.IsNotExist(err) {
		t.Fatal("invalid CA was stored")
	}
}

func TestConnInfoDirectVPC(t *testing.T) {
	got := ConnInfo(Options{
		ServerName: "db-pg-access.tenant-demo-000001-postgresql.svc", Address: "10.20.30.40", Port: 5432,
		Database: "app", User: "app", CAFile: "/ca.crt", Issuer: "https://issuer.example", ClientID: "pg",
	})
	for _, want := range []string{"host=db-pg-access.tenant-demo-000001-postgresql.svc hostaddr=10.20.30.40 port=5432", "sslmode=verify-full", "sslrootcert=/ca.crt", "oauth_issuer=https://issuer.example", "oauth_client_id=pg"} {
		if !strings.Contains(got, want) {
			t.Fatalf("direct conninfo lacks %q: %s", want, got)
		}
	}
}
