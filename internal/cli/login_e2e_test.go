package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ldc-dz/onecloud-cli/internal/cert"
	"github.com/ldc-dz/onecloud-cli/internal/config"
)

// fakeOP is a minimal OpenID Provider: discovery, JWKS, an authorize
// endpoint that signs the user in at once, and a token endpoint.
func fakeOP(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	nonces := map[string]string{}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		mu.Lock()
		nonces["code1"] = q.Get("nonce")
		mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {"code1"}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		nonce := nonces[r.Form.Get("code")]
		mu.Unlock()
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{
			"iss": srv.URL, "sub": "sub-1", "aud": "onecloud-ssh", "email": "user@example.com",
			"email_verified": true, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
		})
		jws, err := signer.Sign(claims)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 300})
	})
	srv = httptest.NewTLSServer(mux)
	orig := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = orig })
	t.Cleanup(srv.Close)
	return srv
}

// TestLoginDeliversCallbackPage drives the real opkssh sign-in against a fake
// provider and checks the browser gets the "signed in" page (it used to get
// ERR_CONNECTION_REFUSED because the local server shut down first).
func TestLoginDeliversCallbackPage(t *testing.T) {
	op := fakeOP(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))

	type result struct {
		status int
		body   string
		err    error
		at     time.Time
	}
	got := make(chan result, 1)
	testOpenURL = func(u string) error {
		jar, _ := cookiejar.New(nil)
		resp, err := (&http.Client{Jar: jar, Timeout: 20 * time.Second}).Get(u)
		if err != nil {
			got <- result{err: err}
			return err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		got <- result{status: resp.StatusCode, body: string(b), at: time.Now()}
		return nil
	}
	t.Cleanup(func() { testOpenURL = nil })

	cl := config.Cluster{Name: "test", Issuer: op.URL, ClientID: "onecloud-ssh", TCPDomain: "tcp.example"}
	if err := login(cl, false); err != nil {
		t.Fatalf("login: %v", err)
	}
	returned := time.Now()
	// ocd exits right after login returns: by then the local callback
	// server must have finished answering the browser and be closed,
	// otherwise the exit cuts the page off (ERR_CONNECTION_REFUSED).
	if c, err := net.DialTimeout("tcp", "localhost:3000", time.Second); err == nil {
		c.Close()
		t.Fatal("the local callback server is still running when login returns")
	}
	select {
	case r := <-got:
		if r.err != nil {
			t.Fatalf("browser could not load the callback page: %v", r.err)
		}
		if r.status != 200 || !contains(r.body, "Signed in to OneCloud") {
			t.Fatalf("callback page: status %d body %q", r.status, r.body)
		}
		// ocd exits as soon as login returns: a page that only reaches the
		// browser afterwards is cut off in real use.
		if r.at.After(returned) {
			t.Fatalf("the callback page reached the browser %v after login returned", r.at.Sub(returned))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("browser got no answer")
	}
	keyPath, _ := cl.KeyPath()
	if _, err := os.Stat(keyPath + "-cert.pub"); err != nil {
		t.Fatalf("certificate not written: %v", err)
	}
}

// TestDeviceLoginMintsAnSSHCertificate uses the real opkssh/OpenPubkey
// device provider end-to-end: no loopback callback, RFC 8628 device code,
// committed nonce in the signed ID token, and a written SSH certificate.
func TestDeviceLoginMintsAnSSHCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	var nonce string
	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
			"device_authorization_endpoint":         srv.URL + "/device",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "onecloud-ssh-device" || r.Form.Get("nonce") == "" || r.Form.Get("scope") == "" {
			http.Error(w, "bad device authorization", 400)
			return
		}
		nonce = r.Form.Get("nonce")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "device1", "user_code": "ABC-123",
			"verification_uri": srv.URL + "/verify", "expires_in": 60, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.Form.Get("device_code") != "device1" {
			http.Error(w, "bad grant", 400)
			return
		}
		// Device sign-in must use the device-only client, never the PKCE one.
		if r.Form.Get("client_id") != "onecloud-ssh-device" {
			http.Error(w, "wrong client "+r.Form.Get("client_id"), 400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		now := time.Now()
		claims, _ := json.Marshal(map[string]any{
			"iss": srv.URL, "sub": "sub-device", "aud": "onecloud-ssh-device", "email": "device@example.com",
			"email_verified": true, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce,
		})
		jws, err := signer.Sign(claims)
		if err != nil {
			http.Error(w, "signing failed", 500)
			return
		}
		idt, _ := jws.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": idt, "expires_in": 300})
	})
	srv = httptest.NewTLSServer(mux)
	defer srv.Close()
	orig := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = orig }()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("OCD_CLOUD_SHELL", "1")
	cl := config.Cluster{Name: "test-device", Issuer: srv.URL, ClientID: "onecloud-ssh", DeviceClientID: "onecloud-ssh-device", TCPDomain: "tcp.example"}
	if err := loginWithMode(cl, false, true); err != nil {
		t.Fatalf("device login: %v", err)
	}
	if calls.Load() != 2 || nonce == "" {
		t.Fatalf("device flow did not poll after authorization_pending: polls %d nonce %q", calls.Load(), nonce)
	}
	keyPath, _ := cl.KeyPath()
	if _, err := os.Stat(keyPath + "-cert.pub"); err != nil {
		t.Fatalf("device login did not write SSH cert: %v", err)
	}
	if _, err := cert.ReadPair(keyPath); err != nil {
		t.Fatalf("device login wrote an invalid SSH cert or private key: %v", err)
	}
	if keyData, err := os.ReadFile(keyPath); err != nil || !strings.Contains(string(keyData), "OPENSSH PRIVATE KEY") {
		t.Fatalf("device key not written: %v", err)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
