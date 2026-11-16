package portal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSignInAndFindCA runs the whole native flow against a fake Keycloak and
// portal: discovery, PKCE browser sign-in on a loopback port, token
// exchange, a two-page inventory with the bearer, and the CA lookup.
func TestSignInAndFindCA(t *testing.T) {
	var srv *httptest.Server
	var challenge string
	mux := http.NewServeMux()
	mux.HandleFunc("/realm/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": srv.URL + "/realm/auth",
			"token_endpoint":         srv.URL + "/realm/token",
		})
	})
	mux.HandleFunc("/realm/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != "the-code" || r.Form.Get("client_id") != "dev-01-portal-tui" || r.Form.Get("code_verifier") == "" || challenge == "" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "tok"})
	})
	mux.HandleFunc(ConnectionsPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cursor") == "" {
			_, _ = w.Write([]byte(`{"connections":[{"id":"ocd-dev-01/tenant-demo-000001-postgresql/other-pg/x","tenantId":"demo-000001","engine":"postgresql","instanceName":"other","sqlAuth":null}],"nextCursor":"p2"}`))
			return
		}
		_, _ = w.Write([]byte(`{"connections":[{"id":"ocd-dev-01/tenant-demo-000001-postgresql/pgoidc01-pg/pgoidc01-pg-access","tenantId":"demo","engine":"postgresql","instanceName":"pgoidc01","sqlAuth":{"mode":"postgresql-oauth","caCertificate":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n"}}],"nextCursor":null}`))
	})
	srv = httptest.NewServer(mux)
	defer srv.Close()

	c := Client{
		PortalURL: srv.URL, Issuer: srv.URL + "/realm", ClientID: "dev-01-portal-tui",
		CallbackHTML: "ok",
		// The "browser": follow the authorization URL straight back to the
		// loopback callback, as Keycloak would after the user signs in.
		Open: func(auth string) error {
			u, err := url.Parse(auth)
			if err != nil {
				return err
			}
			q := u.Query()
			challenge = q.Get("code_challenge")
			if q.Get("code_challenge_method") != "S256" || !strings.HasPrefix(q.Get("redirect_uri"), "http://127.0.0.1:") {
				t.Errorf("unexpected authorization request %s", auth)
			}
			go func() {
				// A stray local request with a wrong state is refused but
				// must not end the pending sign-in.
				if resp, err := http.Get(q.Get("redirect_uri") + "?code=evil&state=wrong"); err == nil {
					if resp.StatusCode != http.StatusBadRequest {
						t.Errorf("wrong state answered %d", resp.StatusCode)
					}
					resp.Body.Close()
				}
				resp, err := http.Get(q.Get("redirect_uri") + "?code=the-code&state=" + url.QueryEscape(q.Get("state")))
				if err == nil {
					resp.Body.Close()
				}
			}()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tok, err := c.SignIn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	conns, err := c.Connections(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := FindCA(conns, "demo-000001", "pgoidc01")
	if err != nil || !strings.Contains(ca, "BEGIN CERTIFICATE") {
		t.Fatalf("FindCA = %q, %v", ca, err)
	}
	if _, err := FindCA([]Connection{{TenantID: "demo-000001", Engine: "postgresql", InstanceName: "why",
		SQLAuth: &struct {
			Mode          string `json:"mode"`
			CACertificate string `json:"caCertificate"`
			Reason        string `json:"reason"`
		}{Mode: "unavailable", Reason: "PostgreSQL OAuth mapping is unavailable."}}}, "demo-000001", "why"); !errors.Is(err, ErrNoCA) || !strings.Contains(err.Error(), "mapping is unavailable") {
		t.Fatalf("portal reason not shown: %v", err)
	}
	if _, err := FindCA(conns, "demo-000001", "other"); err != ErrNoCA {
		t.Fatalf("listed instance without CA: %v, want ErrNoCA", err)
	}
	if _, err := FindCA(conns, "demo-000001", "missing"); err != ErrNotFound {
		t.Fatalf("missing instance: %v, want ErrNotFound", err)
	}
}

func TestPrivateIPv4(t *testing.T) {
	for _, test := range []struct {
		ip      string
		allowed bool
	}{
		{"10.2.3.4", true}, {"10.20.30.40", true}, {"192.168.1.1", true},
		{"100.64.0.1", true}, {"100.127.255.254", true},
		{"100.63.255.255", false}, {"100.128.0.1", false}, {"8.8.8.8", false},
		{"127.0.0.1", false}, {"169.254.1.2", false}, {"0.0.0.0", false},
		{"::1", false}, {"fd00::1", false}, {"::ffff:10.0.0.1", false},
		{"demo.onecloud.ldc.dz", false}, {"10.0.0.1;echo hi", false},
	} {
		if got := PrivateIPv4(test.ip); got != test.allowed {
			t.Errorf("PrivateIPv4(%q) = %v, want %v", test.ip, got, test.allowed)
		}
	}
}

func TestFindVPCAddressScopesTenantClusterAndEngine(t *testing.T) {
	conns := []Connection{
		{ID: "ocd-dev-01/tenant-other-999999-postgresql/pg-pg/a", TenantID: "other", Engine: "postgresql", InstanceName: "db", VPCAddress: "10.9.9.9"},
		{ID: "ocd-prd-01/tenant-demo-000001-postgresql/pg-pg/a", TenantID: "demo", Engine: "postgresql", InstanceName: "db", VPCAddress: "10.2.2.2"},
		{ID: "ocd-dev-01/tenant-demo-000001-postgresql/pg-pg/a", TenantID: "demo", Engine: "postgresql", InstanceName: "db", VPCAddress: "172.16.1.15"},
	}
	got, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "demo-000001", "db")
	if err != nil || got != "172.16.1.15" {
		t.Fatalf("tenant scoped connection = %q, %v", got, err)
	}
	if _, err := FindVPCAddress(conns, "ocd-dev-01", "vm", "demo-000001", "db"); err != ErrNotFound {
		t.Fatalf("wrong engine = %v", err)
	}
	if _, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "other-000001", "db"); err != ErrNotFound {
		t.Fatalf("wrong tenant = %v", err)
	}
	if _, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "000001", "db"); err != nil {
		t.Fatalf("bare tenant id should match namespace: %v", err)
	}
	conns[2].VPCAddress = "example.com;rm -rf /"
	if _, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "demo-000001", "db"); !errors.Is(err, ErrNoVPC) {
		t.Fatalf("unvalidated address = %v", err)
	}
	conns[2].VPCAddress = ""
	if _, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "demo-000001", "db"); err != ErrNoVPC {
		t.Fatalf("missing address = %v", err)
	}
	for _, bad := range []string{"8.8.8.8", "127.0.0.1", "100.128.0.1", "fd00::1"} {
		conns[2].VPCAddress = bad
		if _, err := FindVPCAddress(conns, "ocd-dev-01", "postgresql", "demo-000001", "db"); !errors.Is(err, ErrNoVPC) {
			t.Errorf("public/non-IPv4 portal address %q accepted: %v", bad, err)
		}
	}
}

func TestFindInstanceVPCFacade(t *testing.T) {
	instances := []Instance{
		{Tenant: "other-000002", Cluster: "ocd-prd-01", Service: "vm", InstanceName: "same", Outputs: map[string]any{"vpc": map[string]any{"address": "10.3.3.3"}}},
		{Tenant: "demo-000001", Cluster: "ocd-prd-01", Service: "vm", InstanceName: "same", Outputs: map[string]any{"vpc": map[string]any{"address": "10.20.30.40"}}},
	}
	got, err := FindInstanceVPC(instances, "ocd-prd-01", "demo-000001", "same")
	if err != nil || got != "10.20.30.40" {
		t.Fatalf("facade address %q, %v", got, err)
	}
	if _, err := FindInstanceVPC(instances, "ocd-prd-01", "other-000001", "same"); err != ErrNotFound {
		t.Fatalf("wrong tenant must not match: %v", err)
	}
	for _, bad := range []string{"evil", "127.0.0.1", "8.8.8.8", "fd12::1"} {
		instances[1].Outputs["vpc"] = map[string]any{"address": bad}
		if _, err := FindInstanceVPC(instances, "ocd-prd-01", "demo-000001", "same"); err != ErrNoVPC {
			t.Fatalf("invalid facade address %q = %v", bad, err)
		}
	}
}

func TestAccessTokenExpiry(t *testing.T) {
	tok := "header." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":1924992000}`)) + ".signature"
	got, err := AccessTokenExpiry(tok)
	if err != nil || got.Unix() != 1924992000 {
		t.Fatalf("expiry %s, %v", got, err)
	}
	for _, bad := range []string{"plain", "x.eyJleHAiOjB9.y", "x.e30.y", "x.%%%%.y"} {
		if _, err := AccessTokenExpiry(bad); err == nil {
			t.Errorf("accepted uncacheable token %q", bad)
		}
	}
}

func TestInstancesReadOnlyBearer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/provisioning/instances" || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"tenant":"demo-000001","cluster":"ocd-prd-01","service":"vm","instance_name":"ubuntu01","outputs":{"vpc":{"address":"10.20.30.40"}}}]`))
	}))
	defer server.Close()
	conns, err := (Client{PortalURL: server.URL}).Instances(context.Background(), "tok")
	if err != nil || len(conns) != 1 {
		t.Fatalf("portal ledger = %+v, %v", conns, err)
	}
	if ip, err := FindInstanceVPC(conns, "ocd-prd-01", "demo-000001", "ubuntu01"); err != nil || ip != "10.20.30.40" {
		t.Fatalf("portal facade IP = %q, %v", ip, err)
	}
}

func catalogServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != InstancesPath || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return Client{PortalURL: srv.URL}
}

const catalogItem = `{"id":"%s","tenant":"demo-000001","cluster":"ocd-dev-01","service":"%s","instance_name":"%s","status":"%s","outputs":{"vpc":{"address":"10.1.1.1"}}}`

func TestCatalogPagesAndReadiness(t *testing.T) {
	c := catalogServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("limit") != "100" {
			t.Errorf("limit = %q", r.URL.Query().Get("limit"))
		}
		switch r.URL.Query().Get("cursor") {
		case "":
			fmt.Fprintf(w, `{"instances":[`+catalogItem+`,`+catalogItem+`],"nextCursor":"p2"}`, "1", "postgresql", "pg01", "ready", "2", "mssql", "sql01", "pr_open")
		case "p2":
			fmt.Fprintf(w, `{"instances":[`+catalogItem+`],"nextCursor":null}`, "3", "clickhouse", "ch01", "degraded")
		default:
			http.Error(w, "bad cursor", http.StatusBadRequest)
		}
	})
	got, err := c.Catalog(context.Background(), "tok")
	if err != nil || len(got) != 3 {
		t.Fatalf("catalog = %+v, %v", got, err)
	}
	if !got[0].Ready() || got[1].Ready() || !got[1].Status.Pending() || !got[2].Ready() {
		t.Fatalf("readiness wrong: %+v", got)
	}
	if ip, ok := got[0].Output("vpc", "address"); !ok || ip != "10.1.1.1" {
		t.Fatalf("output = %q %v", ip, ok)
	}
	if _, ok := got[0].Output("vpc", "address", "deeper"); ok {
		t.Fatal("output walked past a string")
	}
	if Status("weird").Deployed() || Status("weird").Known() || !StatusFailed.Known() {
		t.Fatal("unknown status must never be ready")
	}
}

func TestCatalogAcceptsCurrentBareArray(t *testing.T) {
	c := catalogServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[`+catalogItem+`]`, "1", "vm", "ubuntu01", "ready")
	})
	got, err := c.Catalog(context.Background(), "tok")
	if err != nil || len(got) != 1 || got[0].Service != "vm" {
		t.Fatalf("bare array = %+v, %v", got, err)
	}
}

// The deployed portal returns the whole tenant inventory in one bare array;
// more than the requested page size is normal, not a malformed response.
func TestCatalogAcceptsBareArrayOverPageSize(t *testing.T) {
	c := catalogServer(t, func(w http.ResponseWriter, r *http.Request) {
		items := make([]string, 150)
		for i := range items {
			items[i] = fmt.Sprintf(catalogItem, fmt.Sprint(i), "vm", fmt.Sprintf("vm%03d", i), "ready")
		}
		_, _ = w.Write([]byte(`[` + strings.Join(items, ",") + `]`))
	})
	got, err := c.Catalog(context.Background(), "tok")
	if err != nil || len(got) != 150 {
		t.Fatalf("bare array over page size: %d, %v", len(got), err)
	}
}

func TestCatalogFailsClosed(t *testing.T) {
	tooMany := make([]string, catalogMaxItems+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf(catalogItem, fmt.Sprint(i), "vm", "v", "ready")
	}
	for name, body := range map[string]func(cursor string) string{
		"not json":       func(string) string { return `<html>` },
		"wrong shape":    func(string) string { return `{"items":[]}` },
		"null instances": func(string) string { return `{"instances":null}` },
		"wrong type":     func(string) string { return `{"instances":[{"id":7}]}` },
		"missing field":  func(string) string { return `[{"id":"1","tenant":"t","cluster":"c","service":"vm","status":"ready"}]` },
		"padded field":   func(string) string { return fmt.Sprintf(`[`+catalogItem+`]`, " 1", "vm", "v", "ready") },
		"duplicate id": func(string) string {
			return fmt.Sprintf(`[`+catalogItem+`,`+catalogItem+`]`, "1", "vm", "a", "ready", "1", "vm", "b", "ready")
		},
		"inventory overflow": func(string) string { return "[" + strings.Join(tooMany, ",") + "]" },
		"repeated cursor":    func(c string) string { return `{"instances":[],"nextCursor":"same"}` },
		"cursor cycle": func(c string) string {
			next := map[string]string{"": "a", "a": "b", "b": "a"}[c]
			return `{"instances":[],"nextCursor":"` + next + `"}`
		},
		"unpaged after cursor": func(c string) string {
			if c == "" {
				return `{"instances":[],"nextCursor":"a"}`
			}
			return `[]`
		},
		"endless pages": func(c string) string { return `{"instances":[],"nextCursor":"x` + c + `"}` },
	} {
		t.Run(name, func(t *testing.T) {
			c := catalogServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, body(r.URL.Query().Get("cursor")))
			})
			if got, err := c.Catalog(context.Background(), "tok"); err == nil {
				t.Fatalf("accepted %s: %+v", name, got)
			}
		})
	}
	c := catalogServer(t, func(w http.ResponseWriter, r *http.Request) {})
	if _, err := c.Catalog(context.Background(), "bad"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("rejected bearer = %v", err)
	}
}

func revealServer(t *testing.T, status int, ctype, body string, seen *string) Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		if seen != nil {
			*seen = r.URL.EscapedPath()
		}
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return Client{PortalURL: srv.URL}
}

func TestRevealKeepsOnlyReturnedValues(t *testing.T) {
	var path string
	c := revealServer(t, http.StatusOK, "application/json", `{"status":"revealed","username":"app","password":"pa55-secret"}`, &path)
	v, err := c.Reveal(context.Background(), "tok", "id/with space")
	if err != nil {
		t.Fatal(err)
	}
	defer v.Wipe()
	if path != "/api/provisioning/instances/id%2Fwith%20space/reveal" {
		t.Fatalf("reveal path %q", path)
	}
	if keys := v.Keys(); len(keys) != 2 || keys[0] != "password" || keys[1] != "username" {
		t.Fatalf("keys %v (status key must not be a value)", keys)
	}
	if pw, _ := v.String("password"); pw != "pa55-secret" {
		t.Fatalf("password %q", pw)
	}
	if strings.Contains(fmt.Sprintf("%v %+v", v, v), "pa55") {
		t.Fatal("revealed values printable")
	}
	// The current backend may omit the reserved status key.
	c = revealServer(t, http.StatusOK, "application/json", `{"access_key":"AK","secret_key":"SK"}`, nil)
	if v, err := c.Reveal(context.Background(), "tok", "s3"); err != nil || v.Len() != 2 {
		t.Fatalf("plain map = %v, %v", v, err)
	}
}

func TestRevealErrorsAreRedactedAndTyped(t *testing.T) {
	const leak = "LEAKED-SECRET"
	for _, test := range []struct {
		name   string
		status int
		ctype  string
		body   string
		want   error
	}{
		{"expired", http.StatusUnauthorized, "application/json", `{"detail":"` + leak + `"}`, ErrUnauthorized},
		{"member refused", http.StatusForbidden, "application/json", `{"detail":"` + leak + `"}`, ErrForbidden},
		{"no secret", http.StatusNotFound, "application/json", `{"detail":"` + leak + `"}`, ErrNoSecrets},
		{"missing", http.StatusOK, "application/json", `{"status":"missing"}`, ErrNoSecrets},
		{"empty", http.StatusOK, "application/json", `{}`, ErrNoSecrets},
		{"server error", http.StatusInternalServerError, "application/json", `{"password":"` + leak + `"}`, nil},
		{"not json", http.StatusOK, "text/html", leak, ErrMalformed},
		{"array", http.StatusOK, "application/json", `["` + leak + `"]`, ErrMalformed},
		{"non-string value", http.StatusOK, "application/json", `{"password":{"v":"` + leak + `"}}`, ErrMalformed},
		{"status with values", http.StatusOK, "application/json", `{"status":"pending","password":"` + leak + `"}`, ErrMalformed},
		{"status not string", http.StatusOK, "application/json", `{"status":1}`, ErrMalformed},
		{"truncated", http.StatusOK, "application/json", `{"password":"` + leak, ErrMalformed},
		{"too large", http.StatusOK, "application/json", `{"password":"` + strings.Repeat("x", revealMaxBody) + `"}`, ErrMalformed},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := revealServer(t, test.status, test.ctype, test.body, nil)
			v, err := c.Reveal(context.Background(), "tok", "abc")
			if err == nil || v != nil {
				t.Fatalf("accepted: %v", v)
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("err = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), leak) || strings.Contains(err.Error(), "tok") {
				t.Fatalf("error leaks the body or bearer: %v", err)
			}
		})
	}
	c := revealServer(t, http.StatusOK, "application/json", `{"status":"pending"}`, nil)
	var pending *RevealPending
	if _, err := c.Reveal(context.Background(), "tok", "abc"); !errors.As(err, &pending) || pending.Status != "pending" {
		t.Fatalf("pending = %v", err)
	}
	if _, err := c.Reveal(context.Background(), "tok", " "); err == nil {
		t.Fatal("empty instance id accepted")
	}
	if _, err := (Client{PortalURL: "http://127.0.0.1:1"}).Reveal(context.Background(), "tok-SECRET", "abc"); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("transport error = %v", err)
	}
}
