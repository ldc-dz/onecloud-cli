package s3sso

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secret = "sts-secret-do-not-log"

func noSleep(context.Context, time.Duration) error { return nil }

func TestDeviceFlowPendingThenToken(t *testing.T) {
	polls := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("client_id") != "onecloud-s3" {
			t.Errorf("wrong client")
		}
		switch r.URL.Path {
		case "/realm/protocol/openid-connect/auth/device":
			fmt.Fprintf(w, `{"device_code":"dc","user_code":"ABCD","verification_uri_complete":"%s/realm/device?c=ABCD","interval":1,"expires_in":60}`, srv.URL)
		case "/realm/protocol/openid-connect/token":
			polls++
			if polls < 3 {
				w.WriteHeader(400)
				fmt.Fprint(w, `{"error":"authorization_pending"}`)
				return
			}
			fmt.Fprint(w, `{"id_token":"idt","access_token":"at"}`)
		}
	}))
	defer srv.Close()
	var code string
	tok, err := Device{Issuer: srv.URL + "/realm", ClientID: "onecloud-s3", Sleep: noSleep, Notify: func(_, c string) { code = c }}.IDToken(context.Background())
	if err != nil || tok != "idt" || code != "ABCD" || polls != 3 {
		t.Fatalf("device flow: tok=%q code=%q polls=%d err=%v", tok, code, polls, err)
	}
}

func TestDeviceFlowDeniedAndRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/auth/device") {
			fmt.Fprint(w, `{"device_code":"dc","user_code":"X","verification_uri":"u","interval":1}`)
			return
		}
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"access_denied"}`)
	}))
	defer srv.Close()
	if _, err := (Device{Issuer: srv.URL, ClientID: "c", Sleep: noSleep}).IDToken(context.Background()); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("denial not reported: %v", err)
	}
	refused := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"invalid_client"}`)
	}))
	defer refused.Close()
	if _, err := (Device{Issuer: refused.URL, ClientID: "c", Sleep: noSleep}).IDToken(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("refusal not reported: %v", err)
	}
}

func TestAssumeRoleSuccessAndErrors(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" || r.Form.Get("RoleArn") != "arn:aws:iam::role/onecloud-object-storage-demo-000001" || r.Form.Get("DurationSeconds") != "3600" {
			t.Errorf("bad STS form")
		}
		switch r.Form.Get("WebIdentityToken") {
		case "good":
			fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>AK</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>ST</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`, secret)
		case "dtd":
			fmt.Fprint(w, `<!DOCTYPE x [<!ENTITY a "b">]><x/>`)
		default:
			w.WriteHeader(403)
			fmt.Fprint(w, `<ErrorResponse><Error><Code>AccessDenied</Code><Message>trust policy denies web identity assumption</Message></Error></ErrorResponse>`)
		}
	}))
	defer srv.Close()
	role, err := RoleARN("demo-000001")
	if err != nil {
		t.Fatal(err)
	}
	c, err := AssumeRole(context.Background(), srv.Client(), srv.URL, role, "good", "s", time.Hour)
	if err != nil || c.AccessKeyID != "AK" || c.SecretAccessKey != secret || c.SessionToken != "ST" || c.Expiration.Year() != 2030 {
		t.Fatalf("credentials not parsed: %v", err)
	}
	for _, f := range []string{"%v", "%+v", "%#v", "%s"} {
		if strings.Contains(fmt.Sprintf(f, c), secret) {
			t.Fatal("credentials exposed by formatting")
		}
	}
	if _, err := AssumeRole(context.Background(), srv.Client(), srv.URL, role, "bad", "s", time.Hour); err == nil || !strings.Contains(err.Error(), "not a member") {
		t.Fatalf("trust refusal lacks hint: %v", err)
	}
	if _, err := AssumeRole(context.Background(), srv.Client(), srv.URL, role, "dtd", "s", time.Hour); err == nil || !strings.Contains(err.Error(), "DTD") {
		t.Fatalf("DTD not refused: %v", err)
	}
	if _, err := AssumeRole(context.Background(), nil, "http://plain", role, "good", "s", time.Hour); err == nil {
		t.Fatal("non-HTTPS endpoint accepted")
	}
}

func TestRoleARNValidatesTenant(t *testing.T) {
	for _, bad := range []string{"", "demo", "demo-00001", "../x-000001", "Demo-000001"} {
		if _, err := RoleARN(bad); err == nil {
			t.Fatalf("tenant %q accepted", bad)
		}
	}
}

func TestDeviceFlowRejectsForeignVerificationURL(t *testing.T) {
	for _, bad := range []string{"file:///etc/hostname", "https://other-host.example/device?user_code=X", "custom-scheme://x", "javascript:alert(1)"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"device_code":"dc","user_code":"ABCD","verification_uri_complete":%q,"interval":1,"expires_in":60}`, bad)
		}))
		notified := false
		_, err := Device{Issuer: srv.URL + "/realm", ClientID: "c", Sleep: noSleep, Notify: func(string, string) { notified = true }}.IDToken(context.Background())
		srv.Close()
		if err == nil || notified {
			t.Fatalf("%s: accepted (err=%v notified=%v)", bad, err, notified)
		}
	}
}

func TestAssumeRoleDoesNotFollowRedirects(t *testing.T) {
	gotToken := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.Form.Get("WebIdentityToken") != ""
	}))
	defer other.Close()
	sts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/", http.StatusTemporaryRedirect)
	}))
	defer sts.Close()
	// Exercise the default client: trust the test CA but keep its redirect policy.
	hc := noRedirectClient()
	hc.Transport = sts.Client().Transport
	if _, err := AssumeRole(context.Background(), hc, sts.URL, "arn:aws:iam::000001:role/x", "SYNTHETIC-ID-TOKEN", "s", time.Hour); err == nil {
		t.Fatal("redirect response accepted as credentials")
	}
	if gotToken {
		t.Fatal("ID token forwarded through a redirect")
	}
}
