package config

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (rt roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return rt(r) }
func TestProductionDiscovery(t *testing.T) {
	cl, err := Builtin().Merge(Config{}).Cluster("")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, issuer, portal string
		status               int
	}{
		{"before", legacyIssuer, legacyPortal, 200},
		{"after", productionIssuer, productionPortal, 200},
		{"other realm", productionIssuer + "x", "", 200},
		{"wrong host", "https://auth.example.com/realms/prd-01-portal", "", 200},
		{"downgrade", strings.Replace(productionIssuer, "https:", "http:", 1), "", 200},
		{"redirect", productionIssuer, "", 302},
		{"unavailable", legacyIssuer, "", 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := resolveProduction(context.Background(), cl, roundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls != 1 || r.Method != "GET" || r.URL.String() != productionIssuer+"/.well-known/openid-configuration" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Fatal("unexpected discovery request")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Location": []string{"https://example.com/"}}, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"issuer":%q}`, tc.issuer)))}, nil
			}))
			if tc.portal == "" {
				if err == nil {
					t.Fatal("unsafe discovery accepted")
				}
				return
			}
			if err != nil || got.Issuer != tc.issuer || got.PostgresIssuer != tc.issuer || got.PortalURL != tc.portal || got.TCPDomain != cl.TCPDomain || got.S3SSOEndpoint != cl.S3SSOEndpoint {
				t.Fatalf("resolved %+v: %v", got, err)
			}
		})
	}
}
