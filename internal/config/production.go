package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	productionIssuer = "https://auth.onecloud.dz/realms/prd-01-portal"
	legacyIssuer     = "https://auth.onecloud.ldc.dz/realms/prd-01-portal"
	productionPortal = "https://portal.onecloud.dz"
	legacyPortal     = "https://portal.onecloud.ldc.dz"
)

// RuntimeCluster binds production defaults to the single issuer currently published
// by Keycloak. No token or cookie is attached to the bootstrap request; neither
// redirects nor arbitrary realm names can choose where credentials will be used.
func (c Config) RuntimeCluster(ctx context.Context, name string) (Cluster, error) {
	cl, err := c.Cluster(name)
	if err != nil || cl.Name != "ocd-prd-01" || cl.Issuer != productionIssuer {
		return cl, err
	}
	return resolveProduction(ctx, cl, nil)
}

func resolveProduction(ctx context.Context, cl Cluster, transport http.RoundTripper) (Cluster, error) {
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, productionIssuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return Cluster{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Cluster{}, fmt.Errorf("production issuer discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Cluster{}, fmt.Errorf("production issuer discovery: HTTP %d", resp.StatusCode)
	}
	const limit = 1 << 20
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err != nil || len(b) > limit || json.Unmarshal(b, &doc) != nil || (doc.Issuer != productionIssuer && doc.Issuer != legacyIssuer) {
		return Cluster{}, errors.New("production issuer discovery: expected an allowlisted production realm")
	}
	cl.Issuer = doc.Issuer
	if cl.PostgresIssuer == productionIssuer {
		cl.PostgresIssuer = doc.Issuer
	}
	if cl.PortalURL == productionPortal && doc.Issuer == legacyIssuer {
		cl.PortalURL = legacyPortal
	}
	return cl, nil
}
