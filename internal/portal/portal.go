// Package portal talks to the OneCloud portal API as a native client: a
// loopback PKCE sign-in with the portal's public client, then the connection
// inventory (/api/provisioning/connections) the DBeaver plugin also uses.
// ocd uses it for instance CA certificates and direct tenant VPC addresses.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/procmem"
)

// ConnectionsPath is the portal inventory endpoint (BFF -> provisioning /v1/connections).
const ConnectionsPath = "/api/provisioning/connections"

// ErrUnauthorized means a previously saved portal bearer was rejected. The
// caller must drop that token and all associated cached tenant addresses.
var ErrUnauthorized = errors.New("portal session expired or revoked")

// Client signs in to the portal and reads the connection inventory.
type Client struct {
	// PortalURL is the portal base, e.g. https://portal.dev-01.onecloud.ldc.dz.
	PortalURL string
	// Issuer is the Keycloak realm of the portal.
	Issuer string
	// ClientID is the portal public PKCE client trusted by the BFF for bearer calls.
	ClientID string
	// Open shows the sign-in page to the user.
	Open func(url string) error
	// CallbackHTML is the page shown once the browser comes back.
	CallbackHTML string
	// HTTP is the client used for every request (default: 30s timeout, no redirects).
	HTTP *http.Client
}

func (c Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type discovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
}

func (c Client) discover(ctx context.Context) (discovery, error) {
	var d discovery
	u := strings.TrimSuffix(c.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return d, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return d, fmt.Errorf("portal sign-in: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return d, fmt.Errorf("portal sign-in: discovery returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return d, fmt.Errorf("portal sign-in: discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return d, errors.New("portal sign-in: discovery has no authorization or token endpoint")
	}
	return d, nil
}

func randomString() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SignIn runs the browser PKCE sign-in on a free loopback port and returns
// the access token. Keycloak accepts any port for the registered
// http://127.0.0.1/callback (RFC 8252 loopback redirect).
func (c Client) SignIn(ctx context.Context) (string, error) {
	return c.SignInWithExpiry(ctx, func(token string, _ time.Time) {})
}

// SignInWithExpiry delivers the access token and its JWT exp to the caller as
// soon as the code exchange finishes. The caller may keep it in a private,
// expiring on-disk cache; it must never log or reuse it past expiration.
func (c Client) SignInWithExpiry(ctx context.Context, remember func(string, time.Time)) (string, error) {
	t, err := c.signIn(ctx)
	if err == nil && remember != nil {
		if expiresAt, err := AccessTokenExpiry(t.Access); err == nil {
			remember(t.Access, expiresAt)
		}
	}
	return t.Access, err
}

// SignInIDToken runs the same browser PKCE sign-in and returns the ID token
// (audience ClientID), for relying parties such as an STS gateway. The token
// is only returned to the caller; it is never cached or logged here.
func (c Client) SignInIDToken(ctx context.Context) (string, error) {
	t, err := c.signIn(ctx)
	if err != nil {
		return "", err
	}
	if t.ID == "" {
		return "", errors.New("sign-in: no ID token in the response")
	}
	return t.ID, nil
}

type tokens struct{ Access, ID string }

func (c Client) signIn(ctx context.Context) (tokens, error) {
	d, err := c.discover(ctx)
	if err != nil {
		return tokens{}, err
	}
	verifier, err := randomString()
	if err != nil {
		return tokens{}, err
	}
	state, err := randomString()
	if err != nil {
		return tokens{}, err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return tokens{}, fmt.Errorf("portal sign-in: %w", err)
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			// A stray local request must not terminate the pending sign-in.
			http.Error(w, "Invalid sign-in state.", http.StatusBadRequest)
			return
		case q.Get("error") != "":
			res.err = fmt.Errorf("portal sign-in refused: %s %s", q.Get("error"), q.Get("error_description"))
		case q.Get("code") == "":
			res.err = errors.New("portal sign-in: no code returned")
		default:
			res.code = q.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if res.err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "Sign-in failed, see the terminal.")
		} else {
			_, _ = io.WriteString(w, c.CallbackHTML)
		}
		select {
		case done <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {c.ClientID},
		"redirect_uri":          {redirect},
		"scope":                 {"openid"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authURL := d.AuthorizationEndpoint + "?" + q.Encode()
	if c.Open != nil {
		if err := c.Open(authURL); err != nil {
			return tokens{}, err
		}
	}

	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		return tokens{}, fmt.Errorf("portal sign-in: %w", ctx.Err())
	}
	if res.err != nil {
		return tokens{}, res.err
	}
	return c.exchange(ctx, d.TokenEndpoint, res.code, redirect, verifier)
}

// AccessTokenExpiry extracts exp from the access token; this is for cache
// lifetime only, not token verification. The portal always validates the
// bearer on every API request, so a forged cache cannot grant authorization.
func AccessTokenExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(parts[1]) > 16384 {
		return time.Time{}, errors.New("access token is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, err
	}
	var claims struct {
		Expiry int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Expiry <= 0 {
		return time.Time{}, errors.New("access token has no expiry")
	}
	return time.Unix(claims.Expiry, 0), nil
}

func (c Client) exchange(ctx context.Context, endpoint, code, redirect, verifier string) (tokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {c.ClientID},
		"code":          {code},
		"redirect_uri":  {redirect},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http().Do(req)
	if err != nil {
		return tokens{}, fmt.Errorf("portal sign-in: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return tokens{}, fmt.Errorf("portal sign-in: token endpoint returned HTTP %d", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil || t.AccessToken == "" {
		return tokens{}, errors.New("portal sign-in: no access token in the response")
	}
	return tokens{Access: t.AccessToken, ID: t.IDToken}, nil
}

// Connection is the part of a portal connection descriptor ocd uses.
type Connection struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenantId"`
	Cluster      string `json:"cluster"`
	Engine       string `json:"engine"`
	InstanceName string `json:"instanceName"`
	VPCAddress   string `json:"vpcAddress"`
	SQLAuth      *struct {
		Mode          string `json:"mode"`
		CACertificate string `json:"caCertificate"`
		Reason        string `json:"reason"`
	} `json:"sqlAuth"`
}

// Namespace returns the Kubernetes namespace in the descriptor id
// (<cluster>/<namespace>/<cnpg>/<service>).
func (c Connection) Namespace() string {
	parts := strings.Split(c.ID, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// Connections returns the whole inventory the signed-in user may see.
func (c Client) Connections(ctx context.Context, token string) ([]Connection, error) {
	var all []Connection
	seen := map[string]bool{}
	cursor := ""
	for page := 0; page < 100; page++ {
		q := url.Values{"limit": {"100"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		u := strings.TrimSuffix(c.PortalURL, "/") + ConnectionsPath + "?" + q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.http().Do(req)
		if err != nil {
			return nil, fmt.Errorf("portal connections: %w", err)
		}
		var body struct {
			Connections []Connection `json:"connections"`
			NextCursor  *string      `json:"nextCursor"`
		}
		status := resp.StatusCode
		ctype := resp.Header.Get("Content-Type")
		err = nil
		if status == http.StatusOK {
			err = json.NewDecoder(resp.Body).Decode(&body)
		}
		resp.Body.Close()
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return nil, fmt.Errorf("%w: connections HTTP %d", ErrUnauthorized, status)
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("portal connections: HTTP %d", status)
		}
		if !strings.Contains(ctype, "json") || err != nil {
			return nil, errors.New("portal connections: the response is not the connection inventory")
		}
		all = append(all, body.Connections...)
		if body.NextCursor == nil || *body.NextCursor == "" {
			return all, nil
		}
		if seen[*body.NextCursor] {
			return nil, errors.New("portal connections: repeated page cursor")
		}
		seen[*body.NextCursor] = true
		cursor = *body.NextCursor
	}
	return nil, errors.New("portal connections: too many pages")
}

// ErrNotFound means the inventory has no such PostgreSQL instance for this user.
var ErrNotFound = errors.New("instance not in your portal connections")

// ErrNoCA means the instance is listed but the portal publishes no CA for it.
var ErrNoCA = errors.New("the portal publishes no CA certificate for this instance")

// FindCA returns the CA certificate of tenant/instance from the inventory.
// tenant is the full "<slug>-<id>" form; it is matched against the tenant
// id or the instance namespace tenant-<tenant>-postgresql.
func FindCA(conns []Connection, tenant, instance string) (string, error) {
	ns := "tenant-" + tenant + "-postgresql"
	found := false
	reason := ""
	for _, c := range conns {
		if c.Engine != "postgresql" || c.InstanceName != instance {
			continue
		}
		if c.TenantID != tenant && c.Namespace() != ns {
			continue
		}
		found = true
		if c.SQLAuth != nil && strings.TrimSpace(c.SQLAuth.CACertificate) != "" {
			return c.SQLAuth.CACertificate, nil
		}
		if c.SQLAuth != nil && c.SQLAuth.Reason != "" {
			reason = c.SQLAuth.Reason
		}
	}
	if found && reason != "" {
		return "", fmt.Errorf("%w (portal: %s)", ErrNoCA, reason)
	}
	if found {
		return "", ErrNoCA
	}
	return "", ErrNotFound
}

// ErrNoVPC means the portal lists the instance but has no usable tenant-network address.
var ErrNoVPC = errors.New("no tenant-network address published for this instance")

var carrierGradeNAT = netip.MustParsePrefix("100.64.0.0/10")

// PrivateIPv4 accepts only RFC 1918 and shared 100.64.0.0/10 IPv4 addresses
// from the portal. Reject public, loopback, link-local and IPv6 addresses so
// an inventory error cannot redirect a tenant client to another network.
func PrivateIPv4(address string) bool {
	ip, err := netip.ParseAddr(strings.TrimSpace(address))
	return err == nil && ip.Is4() && (ip.IsPrivate() || carrierGradeNAT.Contains(ip))
}

// FindVPCAddress returns the tenant-network IP for an authorized VM or database.
// A bare six-digit tenant ID is accepted for VMs; for PostgreSQL the caller
// supplies the full tenant slug. Do not use the public gateway host as a VPC IP.
func FindVPCAddress(conns []Connection, cluster, engine, tenant, instance string) (string, error) {
	for _, c := range conns {
		if c.Engine != engine || c.InstanceName != instance ||
			(c.Cluster != "" && c.Cluster != cluster) ||
			(c.ID != "" && !strings.HasPrefix(c.ID, cluster+"/")) {
			continue
		}
		// A tenant slug alone ("demo") is ambiguous: only trust the namespace
		// in that case. A full tenantRef or six-digit tenant ID may match either.
		ns := c.Namespace()
		if ns == "" && c.ID == "" && c.Cluster == "" {
			continue // unscoped descriptor cannot authorize a direct address
		}
		matchTenant := (c.TenantID == tenant && (len(tenant) > 6 || ns != "")) ||
			(len(tenant) == 6 && strings.HasSuffix(c.TenantID, "-"+tenant)) ||
			(ns != "" && (ns == "tenant-"+tenant+"-"+engine ||
				(len(tenant) == 6 && strings.HasSuffix(ns, "-"+tenant+"-"+engine))))
		if !matchTenant {
			continue
		}
		address := strings.TrimSpace(c.VPCAddress)
		if address == "" {
			return "", ErrNoVPC
		}
		if !PrivateIPv4(address) {
			return "", fmt.Errorf("%w: not a private IPv4 address", ErrNoVPC)
		}
		return address, nil
	}
	return "", ErrNotFound
}

// Instance is a tenant-scoped record returned by the provisioning ledger.
// The persisted outputs map contains public facade values, never revealed keys.
type Instance struct {
	Tenant       string         `json:"tenant"`
	Cluster      string         `json:"cluster"`
	Service      string         `json:"service"`
	InstanceName string         `json:"instance_name"`
	Outputs      map[string]any `json:"outputs"`
}

// Instances lists the signed-in tenant's instances as the portal does for its
// My services page. The backend scopes the inventory to the bearer tenant.
func (c Client) Instances(ctx context.Context, token string) ([]Instance, error) {
	u := strings.TrimSuffix(c.PortalURL, "/") + "/api/provisioning/instances"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fmt.Errorf("portal instances: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("%w: instances HTTP %d", ErrUnauthorized, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("portal instances: HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return nil, errors.New("portal instances: the response is not JSON")
	}
	var instances []Instance
	if err := json.NewDecoder(resp.Body).Decode(&instances); err != nil {
		return nil, fmt.Errorf("portal instances: %w", err)
	}
	return instances, nil
}

// FindInstanceVPC returns a live VM's facade vpc.address in the tenant's
// provisioning ledger. It rejects other tenants, clusters, services and
// malformed addresses even when a matching instance name exists.
func FindInstanceVPC(instances []Instance, cluster, tenant, name string) (string, error) {
	for _, i := range instances {
		if i.Cluster != cluster || i.Service != "vm" || i.InstanceName != name ||
			(i.Tenant != tenant && !(len(tenant) == 6 && strings.HasSuffix(i.Tenant, "-"+tenant))) {
			continue
		}
		vpc, ok := i.Outputs["vpc"].(map[string]any)
		if !ok {
			return "", ErrNoVPC
		}
		address, _ := vpc["address"].(string)
		address = strings.TrimSpace(address)
		if !PrivateIPv4(address) {
			return "", ErrNoVPC
		}
		return address, nil
	}
	return "", ErrNotFound
}

// InstancesPath is the provisioning ledger endpoint (BFF -> provisioning /v1/instances).
const InstancesPath = "/api/provisioning/instances"

// Catalog limits. The CLI fails closed rather than act on a partial or
// runaway inventory. The current unpaged inventory can legitimately hold more
// than one page-size worth of instances; bound total records, not one page.
const (
	catalogPageSize  = 100
	catalogMaxPages  = 100
	catalogMaxItems  = 10000
	catalogMaxBody   = 32 << 20
	revealMaxBody    = 1 << 20
	revealStatusKey  = "status"
	revealedStatus   = "revealed"
	maxRevealedValue = 256 << 10
)

// Status is the provisioning lifecycle of an instance (ProvisioningStatus).
type Status string

// Known statuses. Any other value is kept but never treated as ready.
const (
	StatusPROpen      Status = "pr_open"
	StatusMerged      Status = "merged"
	StatusReady       Status = "ready"
	StatusDegraded    Status = "degraded"
	StatusFailed      Status = "failed"
	StatusUnavailable Status = "unavailable"
)

// Known reports whether s is a status the portal documents.
func (s Status) Known() bool {
	switch s {
	case StatusPROpen, StatusMerged, StatusReady, StatusDegraded, StatusFailed, StatusUnavailable:
		return true
	}
	return false
}

// Deployed means the instance exists in the infrastructure right now
// (ready, or up but reported unhealthy), so connecting is worth trying.
func (s Status) Deployed() bool { return s == StatusReady || s == StatusDegraded }

// Pending means the request is still in flight (pull request open or merged).
func (s Status) Pending() bool { return s == StatusPROpen || s == StatusMerged }

// ErrMalformed means a portal response does not match the documented shape.
// The CLI never acts on a partially understood inventory or reveal.
var ErrMalformed = errors.New("portal returned a malformed response")

// CatalogInstance is one tenant-scoped instance of the provisioning ledger
// (ProvisioningRequestRead). Outputs holds public facade values only;
// secrets are fetched on demand with Reveal and never stored here.
type CatalogInstance struct {
	ID           string         `json:"id"`
	Tenant       string         `json:"tenant"`
	Cluster      string         `json:"cluster"`
	Service      string         `json:"service"`
	InstanceName string         `json:"instance_name"`
	Size         *string        `json:"size"`
	Status       Status         `json:"status"`
	CreatedAt    string         `json:"created_at"`
	ReadyAt      *string        `json:"ready_at"`
	Outputs      map[string]any `json:"outputs"`
	Credentials  *struct {
		Status string  `json:"status"`
		Reason *string `json:"reason"`
	} `json:"credentials"`
}

// Ready is Status.Deployed for this instance.
func (i CatalogInstance) Ready() bool { return i.Status.Deployed() }

// Output returns a public string output, e.g. Output("vpc", "address").
func (i CatalogInstance) Output(path ...string) (string, bool) {
	var cur any = i.Outputs
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur = m[p]
	}
	s, ok := cur.(string)
	return s, ok
}

func (i CatalogInstance) validate() error {
	for name, v := range map[string]string{
		"id": i.ID, "tenant": i.Tenant, "cluster": i.Cluster,
		"service": i.Service, "instance_name": i.InstanceName, "status": string(i.Status),
	} {
		if strings.TrimSpace(v) == "" || v != strings.TrimSpace(v) || strings.ContainsAny(v, "\x00\r\n") {
			return fmt.Errorf("%w: instance without a valid %s", ErrMalformed, name)
		}
	}
	return nil
}

// Catalog returns every instance the bearer may see, following pages until
// the portal reports the end. It accepts the current bare JSON array (one
// complete page) and the wrapped {"instances": [...], "nextCursor": ...}
// shape. It fails closed on HTTP errors, a non-JSON or malformed body,
// missing instance fields, duplicate ids, a repeated cursor, more than
// catalogMaxItems records, or more than catalogMaxPages pages.
func (c Client) Catalog(ctx context.Context, token string) ([]CatalogInstance, error) {
	var all []CatalogInstance
	ids := map[string]bool{}
	cursors := map[string]bool{}
	cursor := ""
	for page := 0; page < catalogMaxPages; page++ {
		items, next, err := c.catalogPage(ctx, token, cursor)
		if err != nil {
			return nil, err
		}
		if len(all)+len(items) > catalogMaxItems {
			return nil, fmt.Errorf("%w: instances inventory exceeds %d records", ErrMalformed, catalogMaxItems)
		}
		for _, i := range items {
			if err := i.validate(); err != nil {
				return nil, fmt.Errorf("portal instances: %w", err)
			}
			if ids[i.ID] {
				return nil, fmt.Errorf("portal instances: %w: duplicate instance id", ErrMalformed)
			}
			ids[i.ID] = true
			all = append(all, i)
		}
		if next == nil || *next == "" {
			return all, nil
		}
		if *next == cursor || cursors[*next] {
			return nil, errors.New("portal instances: repeated page cursor")
		}
		cursors[*next] = true
		cursor = *next
	}
	return nil, errors.New("portal instances: too many pages")
}

func (c Client) catalogPage(ctx context.Context, token, cursor string) ([]CatalogInstance, *string, error) {
	q := url.Values{"limit": {fmt.Sprint(catalogPageSize)}}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	u := strings.TrimSuffix(c.PortalURL, "/") + InstancesPath + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("portal instances: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, nil, fmt.Errorf("%w: instances HTTP %d", ErrUnauthorized, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("portal instances: HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return nil, nil, fmt.Errorf("portal instances: %w: not JSON", ErrMalformed)
	}
	raw, err := readLimited(resp.Body, catalogMaxBody)
	if err != nil {
		return nil, nil, fmt.Errorf("portal instances: %w", err)
	}
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) > 0 && raw[0] == '[' {
		if cursor != "" {
			// A bare array has no paging: getting one after a cursor means
			// the server ignored it and would loop forever.
			return nil, nil, fmt.Errorf("portal instances: %w: unpaged answer to a cursor", ErrMalformed)
		}
		var items []CatalogInstance
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, nil, fmt.Errorf("portal instances: %w", ErrMalformed)
		}
		return items, nil, nil
	}
	var body struct {
		Instances  *[]CatalogInstance `json:"instances"`
		NextCursor *string            `json:"nextCursor"`
	}
	if err := json.Unmarshal(raw, &body); err != nil || body.Instances == nil {
		return nil, nil, fmt.Errorf("portal instances: %w", ErrMalformed)
	}
	return *body.Instances, body.NextCursor, nil
}

// readLimited reads at most limit bytes and fails when the body is longer.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: response too large", ErrMalformed)
	}
	return b, nil
}

// ErrForbidden means the portal refused the reveal for this signed-in user
// (for example a tenant member without reveal rights). The bearer itself is
// still valid, so the caller must not drop it.
var ErrForbidden = errors.New("the portal does not allow you to reveal this instance's credentials")

// ErrNoSecrets means the instance has no revealable secret (HTTP 404 or
// {"status":"missing"}): a normal state, e.g. a VM reached with SSO.
var ErrNoSecrets = errors.New("the portal has no credentials to reveal for this instance")

// RevealPending means the credentials exist but are not readable yet.
type RevealPending struct{ Status string }

func (e *RevealPending) Error() string {
	return fmt.Sprintf("the instance credentials are not ready yet (portal status %q)", e.Status)
}

// Reveal calls POST /api/provisioning/instances/{id}/reveal with the same
// portal bearer as the inventory. Only the values the portal returns are
// kept, in process memory (procmem.Values); the caller must Wipe them when
// done and never print, log or persist them. Errors carry the HTTP status
// only: the response body is never echoed, so a misbehaving backend cannot
// leak a secret through an error message.
func (c Client) Reveal(ctx context.Context, token, instanceID string) (*procmem.Values, error) {
	if strings.TrimSpace(instanceID) == "" || strings.ContainsAny(instanceID, "\x00\r\n") {
		return nil, errors.New("portal reveal: invalid instance id")
	}
	u := strings.TrimSuffix(c.PortalURL, "/") + InstancesPath + "/" + url.PathEscape(instanceID) + "/reveal"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return nil, errors.New("portal reveal: invalid portal URL")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http().Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return nil, fmt.Errorf("portal reveal: %w", err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: reveal HTTP %d", ErrUnauthorized, resp.StatusCode)
	case resp.StatusCode == http.StatusForbidden:
		return nil, ErrForbidden
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNoSecrets
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("portal reveal: HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(resp.Header.Get("Content-Type"), "json") {
		return nil, fmt.Errorf("portal reveal: %w: not JSON", ErrMalformed)
	}
	raw, err := readLimited(resp.Body, revealMaxBody)
	if err != nil {
		return nil, fmt.Errorf("portal reveal: %w", ErrMalformed)
	}
	defer procmem.Zero(raw)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("portal reveal: %w", ErrMalformed)
	}
	if st, ok := fields[revealStatusKey]; ok {
		var status string
		if err := json.Unmarshal(st, &status); err != nil {
			return nil, fmt.Errorf("portal reveal: %w", ErrMalformed)
		}
		delete(fields, revealStatusKey)
		switch {
		case status == "missing" && len(fields) == 0:
			return nil, ErrNoSecrets
		case status != revealedStatus && len(fields) == 0:
			return nil, &RevealPending{Status: status}
		case status != revealedStatus:
			return nil, fmt.Errorf("portal reveal: %w", ErrMalformed)
		}
	}
	values := &procmem.Values{}
	for key, v := range fields {
		var s string
		if key == "" || len(v) > maxRevealedValue || json.Unmarshal(v, &s) != nil {
			values.Wipe()
			return nil, fmt.Errorf("portal reveal: %w", ErrMalformed)
		}
		values.Set(key, []byte(s))
		procmem.Zero(v)
	}
	if values.Len() == 0 {
		return nil, ErrNoSecrets
	}
	return values, nil
}
