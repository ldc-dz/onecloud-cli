package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/s3cmd"
	"github.com/ldc-dz/onecloud-cli/internal/s3sso"
	"github.com/ldc-dz/onecloud-cli/internal/selector"
)

// useStaticS3Keys forces the portal-published access keys (--static-keys).
var useStaticS3Keys bool

// s3SSODuration is the lifetime asked for temporary object-storage keys.
const s3SSODuration = time.Hour

// ssoCredentials signs in with the OneCloud account (same Keycloak realm as
// ocd login, browser session reused) and exchanges the ID token for
// temporary keys scoped to the tenant. Nothing is cached on disk.
func ssoCredentials(ctx context.Context, cl config.Cluster, tenant string) (s3sso.Credentials, error) {
	role, err := s3sso.RoleARN(tenant)
	if err != nil {
		return s3sso.Credentials{}, err
	}
	clientID := cl.S3SSOClientID
	if clientID == "" {
		clientID = "onecloud-s3"
	}
	var idToken string
	if cl.S3SSOFlow == "pkce" {
		pc := newPortalClient(cl)
		pc.ClientID = clientID
		say("Signing in to object storage with your OneCloud account")
		idToken, err = pc.SignInIDToken(ctx)
	} else {
		idToken, err = deviceIDToken(ctx, cl, clientID)
	}
	if err != nil {
		return s3sso.Credentials{}, err
	}
	return s3sso.AssumeRole(ctx, nil, cl.S3SSOEndpoint, role, idToken, fmt.Sprintf("ocd-%d", time.Now().Unix()), s3SSODuration)
}

func deviceIDToken(ctx context.Context, cl config.Cluster, clientID string) (string, error) {
	opener := browserOpener()
	d := s3sso.Device{
		Issuer: cl.Issuer, ClientID: clientID,
		Notify: func(u, code string) {
			say("Object storage sign-in: confirm code %s with your OneCloud account", code)
			if opener.Disabled() || opener.Open(u) != nil {
				say("Open this address in your browser: %s", u)
			} else {
				say("If no browser tab opened, visit: %s", u)
			}
		},
	}
	return d.IDToken(ctx)
}

// splitSSOTarget parses "<tenant>[/<instance or bucket>]".
func splitSSOTarget(typed string) (tenant, bucket string) {
	tenant, rest, _ := strings.Cut(typed, "/")
	return tenant, rest
}

// tenantBucket maps an instance name to its bucket (<instance>.<tenant id>);
// a full bucket name of this tenant is kept as is.
func tenantBucket(tenant, name string) string {
	id := tenant[len(tenant)-6:]
	if strings.HasSuffix(name, "."+id) {
		return name
	}
	return name + "." + id
}

// filterTenantBuckets keeps the buckets of this tenant only.
func filterTenantBuckets(tenant string, names []string) []string {
	id := "." + tenant[len(tenant)-6:]
	var out []string
	for _, n := range names {
		if strings.HasSuffix(n, id) {
			out = append(out, n)
		}
	}
	return out
}

// ssoTenants lists the tenants of the signed-in account from the portal.
func ssoTenants(ctx context.Context, cl config.Cluster) ([]string, error) {
	_, inst, err := portalCatalog(ctx, cl)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, i := range inst {
		if _, err := s3sso.RoleARN(i.Tenant); err == nil && !seen[i.Tenant] {
			seen[i.Tenant] = true
			out = append(out, i.Tenant)
		}
	}
	sort.Strings(out)
	return out, nil
}

func choose(ctx context.Context, title string, names []string) (string, error) {
	if len(names) == 1 {
		return names[0], nil
	}
	items := make([]selector.Item, len(names))
	for i, n := range names {
		items[i] = selector.Item{Label: n}
	}
	idx, err := selector.Select(ctx, title, items)
	if errors.Is(err, selector.ErrNotInteractive) {
		return "", fmt.Errorf("%s: pass it on the command line (one of %s)", title, strings.Join(names, ", "))
	}
	if err != nil {
		return "", err
	}
	return names[idx], nil
}

// openSSOBucket signs in with the OneCloud account, gets temporary keys for
// the tenant, and lets the user pick one of the tenant's buckets as seen by
// the SSO gateway itself (not the portal inventory).
func openSSOBucket(ctx context.Context, cl config.Cluster, typed string) (*s3cmd.Client, string, error) {
	tenant, bucket := splitSSOTarget(typed)
	if tenant == "" {
		tenants, err := ssoTenants(ctx, cl)
		if err != nil {
			return nil, "", err
		}
		if len(tenants) == 0 {
			return nil, "", errors.New("your OneCloud account belongs to no tenant with object storage")
		}
		if tenant, err = choose(ctx, "Tenant", tenants); err != nil {
			return nil, "", err
		}
	}
	if _, err := s3sso.RoleARN(tenant); err != nil {
		return nil, "", err
	}
	creds, err := ssoCredentials(ctx, cl, tenant)
	if err != nil {
		return nil, "", err
	}
	// The bucket field is only a placeholder until a bucket is chosen.
	c, err := s3cmd.New(s3cmd.Config{
		EndpointURL: cl.S3SSOEndpoint, Region: "us-east-1", Bucket: "_",
		AccessKey: creds.AccessKeyID, SecretKey: creds.SecretAccessKey, SessionToken: creds.SessionToken,
	})
	if err != nil {
		return nil, "", err
	}
	if bucket == "" {
		all, err := c.Buckets(ctx)
		if err != nil {
			return nil, "", err
		}
		mine := filterTenantBuckets(tenant, all)
		if len(mine) == 0 {
			return nil, "", fmt.Errorf("tenant %s has no bucket on %s", tenant, cl.S3SSOEndpoint)
		}
		if bucket, err = choose(ctx, "Bucket", mine); err != nil {
			return nil, "", err
		}
	} else {
		bucket = tenantBucket(tenant, bucket)
	}
	c, err = c.WithBucket(bucket)
	return c, tenant + "/" + bucket, err
}
