// Package s3sso turns a OneCloud Portal sign-in into temporary object-storage
// credentials: an ID token for the dedicated Keycloak client (onecloud-s3) is
// exchanged at the SSO S3 gateway with STS AssumeRoleWithWebIdentity.
//
// The ID token and the temporary keys stay in process memory: nothing here
// writes them to disk, logs them or puts them in error messages.
package s3sso

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// RoleARN is the per-tenant role declared by the gateway (#2527).
func RoleARN(tenant string) (string, error) {
	if !tenantRef.MatchString(tenant) {
		return "", fmt.Errorf("tenant %q is not a <slug>-<six digits> reference", tenant)
	}
	return "arn:aws:iam::role/onecloud-object-storage-" + tenant, nil
}

var tenantRef = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?-[0-9]{6}$`)

// Credentials are temporary S3 keys. Never format or log them.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

func (Credentials) String() string   { return "s3sso.Credentials{redacted}" }
func (Credentials) GoString() string { return "s3sso.Credentials{redacted}" }

// Device runs the OAuth device flow and returns the ID token. Notify shows
// the verification address and code; the browser session of the OneCloud
// account is reused, so no password is asked when already signed in.
type Device struct {
	Issuer   string
	ClientID string
	HTTP     *http.Client
	Notify   func(verificationURL, userCode string)
	Sleep    func(context.Context, time.Duration) error
	Deadline time.Duration
}

// noRedirectClient never follows redirects: a 307/308 would replay the POST
// body (device code, ID token) to whatever origin the response names.
func noRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (d Device) client() *http.Client {
	if d.HTTP != nil {
		return d.HTTP
	}
	return noRedirectClient()
}

// verificationURL accepts only an http(s) page on the issuer's own origin
// (https, or http for a loopback test issuer); anything else is never handed
// to the browser opener.
func verificationURL(raw, issuer string) (string, error) {
	u, err := url.Parse(raw)
	iss, ierr := url.Parse(issuer)
	if err != nil || ierr != nil || u.Host == "" || u.User != nil ||
		!strings.EqualFold(u.Scheme, iss.Scheme) || !strings.EqualFold(u.Host, iss.Host) ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("object storage sign-in: the verification address is not on the issuer")
	}
	return u.String(), nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func post(ctx context.Context, hc *http.Client, endpoint string, form url.Values) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, err
}

// IDToken returns the ID token once the user approves the code.
func (d Device) IDToken(ctx context.Context) (string, error) {
	base := strings.TrimSuffix(d.Issuer, "/") + "/protocol/openid-connect"
	status, body, err := post(ctx, d.client(), base+"/auth/device", url.Values{"client_id": {d.ClientID}, "scope": {"openid"}})
	if err != nil {
		return "", fmt.Errorf("object storage sign-in: %w", err)
	}
	var start struct {
		DeviceCode   string `json:"device_code"`
		UserCode     string `json:"user_code"`
		URI          string `json:"verification_uri"`
		URIComplete  string `json:"verification_uri_complete"`
		Interval     int    `json:"interval"`
		ExpiresIn    int    `json:"expires_in"`
		Error        string `json:"error"`
		ErrorMessage string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &start)
	if status != http.StatusOK || start.DeviceCode == "" {
		return "", fmt.Errorf("object storage sign-in refused (HTTP %d %s %s)", status, start.Error, start.ErrorMessage)
	}
	if d.Notify != nil {
		raw := start.URIComplete
		if raw == "" {
			raw = start.URI
		}
		u, err := verificationURL(raw, d.Issuer)
		if err != nil {
			return "", err
		}
		d.Notify(u, start.UserCode)
	}
	interval := time.Duration(max(start.Interval, 1)) * time.Second
	limit := d.Deadline
	if limit <= 0 {
		limit = 10 * time.Minute
	}
	if start.ExpiresIn > 0 && time.Duration(start.ExpiresIn)*time.Second < limit {
		limit = time.Duration(start.ExpiresIn) * time.Second
	}
	sleep := d.Sleep
	if sleep == nil {
		sleep = sleepCtx
	}
	for waited := time.Duration(0); waited < limit; waited += interval {
		if err := sleep(ctx, interval); err != nil {
			return "", fmt.Errorf("object storage sign-in: %w", err)
		}
		status, body, err := post(ctx, d.client(), base+"/token", url.Values{
			"grant_type": {deviceGrant}, "device_code": {start.DeviceCode}, "client_id": {d.ClientID},
		})
		if err != nil {
			return "", fmt.Errorf("object storage sign-in: %w", err)
		}
		var t struct {
			IDToken string `json:"id_token"`
			Error   string `json:"error"`
			Desc    string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &t)
		switch {
		case status == http.StatusOK && t.IDToken != "":
			return t.IDToken, nil
		case status == http.StatusOK:
			return "", errors.New("object storage sign-in: no ID token in the response")
		case t.Error == "authorization_pending":
		case t.Error == "slow_down":
			interval += 5 * time.Second
		default:
			return "", fmt.Errorf("object storage sign-in failed: %s %s", t.Error, t.Desc)
		}
	}
	return "", errors.New("object storage sign-in was not approved in time")
}

// AssumeRole exchanges the ID token for temporary credentials.
func AssumeRole(ctx context.Context, hc *http.Client, endpoint, roleARN, idToken, session string, duration time.Duration) (Credentials, error) {
	if hc == nil {
		hc = noRedirectClient()
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return Credentials{}, errors.New("SSO S3 endpoint must be an HTTPS origin")
	}
	status, body, err := post(ctx, hc, strings.TrimSuffix(endpoint, "/")+"/", url.Values{
		"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"},
		"RoleArn": {roleARN}, "RoleSessionName": {session},
		"WebIdentityToken": {idToken}, "DurationSeconds": {strconv.Itoa(int(duration / time.Second))},
	})
	if err != nil {
		return Credentials{}, fmt.Errorf("object storage STS: %w", err)
	}
	// Go's XML decoder does not expand external entities; refuse DTDs anyway.
	if bytes.Contains(body, []byte("<!DOCTYPE")) || bytes.Contains(body, []byte("<!ENTITY")) {
		return Credentials{}, errors.New("object storage STS answer contains a DTD, refused")
	}
	var r struct {
		Creds struct {
			AccessKeyID     string `xml:"AccessKeyId"`
			SecretAccessKey string `xml:"SecretAccessKey"`
			SessionToken    string `xml:"SessionToken"`
			Expiration      string `xml:"Expiration"`
		} `xml:"AssumeRoleWithWebIdentityResult>Credentials"`
		Code    string `xml:"Error>Code"`
		Message string `xml:"Error>Message"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return Credentials{}, fmt.Errorf("object storage STS answered HTTP %d with an unreadable body", status)
	}
	if status != http.StatusOK || r.Creds.AccessKeyID == "" || r.Creds.SecretAccessKey == "" || r.Creds.SessionToken == "" {
		msg := r.Message
		if msg == "" {
			msg = r.Code
		}
		if msg == "" {
			msg = "HTTP " + strconv.Itoa(status)
		}
		return Credentials{}, fmt.Errorf("object storage access refused: %s", hint(msg))
	}
	exp, _ := time.Parse(time.RFC3339, r.Creds.Expiration)
	return Credentials{AccessKeyID: r.Creds.AccessKeyID, SecretAccessKey: r.Creds.SecretAccessKey, SessionToken: r.Creds.SessionToken, Expiration: exp}, nil
}

// hint adds the likely cause to the gateway's known refusals.
func hint(msg string) string {
	switch {
	case strings.Contains(msg, "trust policy"):
		return msg + " (your account is not a member of this tenant)"
	case strings.Contains(msg, "audience"):
		return msg + " (token issued for another client)"
	}
	return msg
}
