// Package s3cmd implements managed, path-style S3 operations. Credentials stay
// in process memory; this package never loads shared AWS config or logs requests.
package s3cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

var (
	ErrExists         = errors.New("destination already exists; use explicit overwrite")
	ErrConfirmation   = errors.New("removal requires dry-run or explicit yes confirmation")
	ErrInvalidRemoval = errors.New("unsafe removal target")
	ErrInvalidKey     = errors.New("an exact nonempty object key is required")
)

// Config uses the published instance endpoint and bucket, not an arbitrary
// bucket inferred from an instance name. HTTPClient is a trusted test seam;
// endpoints always require HTTPS and credentials are never read from disk/env.
// Never log or embed Config in another logged struct: Go reflection/encoding and
// formatting unexported container fields can bypass the redacting fmt methods.
// The default HTTP client caps an entire request/transfer at 30 minutes.
type Config struct {
	EndpointURL string
	Region      string
	Bucket      string
	AccessKey   string
	SecretKey   string
	// SessionToken is set for temporary (STS) credentials.
	SessionToken string
	HTTPClient   *http.Client
}

// String and GoString protect direct fmt formatting, including %+v and %#v.
// Redact every field because an invalid endpoint may itself contain secrets.
func (Config) String() string   { return "s3cmd.Config{redacted}" }
func (Config) GoString() string { return "s3cmd.Config{redacted}" }

// Client contains an SDK client with static in-memory credentials only.
type Client struct {
	api    *s3.Client
	bucket string
}

func New(c Config) (*Client, error) {
	u, err := url.Parse(c.EndpointURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("managed S3 endpoint must be an HTTPS origin without credentials, path, query or fragment")
	}
	if strings.TrimSpace(c.Region) == "" || strings.TrimSpace(c.Bucket) == "" || strings.ContainsAny(c.Bucket, "/\\\x00\r\n") || c.AccessKey == "" || c.SecretKey == "" {
		return nil, errors.New("managed S3 requires region, bucket and in-memory access credentials")
	}
	// Clone the caller's client rather than mutate it. Never forward credentials
	// through redirects (including same-origin redirects) or emit SDK logging.
	hc := &http.Client{Timeout: 30 * time.Minute}
	if c.HTTPClient != nil {
		*hc = *c.HTTPClient
	}
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg := aws.Config{Region: c.Region, Credentials: credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, c.SessionToken), HTTPClient: hc, RetryMaxAttempts: 1}
	api := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(strings.TrimSuffix(c.EndpointURL, "/"))
		o.UsePathStyle = true
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &Client{api: api, bucket: c.Bucket}, nil
}

// WithBucket returns a client on another bucket with the same credentials.
func (c *Client) WithBucket(bucket string) (*Client, error) {
	if strings.TrimSpace(bucket) == "" || strings.ContainsAny(bucket, "/\\\x00\r\n") {
		return nil, errors.New("invalid bucket name")
	}
	return &Client{api: c.api, bucket: bucket}, nil
}

// Buckets lists the buckets these credentials can see (sorted).
func (c *Client) Buckets(ctx context.Context) ([]string, error) {
	out, err := c.api.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, safeError("list buckets", err)
	}
	names := make([]string, 0, len(out.Buckets))
	for _, b := range out.Buckets {
		if b.Name != nil && *b.Name != "" {
			names = append(names, *b.Name)
		}
	}
	sort.Strings(names)
	return names, nil
}

// safeError deliberately omits SDK response messages, URLs, request IDs and
// wrapped transport errors, all of which may contain credentials or key data.
func safeError(operation string, err error) error {
	if errors.Is(err, context.Canceled) {
		return fmt.Errorf("S3 %s: %w", operation, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("S3 %s: %w", operation, context.DeadlineExceeded)
	}
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		if response.HTTPStatusCode() == http.StatusPreconditionFailed {
			return fmt.Errorf("S3 %s: %w", operation, ErrExists)
		}
		return fmt.Errorf("S3 %s failed (HTTP %d)", operation, response.HTTPStatusCode())
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		return fmt.Errorf("S3 %s failed (service rejected request)", operation)
	}
	return fmt.Errorf("S3 %s failed (transport or response error)", operation)
}

func exactKey(key string) error {
	// Do not clean, trim, split or otherwise normalize object keys.
	if key == "" || strings.ContainsRune(key, '\x00') {
		return ErrInvalidKey
	}
	return nil
}

// Object is current-object metadata, never historical versions.
type Object struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

const maxListPages = 10000

// List enumerates all current objects. Prefix is a literal string, not a glob or
// local path. Any failed/malformed page discards the partial list.
func (c *Client) List(ctx context.Context, prefix string) ([]Object, error) {
	if strings.ContainsRune(prefix, '\x00') {
		return nil, errors.New("invalid literal prefix")
	}
	objects := []Object{}
	seenTokens := map[string]bool{}
	seenKeys := map[string]bool{}
	var token *string
	for page := 0; page < maxListPages; page++ {
		input := &s3.ListObjectsV2Input{Bucket: aws.String(c.bucket), ContinuationToken: token, EncodingType: types.EncodingTypeUrl}
		if prefix != "" {
			input.Prefix = aws.String(prefix)
		}
		output, err := c.api.ListObjectsV2(ctx, input)
		if err != nil {
			return nil, safeError("list", err)
		}
		if output.IsTruncated == nil {
			return nil, errors.New("S3 list failed: missing pagination status")
		}
		if output.EncodingType != "" && output.EncodingType != types.EncodingTypeUrl {
			return nil, errors.New("S3 list failed: unsupported key encoding")
		}
		for _, obj := range output.Contents {
			key := aws.ToString(obj.Key)
			if output.EncodingType == types.EncodingTypeUrl {
				// encoding-type=url keys are form encoded: AWS S3 and SeaweedFS
				// send a space as '+' (SeaweedFS as '%20' in folder segments and
				// '+' in the last one) and a literal '+' as '%2B', so '+' must be
				// decoded as a space. Path decoding would keep '+' and show a key
				// that does not exist.
				key, err = url.QueryUnescape(key)
				if err != nil {
					return nil, errors.New("S3 list failed: malformed encoded key")
				}
			}
			if exactKey(key) != nil || !strings.HasPrefix(key, prefix) || seenKeys[key] {
				return nil, errors.New("S3 list failed: invalid, duplicate or out-of-prefix object")
			}
			seenKeys[key] = true
			item := Object{Key: key, Size: aws.ToInt64(obj.Size), ETag: aws.ToString(obj.ETag)}
			if obj.LastModified != nil {
				item.LastModified = *obj.LastModified
			}
			objects = append(objects, item)
		}
		if !*output.IsTruncated {
			return objects, nil
		}
		next := aws.ToString(output.NextContinuationToken)
		if next == "" || seenTokens[next] {
			return nil, errors.New("S3 list failed: missing or repeated continuation token")
		}
		seenTokens[next] = true
		token = aws.String(next)
	}
	return nil, errors.New("S3 list failed: page limit exceeded")
}
