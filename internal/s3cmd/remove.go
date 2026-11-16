package s3cmd

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// RemoveOptions selects exactly one mode. Prefix mode requires Recursive and a
// nonempty slash-terminated prefix. DryRun never deletes, even if Yes is set.
type RemoveOptions struct {
	Key       string
	Prefix    string
	Recursive bool
	DryRun    bool
	Yes       bool
}

// ValidateRemoval is pure and may be used before credential reveal or prompts.
func ValidateRemoval(o RemoveOptions) error {
	if (o.Key == "") == (o.Prefix == "") {
		return fmt.Errorf("%w: choose an exact key OR a prefix", ErrInvalidRemoval)
	}
	if o.Key != "" {
		if exactKey(o.Key) != nil || o.Key == "." || o.Key == ".." || strings.HasSuffix(o.Key, "/") || o.Recursive {
			return fmt.Errorf("%w: folder-like exact keys and recursive exact-key mode are forbidden", ErrInvalidRemoval)
		}
	} else {
		if !o.Recursive || !strings.HasSuffix(o.Prefix, "/") || strings.ContainsRune(o.Prefix, '\x00') {
			return fmt.Errorf("%w: prefix removal needs recursive and a slash-terminated prefix", ErrInvalidRemoval)
		}
		// Folder-looking root/dot paths are dangerous even though S3 keys are opaque.
		// Reject these targets, without ever normalizing an allowed key/prefix.
		onlyDotsOrSlashes := true
		for _, r := range o.Prefix {
			if r != '.' && r != '/' {
				onlyDotsOrSlashes = false
				break
			}
		}
		if onlyDotsOrSlashes {
			return fmt.Errorf("%w: bucket-root removal is forbidden", ErrInvalidRemoval)
		}
	}
	if !o.DryRun && !o.Yes {
		return ErrConfirmation
	}
	return nil
}

// RemovalPlan freezes the listed current keys before any DELETE. Private fields
// and defensive Keys copies prevent a caller changing a confirmed manifest.
// There is no version/history deletion, DeleteBucket, or prefix-wide API call.
// This freezes keys, not versions/content: an object overwritten between
// preparation and execution is still deleted. Gateway conditional-DELETE
// support is not assumed, so applications must communicate this limitation.
type RemovalPlan struct {
	client   *Client
	keys     []string
	dryRun   bool
	mu       sync.Mutex
	executed bool
}

func (p *RemovalPlan) Keys() []string { return append([]string(nil), p.keys...) }

func (c *Client) PrepareRemoval(ctx context.Context, o RemoveOptions) (*RemovalPlan, error) {
	if err := ValidateRemoval(o); err != nil {
		return nil, err
	}
	keys := []string{o.Key}
	if o.Prefix != "" {
		objects, err := c.List(ctx, o.Prefix)
		if err != nil {
			return nil, err
		}
		keys = make([]string, len(objects))
		for i, obj := range objects {
			keys[i] = obj.Key
		}
	}
	return &RemovalPlan{client: c, keys: keys, dryRun: o.DryRun}, nil
}

// Execute deletes only the frozen manifest and destructive execution is
// single-use. The returned slice records successful deletions before any failure;
// a partial deletion is never reported as complete success. Dry-run returns an
// empty deleted slice without consuming the plan, allowing subsequent confirmation.
func (p *RemovalPlan) Execute(ctx context.Context) ([]string, error) {
	return p.execute(ctx, p.dryRun)
}

// ExecuteConfirmed is the interactive-prompt seam: prepare with DryRun true,
// display Keys, ask the user, then pass their explicit affirmative answer here.
// It uses exactly the same frozen manifest, without a second listing. False
// never sends a deletion or consumes the plan. Calling Execute instead always
// respects the original DryRun flag. Destructive execution is single-use.
func (p *RemovalPlan) ExecuteConfirmed(ctx context.Context, yes bool) ([]string, error) {
	if !yes {
		return nil, ErrConfirmation
	}
	return p.execute(ctx, false)
}

func (p *RemovalPlan) execute(ctx context.Context, dryRun bool) ([]string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.executed {
		return nil, fmt.Errorf("removal plan has already been executed")
	}
	deleted := []string{}
	if dryRun {
		return deleted, nil
	}
	p.executed = true
	for _, key := range p.keys {
		_, err := p.client.api.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(p.client.bucket), Key: aws.String(key)})
		if err != nil {
			return deleted, safeError("remove", err)
		}
		deleted = append(deleted, key)
	}
	return deleted, nil
}
