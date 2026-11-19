package s3cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Get downloads to a private sibling temp file and publishes only a complete
// transfer; an interrupted transfer is resumed (see download). Default publication is an atomic no-replace hard link + unlink;
// portable os.Rename would silently overwrite. Explicit overwrite uses rename
// (replacing a symlink itself, not following it). All accesses are anchored to
// the opened parent directory, so parent-path changes cannot redirect writes.
func (c *Client) Get(ctx context.Context, key, destination string, overwrite bool) error {
	if err := exactKey(key); err != nil {
		return err
	}
	if destination == "" {
		return errors.New("a local output file is required")
	}
	base := filepath.Base(destination)
	if base == "." || base == string(filepath.Separator) || base == ".." {
		return errors.New("output must name a file, not a directory")
	}
	root, err := os.OpenRoot(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("open output parent: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(base)
	if err == nil {
		if !overwrite {
			return ErrExists
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			return errors.New("output must be a regular file or a replaceable symlink")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect output: %w", err)
	}
	temp, tempName, err := siblingTemp(root)
	if err != nil {
		return err
	}
	defer root.Remove(tempName)
	defer temp.Close()
	if err := c.download(ctx, key, temp); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync downloaded file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close downloaded file: %w", err)
	}
	if overwrite {
		err = root.Rename(tempName, base)
	} else {
		err = root.Link(tempName, base)
	}
	if errors.Is(err, os.ErrExist) {
		return ErrExists
	}
	if err != nil {
		return fmt.Errorf("publish downloaded file: %w", err)
	}
	return nil
}

// getAttempts bounds the requests made for one download: the first one plus
// resumed ones. getBackoff is the wait before attempt n+1 (1, 2, 4, 8, 16 s:
// long enough for a restarted gateway to answer again).
const getAttempts = 6

var getBackoff = func(attempt int) time.Duration { return time.Second << (attempt - 1) }

// localWriter remembers a local write failure, so that it is never reported
// or retried as a transfer problem.
type localWriter struct {
	file *os.File
	err  error
}

func (w *localWriter) Write(p []byte) (int, error) {
	n, err := w.file.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

// download streams the object into file. A transfer cut by the network or by
// the gateway is resumed from the bytes already written with a ranged request
// bound to the same object version (If-Match on the first response's ETag);
// without an ETag nothing can prove the object is unchanged, so the transfer
// fails as before. Requests the gateway could not serve (transport error,
// HTTP 500, 502, 503, 504) are retried the same way.
func (c *Client) download(ctx context.Context, key string, file *os.File) error {
	sink := &localWriter{file: file}
	var written int64
	total := int64(-1)
	etag := ""
	for attempt := 1; ; attempt++ {
		input := &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)}
		if written > 0 {
			input.Range = aws.String(fmt.Sprintf("bytes=%d-", written))
			input.IfMatch = aws.String(etag)
		}
		output, err := c.api.GetObject(ctx, input)
		if err != nil {
			if written > 0 && httpStatus(err) == http.StatusPreconditionFailed {
				return errors.New("S3 get failed: the object changed during the download")
			}
			if attempt < getAttempts && retryableGet(err) && pause(ctx, getBackoff(attempt)) {
				continue
			}
			return safeError("get", err)
		}
		if output.Body == nil {
			return errors.New("S3 get failed: missing response body")
		}
		if written == 0 {
			etag = aws.ToString(output.ETag)
			total = -1
			if output.ContentLength != nil {
				total = *output.ContentLength
			}
		} else if !resumesAt(output, written, total) {
			output.Body.Close()
			return errors.New("S3 get failed: the gateway did not resume the interrupted transfer")
		}
		n, copyErr := io.Copy(sink, output.Body)
		closeErr := output.Body.Close()
		written += n
		if sink.err != nil {
			return fmt.Errorf("write downloaded file: %w", sink.err)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if copyErr == nil && (total < 0 || written == total) {
			if closeErr != nil {
				return errors.New("S3 get failed: response body failure")
			}
			return nil
		}
		if total >= 0 && written > total {
			return errors.New("S3 get failed: more data received than announced")
		}
		if written == total {
			return errors.New("S3 get failed: response body failure")
		}
		if etag == "" || total < 0 || attempt >= getAttempts || !pause(ctx, getBackoff(attempt)) {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fmt.Errorf("S3 get failed: transfer interrupted after %d of %s bytes (%d attempt(s))", written, sizeText(total), attempt)
		}
	}
}

func sizeText(total int64) string {
	if total < 0 {
		return "an unknown number of"
	}
	return fmt.Sprint(total)
}

// resumesAt checks that a ranged response continues exactly where the local
// file stops and ends at the end of the same object.
func resumesAt(output *s3.GetObjectOutput, written, total int64) bool {
	want := fmt.Sprintf("bytes %d-%d/%d", written, total-1, total)
	return aws.ToString(output.ContentRange) == want && output.ContentLength != nil && *output.ContentLength == total-written
}

func httpStatus(err error) int {
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		return response.HTTPStatusCode()
	}
	return 0
}

// retryableGet: the request never reached a gateway able to serve it.
func retryableGet(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	switch httpStatus(err) {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	case 0:
		var apiError smithy.APIError
		return !errors.As(err, &apiError)
	}
	return false
}

// pause waits d; false when the command was cancelled or timed out meanwhile.
func pause(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func siblingTemp(root *os.Root) (*os.File, string, error) {
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", errors.New("cannot create private download file")
		}
		name := ".ocd-s3-" + hex.EncodeToString(random[:]) + ".tmp"
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create download file: %w", err)
		}
		return file, name, nil
	}
	return nil, "", errors.New("cannot create unique private download file")
}

// Put uploads an exact literal key from a regular local file. No path component
// is followed through a symlink. Default overwrite protection is atomic at the
// server: If-None-Match: *. A gateway that rejects conditional PUT fails closed;
// we never fall back to a racy HEAD-then-PUT or unguarded upload.
func (c *Client) Put(ctx context.Context, key, source string, overwrite bool) error {
	if err := exactKey(key); err != nil {
		return err
	}
	if source == "" {
		return errors.New("a local input file is required")
	}
	file, err := openNoFollow(source)
	if err != nil {
		return fmt.Errorf("open upload source without symlinks: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect upload source: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("upload source must be a regular file")
	}
	input := &s3.PutObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key), Body: file, ContentLength: aws.Int64(info.Size())}
	if !overwrite {
		input.IfNoneMatch = aws.String("*")
	}
	_, err = c.api.PutObject(ctx, input)
	if err != nil {
		return safeError("put", err)
	}
	return nil
}
