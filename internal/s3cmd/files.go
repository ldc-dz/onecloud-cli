package s3cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Get downloads to a private sibling temp file and publishes only a complete
// transfer. Default publication is an atomic no-replace hard link + unlink;
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
	output, err := c.api.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(c.bucket), Key: aws.String(key)})
	if err != nil {
		return safeError("get", err)
	}
	if output.Body == nil {
		return errors.New("S3 get failed: missing response body")
	}
	defer output.Body.Close()
	n, err := io.Copy(temp, output.Body)
	if err != nil {
		return errors.New("S3 get failed: incomplete transfer or local write failure")
	}
	if output.ContentLength != nil && n != *output.ContentLength {
		return errors.New("S3 get failed: incomplete transfer")
	}
	if err := output.Body.Close(); err != nil {
		return errors.New("S3 get failed: response body failure")
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
