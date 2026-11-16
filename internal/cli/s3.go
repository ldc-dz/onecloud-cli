package cli

import (
	"context"
	"errors"
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/ldc-dz/onecloud-cli/internal/config"
	"github.com/ldc-dz/onecloud-cli/internal/s3cmd"
	"github.com/ldc-dz/onecloud-cli/internal/services"
)

// s3Timeout bounds one S3 command, transfers included.
const s3Timeout = 30 * time.Minute

// openBucket resolves an object-storage instance, reads its published
// endpoint and bucket, and reveals its access keys into memory only.
func openBucket(ctx context.Context, cl config.Cluster, typed string) (*s3cmd.Client, string, error) {
	if cl.S3SSOEndpoint != "" && !useStaticS3Keys {
		return openSSOBucket(ctx, cl, typed)
	}
	sess, e, err := pickService(ctx, cl, typed, "s3 ls", services.ObjectStorage)
	if err != nil {
		return nil, "", err
	}
	endpoint := firstValue(nil, e, "endpoint", "s3Endpoint")
	bucket := firstValue(nil, e, "bucket")
	if endpoint == "" || bucket == "" {
		return nil, "", fmt.Errorf("%s: the portal publishes no S3 endpoint or bucket yet", e.Target())
	}
	region := firstValue(nil, e, "region")
	if region == "" {
		region = "us-east-1"
	}
	vals, err := sess.reveal(ctx, cl, e)
	if err != nil {
		return nil, "", err
	}
	defer vals.Wipe()
	c, err := s3cmd.New(s3cmd.Config{
		EndpointURL: endpoint, Region: region, Bucket: bucket,
		AccessKey: firstValue(vals, e, "accessKey", "access_key", "AWS_ACCESS_KEY_ID"),
		SecretKey: firstValue(vals, e, "secretKey", "secret_key", "AWS_SECRET_ACCESS_KEY"),
	})
	return c, e.Target(), err
}

func newS3Cmd(cluster func() (config.Cluster, error)) *cobra.Command {
	root := &cobra.Command{
		Use:   "s3",
		Short: "List, download, upload and remove objects in a tenant managed object storage",
		Long: "The target is the object-storage instance (<tenant>/<instance>); its bucket and\n" +
			"endpoint come from the portal. Without a target, ocd lets you choose one.\n" +
			"Keys are used exactly as written: no wildcards, no path cleaning.",
	}
	with := func(args []string, fn func(context.Context, *s3cmd.Client, string) error) error {
		cl, err := cluster()
		if err != nil {
			return err
		}
		typed := ""
		if len(args) > 0 {
			typed = args[0]
		}
		ctx, stop := context.WithTimeout(context.Background(), s3Timeout)
		defer stop()
		c, name, err := openBucket(ctx, cl, typed)
		if err != nil {
			return err
		}
		return fn(ctx, c, name)
	}

	var prefix string
	ls := &cobra.Command{
		Use:   "ls [<tenant>/<instance>]",
		Short: "List objects (all pages)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return with(args, func(ctx context.Context, s *s3cmd.Client, _ string) error {
				objects, err := s.List(ctx, prefix)
				if err != nil {
					return err
				}
				w := tabwriter.NewWriter(c.OutOrStdout(), 0, 4, 2, ' ', 0)
				for _, o := range objects {
					fmt.Fprintf(w, "%s\t%d\t%s\n", o.LastModified.Local().Format(time.RFC3339), o.Size, display(o.Key))
				}
				return w.Flush()
			})
		},
	}
	ls.Flags().StringVar(&prefix, "prefix", "", "only keys starting with this literal prefix")

	var getKey, output string
	var getOverwrite bool
	get := &cobra.Command{
		Use:   "get [<tenant>/<instance>] --key <key> --output <file>",
		Short: "Download one object (never overwrites without --overwrite)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if getKey == "" || output == "" {
				return errors.New("--key and --output are required")
			}
			return with(args, func(ctx context.Context, s *s3cmd.Client, name string) error {
				if err := s.Get(ctx, getKey, output, getOverwrite); err != nil {
					return err
				}
				say("Downloaded %s from %s to %s", display(getKey), name, output)
				return nil
			})
		},
	}
	get.Flags().StringVar(&getKey, "key", "", "exact object key")
	get.Flags().StringVarP(&output, "output", "o", "", "local file to write")
	get.Flags().BoolVar(&getOverwrite, "overwrite", false, "replace an existing local file")

	var putKey string
	var putOverwrite bool
	put := &cobra.Command{
		Use:   "put [<tenant>/<instance>] <file> --key <key>",
		Short: "Upload one file (refuses to replace an existing object without --overwrite)",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(_ *cobra.Command, args []string) error {
			if putKey == "" {
				return errors.New("--key is required")
			}
			file := args[len(args)-1]
			return with(args[:len(args)-1], func(ctx context.Context, s *s3cmd.Client, name string) error {
				if err := s.Put(ctx, putKey, file, putOverwrite); err != nil {
					return err
				}
				say("Uploaded %s to %s as %s", file, name, display(putKey))
				return nil
			})
		},
	}
	put.Flags().StringVar(&putKey, "key", "", "exact object key")
	put.Flags().BoolVar(&putOverwrite, "overwrite", false, "replace an existing object")

	var ro s3cmd.RemoveOptions
	rm := &cobra.Command{
		Use:   "rm [<tenant>/<instance>] (--key <key> | --prefix <dir/> --recursive) (--dry-run | --yes)",
		Short: "Remove one object, or every object under a prefix",
		Long: "Removes the exact key, or with --recursive every object listed under a\n" +
			"slash-terminated prefix. The list is taken once and only those objects are\n" +
			"removed. Bucket-root and folder-like exact keys are refused. Use --dry-run\n" +
			"to see what would go, then --yes to remove it. Removal is not transactional.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			// Refuse unsafe requests before any sign-in or network call.
			if err := s3cmd.ValidateRemoval(ro); err != nil {
				return err
			}
			return with(args, func(ctx context.Context, s *s3cmd.Client, name string) error {
				plan, err := s.PrepareRemoval(ctx, ro)
				if err != nil {
					return err
				}
				keys := plan.Keys()
				if ro.DryRun {
					for _, k := range keys {
						fmt.Fprintln(c.OutOrStdout(), "would remove", display(k))
					}
					say("%d object(s) in %s would be removed (dry run)", len(keys), name)
					return nil
				}
				deleted, err := plan.Execute(ctx)
				for _, k := range deleted {
					fmt.Fprintln(c.OutOrStdout(), "removed", display(k))
				}
				if err != nil {
					return fmt.Errorf("removed %d of %d object(s) in %s: %w", len(deleted), len(keys), name, err)
				}
				say("Removed %d object(s) from %s", len(deleted), name)
				return nil
			})
		},
	}
	rf := rm.Flags()
	rf.StringVar(&ro.Key, "key", "", "exact object key")
	rf.StringVar(&ro.Prefix, "prefix", "", "slash-terminated prefix (needs --recursive)")
	rf.BoolVar(&ro.Recursive, "recursive", false, "remove every object under --prefix")
	rf.BoolVar(&ro.DryRun, "dry-run", false, "only list what would be removed")
	rf.BoolVar(&ro.Yes, "yes", false, "confirm the removal")

	root.PersistentFlags().BoolVar(&useStaticS3Keys, "static-keys", false, "use the portal access keys instead of the OneCloud account sign-in")
	root.AddCommand(ls, get, put, rm)
	return root
}
