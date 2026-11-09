package trcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/reireirei/yabanin/pkg/lineage"
	"github.com/spf13/cobra"
)

// lineageExportCmd exports the lineage ledger as JSONL + a sha256 checksum
// (H2). Optionally pushes to S3 with object-lock COMPLIANCE retention.
func lineageExportCmd() *cobra.Command {
	var (
		pgURI   string
		orgID   string
		limit   int
		outFile string
		s3URI   string // s3://bucket/key
		region  string
		// object-lock
		lockCompliance bool
		lockDays       int
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the lineage ledger to JSONL + sha256 (optional S3 object-lock)",
		Long: `Export request_lineage rows (ts order) as JSONL and print a sha256
checksum. With --s3, also push the JSONL to S3 with object-lock COMPLIANCE
retention (WORM).

  yb lineage export --pg-uri postgres://... --out export.jsonl
  yb lineage export --pg-uri ... --org <id> --s3 s3://bucket/lineage.jsonl \
      --region us-east-1 --lock-compliance --lock-days 9250`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLineageExport(cmd.OutOrStdout(), lineageExportOpts{
				PGURI: pgURI, OrgID: orgID, Limit: limit, OutFile: outFile,
				S3URI: s3URI, Region: region, LockCompliance: lockCompliance, LockDays: lockDays,
			})
		},
	}
	cmd.Flags().StringVar(&pgURI, "pg-uri", "", "Postgres URI (required)")
	cmd.Flags().StringVar(&orgID, "org", "", "Optional organization ID (empty = all orgs)")
	cmd.Flags().IntVar(&limit, "limit", 0, "Optional max rows (0 = all)")
	cmd.Flags().StringVar(&outFile, "out", "lineage-export.jsonl", "Output JSONL file path")
	cmd.Flags().StringVar(&s3URI, "s3", "", "Optional S3 target (s3://bucket/key)")
	cmd.Flags().StringVar(&region, "region", "", "AWS region for the S3 target (required with --s3)")
	cmd.Flags().BoolVar(&lockCompliance, "lock-compliance", false, "Enable S3 object-lock COMPLIANCE mode")
	cmd.Flags().IntVar(&lockDays, "lock-days", 2555, "Object-lock retention in days (default 2555)")
	_ = cmd.MarkFlagRequired("pg-uri")
	return cmd
}

type lineageExportOpts struct {
	PGURI          string
	OrgID          string
	Limit          int
	OutFile        string
	S3URI          string
	Region         string
	LockCompliance bool
	LockDays       int
}

// runLineageExport is the pure core: reads rows from Postgres, writes JSONL,
// computes sha256, optionally pushes to S3 with object-lock. Returns an error
// (gate failure) and never calls os.Exit.
func runLineageExport(out io.Writer, o lineageExportOpts) error {
	if out == nil {
		out = io.Discard
	}
	if o.S3URI != "" && o.Region == "" {
		return fmt.Errorf("--region is required when --s3 is set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, o.PGURI)
	if err != nil {
		return fmt.Errorf("connect postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}

	store := lineage.NewLedgerStore(pool)
	rows, err := store.QueryForExport(ctx, o.OrgID, o.Limit)
	if err != nil {
		return err
	}

	// Build JSONL.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encode export row %s: %w", row.RequestID, err)
		}
	}
	sha := sha256.Sum256(buf.Bytes())
	shaHex := hex.EncodeToString(sha[:])

	// Write local JSONL.
	if err := writeLocalFile(o.OutFile, buf.Bytes()); err != nil {
		return err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "rows=%d sha256=%s file=%s\n", len(rows), shaHex, o.OutFile)

	// Optional S3 object-lock push.
	if o.S3URI != "" {
		bucket, key, err := parseS3URI(o.S3URI)
		if err != nil {
			return err
		}
		if err := pushS3Locked(ctx, o.Region, bucket, key, buf.Bytes(), o.LockCompliance, o.LockDays); err != nil {
			return err
		}
		lockMode := "none"
		if o.LockCompliance {
			lockMode = fmt.Sprintf("compliance/%dd", o.LockDays)
		}
		fmt.Fprintf(&b, "s3=s3://%s/%s lock=%s\n", bucket, key, lockMode)
	}

	_, err = fmt.Fprint(out, b.String())
	return err
}

// parseS3URI splits s3://bucket/key into bucket and key.
func parseS3URI(uri string) (bucket, key string, err error) {
	rest := strings.TrimPrefix(uri, "s3://")
	if rest == uri {
		return "", "", fmt.Errorf("--s3 must be of the form s3://bucket/key (got %q)", uri)
	}
	parts := strings.SplitN(rest, "/", 2)
	bucket = parts[0]
	if bucket == "" {
		return "", "", fmt.Errorf("--s3 bucket is empty")
	}
	if len(parts) == 2 {
		key = parts[1]
	}
	return bucket, key, nil
}

// pushS3Locked uploads data to S3, optionally with object-lock COMPLIANCE
// retention (WORM). The bucket must have object-lock enabled for the lock to
// take effect.
func pushS3Locked(ctx context.Context, region, bucket, key string, data []byte, compliance bool, days int) error {
	awsCfg, err := awscfg.LoadDefaultConfig(ctx, awscfg.WithRegion(region))
	if err != nil {
		return fmt.Errorf("load aws config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg)

	in := &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &key,
		Body:          bytes.NewReader(data),
		ContentType:   aws.String("application/x-ndjson"),
		ContentLength: aws.Int64(int64(len(data))),
	}
	if compliance {
		date := time.Now().UTC().AddDate(0, 0, days)
		in.ObjectLockMode = types.ObjectLockModeCompliance
		in.ObjectLockRetainUntilDate = &date
	}
	if _, err := client.PutObject(ctx, in); err != nil {
		return fmt.Errorf("s3 put %s/%s: %w", bucket, key, err)
	}
	return nil
}

// writeLocalFile writes data to path with 0600 perms.
func writeLocalFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write export file %s: %w", path, err)
	}
	return nil
}
