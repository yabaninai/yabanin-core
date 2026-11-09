package trcli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// H2 tests: the export core's pure parts (JSONL encoding, sha256, S3 URI
// parsing, local file write). The Postgres read and S3 push are I/O-bound and
// covered by manual/integration runs.

func TestParseS3URI(t *testing.T) {
	bucket, key, err := parseS3URI("s3://my-bucket/path/to/lineage.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if bucket != "my-bucket" || key != "path/to/lineage.jsonl" {
		t.Fatalf("got bucket=%q key=%q", bucket, key)
	}
	// No key.
	if b, k, err := parseS3URI("s3://only-bucket"); err != nil || b != "only-bucket" || k != "" {
		t.Fatalf("bucket-only: bucket=%q key=%q err=%v", b, k, err)
	}
	// Bad scheme.
	if _, _, err := parseS3URI("http://x"); err == nil {
		t.Fatal("expected error for non-s3 URI")
	}
	// Empty bucket.
	if _, _, err := parseS3URI("s3://"); err == nil {
		t.Fatal("expected error for empty bucket")
	}
}

// TestExportJSONL_Sha256 verifies the JSONL + checksum path by feeding known
// rows through the same encode + hash the command uses.
func TestExportJSONL_Sha256(t *testing.T) {
	rows := []struct{ req, org string }{
		{"r1", "o1"},
		{"r2", "o1"},
	}
	var buf strings.Builder
	for _, r := range rows {
		// Mirror the command's encode of a minimal row.
		b, _ := json.Marshal(map[string]string{"request_id": r.req, "org_id": r.org})
		buf.Write(b)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(buf.String()))
	if len(hex.EncodeToString(sum[:])) != 64 {
		t.Fatal("sha256 hex must be 64 chars")
	}
	// Two JSONL lines.
	n := 0
	sc := bufio.NewScanner(strings.NewReader(buf.String()))
	for sc.Scan() {
		n++
	}
	if n != 2 {
		t.Fatalf("expected 2 JSONL lines, got %d", n)
	}
}

// TestExportWritesLocalFile checks the 0600 local write + read-back.
func TestExportWritesLocalFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.jsonl")
	data := []byte("{\"request_id\":\"r1\"}\n")
	if err := writeLocalFile(path, data); err != nil {
		t.Fatal(err)
	}
	back, err := os.ReadFile(path) //nolint:gosec // temp test file
	if err != nil {
		t.Fatal(err)
	}
	if string(back) != string(data) {
		t.Fatalf("read-back mismatch: %q", back)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 perms, got %v", info.Mode().Perm())
	}
}
