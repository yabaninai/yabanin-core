package audit

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var (
	sampleOut    = flag.String("sample.out", "", "write the regenerated sample HTML to this path")
	sampleBanner = flag.Bool("sample.banner", false, "prepend the synthetic-data banner (published example only)")
)

// TestRegenerateSampleHTML is an opt-in maintenance hook: it re-renders the
// bundled sample traffic through the current renderer and writes the artifact,
// so the published example and the datasets/ artifact never drift from the
// shipping code. It is skipped unless -sample.out is passed.
//
//	go test ./pkg/costsim -run TestRegenerateSampleHTML -args -sample.out web/site/static/examples/audit-sample.html -sample.banner
//	go test ./pkg/costsim -run TestRegenerateSampleHTML -args -sample.out datasets/audit/sample_report.html
func TestRegenerateSampleHTML(t *testing.T) {
	if *sampleOut == "" {
		t.Skip("pass -sample.out <path> to regenerate the sample artifact")
	}
	// go test runs from the package dir; treat a repo-relative path as
	// relative to the repo root.
	out := *sampleOut
	if !filepath.IsAbs(out) {
		root, err := filepath.Abs("../..")
		if err != nil {
			t.Fatalf("resolve repo root: %v", err)
		}
		out = filepath.Join(root, out)
	}
	if err := RegenerateSample(out, *sampleBanner); err != nil {
		t.Fatalf("RegenerateSample: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("stat %s: %v", out, err)
	}
	t.Logf("wrote %s (%d bytes)", out, info.Size())
}
