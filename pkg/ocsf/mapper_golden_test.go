package ocsf

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// update rewites the golden fixtures: `go test ./pkg/ocsf/ -update`.
// A regenerated fixture MUST be reviewed: golden files are the pinned
// canonical encoding of the export contract (W01-C03), not scratch
// output. Field order is the struct declaration order (record.go).
var update = flag.Bool("update", false, "rewrite golden fixture files")

// goldenCases pins the canonical encoding of every mapping-artifact row
// plus the documented variants (unmapped type; unknown cost and unknown
// identity — the never-collapse rules).
var goldenCases = []struct {
	name string
	mut  func(*secevents.Event)
}{
	{"deny-full.json", func(ev *secevents.Event) {}},
	{"mask.json", func(ev *secevents.Event) {}},
	{"flag.json", func(ev *secevents.Event) {}},
	{"allow.json", func(ev *secevents.Event) {}},
	{"unknown-type.json", func(ev *secevents.Event) {}},
	{"cost-unknown-identity-unknown.json", func(ev *secevents.Event) {
		ev.Cost = secevents.Cost{State: secevents.CostUnknown}
		ev.Identity.Session = secevents.IDRef{State: secevents.IDUnknown}
	}},
}

func goldenEvent(name string) secevents.Event {
	switch name {
	case "deny-full.json":
		return fixture("policy.deny")
	case "mask.json":
		return fixture("policy.mask")
	case "flag.json":
		return fixture("policy.flag")
	case "allow.json":
		return fixture("policy.allow")
	case "unknown-type.json":
		return fixture("policy.quarantine")
	case "cost-unknown-identity-unknown.json":
		return fixture("policy.mask")
	}
	panic("unmapped golden case: " + name)
}

func TestGoldenCanonicalRecords(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			ev := goldenEvent(tc.name)
			tc.mut(&ev)
			rec, err := MapEvent(ev)
			if err != nil {
				t.Fatalf("MapEvent: %v", err)
			}
			got, err := marshalGolden(rec)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			path := filepath.Join(dir, tc.name)
			if *update {
				if err := os.MkdirAll(dir, 0o750); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}
			// #nosec G304 -- the path is built from this package's own
			// testdata/golden directory and the fixed case table above;
			// no external input reaches it.
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden (run `go test ./pkg/ocsf/ -update` once and review the diff): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("canonical record drifted from golden %s\n--- golden ---\n%s\n--- got ---\n%s",
					tc.name, want, got)
			}
		})
	}
}

// marshalGolden is the on-disk golden form: the canonical JSON encoding,
// indented for review, with a trailing newline. Indentation does not
// change the contract: compact and indented forms decode to the same
// record and preserve the same key order.
func marshalGolden(rec NormalizedRecord) ([]byte, error) {
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, data, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
