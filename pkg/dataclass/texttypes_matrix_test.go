package dataclass

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The public matrix must agree with the supported type set, byte limits and
// boundary tests. Missing documentation is a failure, not a skipped check.
func TestTextTypesMatrix(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "contracts", "text-types.md"))
	if err != nil {
		t.Fatalf("public capability matrix is mandatory: %v", err)
	}
	doc := string(raw)

	rows := matrixRows(t, doc)
	want := SupportedTextTypes()
	if len(rows) != len(want) {
		t.Fatalf("matrix must have exactly %d type rows, got %d (type set changed without the matrix?)", len(want), len(rows))
	}
	for i, row := range rows {
		ty := want[i]
		t.Run(string(ty), func(t *testing.T) {
			if row[0] != string(ty) {
				t.Fatalf("row %d type cell = %q, want %q — canonical order must match SupportedTextTypes()", i, row[0], ty)
			}
			if row[1] != "yes" {
				t.Fatalf("type %q must be marked supported (yes)", ty)
			}
			limit, err := MaxTextBytes(ty)
			if err != nil {
				t.Fatalf("MaxTextBytes(%q): %v", ty, err)
			}
			if row[2] != strconv.Itoa(limit) {
				t.Fatalf("type %q matrix limit = %q, code limit = %d — dual source of truth, fix one side deliberately", ty, row[2], limit)
			}
			for _, refusal := range []string{"ErrTooLarge", "ErrNotUTF8", "ErrEmpty"} {
				if !strings.Contains(row[3], refusal) {
					t.Fatalf("type %q refusal cell must cite %s, got %q", ty, refusal, row[3])
				}
			}
			if strings.TrimSpace(row[4]) == "" {
				t.Fatalf("type %q rationale cell must be non-empty", ty)
			}
			subtest := fmt.Sprintf("TestTextTypes_LimitsExactBoundary/%s", ty)
			if !strings.Contains(row[5], subtest) {
				t.Fatalf("type %q row must cite its exact boundary subtest %q, got %q", ty, subtest, row[5])
			}
		})
	}

	// Cross-cutting rows must reference real boundary test names (no dangling
	// documentation), and the form row must disclose that DetectType never
	// produces the type.
	for _, tc := range []struct {
		battery string
		note    string
	}{
		{"TestTextTypes_LimitIsBytesNotRunes", "RU/EN multibyte note must cite the bytes-not-runes battery"},
		{"TestTextTypes_CheckOrderIsFixedAndObservable", "check-order note must cite the order battery"},
		{"TestTextTypes_EmptyAndWhitespaceRefused", "whitespace-refusal note must cite the emptiness battery"},
		{"TestTextTypes_ParseRefusesUnknown", "closed-set note must cite the unknown-type battery"},
	} {
		if !strings.Contains(doc, tc.battery) {
			t.Errorf("%s: %s (test missing from the contract)", tc.battery, tc.note)
		}
	}
	if !strings.Contains(doc, "DetectType never returns form") {
		t.Errorf("the form row must disclose that DetectType never returns form (caller-declared only)")
	}
}

// matrixRows extracts the pipe-table data rows (cells trimmed) from the
// public contract: the first table in the document.
func matrixRows(t *testing.T, doc string) [][]string {
	t.Helper()
	var rows [][]string
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "|") {
			if len(rows) > 0 {
				break // table ended
			}
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) < 6 {
			continue // header or |---| separator
		}
		if cells[0] == "Type" || strings.HasPrefix(cells[0], "-") {
			continue
		}
		rows = append(rows, cells)
	}
	return rows
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repo root (go.mod) not found")
		}
		dir = parent
	}
}
