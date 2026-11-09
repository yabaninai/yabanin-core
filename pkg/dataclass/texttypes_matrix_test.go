package dataclass

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// E04-P01-W01-C02 lock-step watchdog: the capability matrix
// (artifacts/enterprise-beta/E04-P01/W01-TEXT-TYPES-2026-11-07.md) and the
// code constants in texttypes.go are two views of one truth. This test
// makes them inseparable:
//   - every matrix row must match its code constant (type, order, limit);
//   - every row must cite the exact C01 boundary subtest;
//   - the documented cross-cutting batteries (multibyte, check order,
//     whitespace refusal, closed set) must be cited, not dangle;
//   - a missing artifact is a FAIL, never a skip (dispatch W01-C02 AC).
//
// Changing a limit without the matrix (or the matrix without the code)
// breaks this test; adding a sixth type in code breaks the row-count
// equality.
func TestTextTypesMatrix(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "artifacts", "enterprise-beta", "E04-P01", "W01-TEXT-TYPES-2026-11-07.md"))
	if err != nil {
		t.Fatalf("capability matrix artifact is mandatory (dispatch E04-P01-W01-C02): %v", err)
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
			if row[1] != "да" {
				t.Fatalf("type %q must be marked supported (да) in this window", ty)
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
				t.Fatalf("type %q row must cite its exact C01 boundary subtest %q, got %q", ty, subtest, row[5])
			}
		})
	}

	// Cross-cutting rows must reference real C01 battery names (no dangling
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
			t.Errorf("%s: %s (battery missing from the artifact)", tc.battery, tc.note)
		}
	}
	if !strings.Contains(doc, "DetectType его НЕ возвращает") {
		t.Errorf("the form row must disclose that DetectType never returns form (caller-declared only)")
	}
}

// matrixRows extracts the pipe-table data rows (cells trimmed) from the
// artifact's «Матрица» section: the first table in the document.
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
		if cells[0] == "Тип" || strings.HasPrefix(cells[0], "-") {
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
