package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// N10-P01-T03: the mirror+numbering contract recorded in
// migrations/README.md (N10-P01-T02) as always-on checks. The byte-level
// mirror sync itself is TestEmbeddedMigrationsInSyncWithRoot; version
// uniqueness and up/down pairing are covered by
// TestEmbeddedMigrationsHaveUniqueVersions, TestMigrations_NoDuplicateVersions
// and TestMigrations_PairedUpDown. This file enforces the remaining halves of
// the contract that had no guard:
//
//  1. numbering is contiguous 4-digit 0001..head (the README's "next free
//     number is head+1" discipline presupposes an unbroken sequence) with
//     the documented exception of reservedGaps — version slots deliberately
//     left file-free so later migrations can occupy stable numbers without
//     renumbering already-shipped files;
//  2. the up and down files of one version share the same NNNN_name stem;
//  3. the numbering claims pinned in migrations/README.md (head version and
//     name, next free number) match the actual embedded set, so the
//     documented contract cannot drift when the next migration lands.

// migrationFileNameRe is the strict README format: 4-digit zero-padded
// version, lowercase stem, one up and one down file per version. The audit
// test's (\d+) regex is deliberately looser (it must also describe
// pre-NNNN history); this contract test holds the shipped set to the
// documented NNNN_name shape.
var migrationFileNameRe = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.(up|down)\.sql$`)

// numberingScan is the numbering state of the embedded migration set.
type numberingScan struct {
	versions   []string          // sorted unique 4-digit versions
	stems      map[string]string // version -> shared up/down stem
	violations []string          // structural numbering violations
}

// scanEmbeddedNumbering walks the embedded migrations and collects versions
// and stems, flagging every deviation from the documented pair format: a file
// outside NNNN_name.(up|down).sql, a version with only one direction, or a
// version whose up and down stems differ.
func scanEmbeddedNumbering(t *testing.T) numberingScan {
	t.Helper()
	upStems := map[string]string{}
	downStems := map[string]string{}
	seen := map[string]bool{}
	var scan numberingScan

	err := fs.WalkDir(migrationsFS, "migrations", func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		m := migrationFileNameRe.FindStringSubmatch(d.Name())
		if m == nil {
			scan.violations = append(scan.violations,
				"file does not match NNNN_name.(up|down).sql: "+d.Name())
			return nil
		}
		ver, stem, dir := m[1], m[2], m[3]
		if !seen[ver] {
			seen[ver] = true
			scan.versions = append(scan.versions, ver)
		}
		bucket := upStems
		if dir == "down" {
			bucket = downStems
		}
		if prev, ok := bucket[ver]; ok && prev != stem {
			scan.violations = append(scan.violations, fmt.Sprintf(
				"version %s has two different %s stems: %s and %s", ver, dir, prev, stem))
		} else {
			bucket[ver] = stem
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk embedded migrations: %v", err)
	}

	sort.Strings(scan.versions)
	scan.stems = map[string]string{}
	for _, ver := range scan.versions {
		up, down := upStems[ver], downStems[ver]
		switch {
		case up == "":
			scan.violations = append(scan.violations, "version "+ver+" has no up migration")
		case down == "":
			scan.violations = append(scan.violations, "version "+ver+" has no down migration")
		case up != down:
			scan.violations = append(scan.violations, fmt.Sprintf(
				"version %s stems differ: up %s vs down %s", ver, up, down))
		default:
			scan.stems[ver] = up
		}
	}
	return scan
}

// reservedGaps holds version slots deliberately absent from the embedded set
// because a parallel delivery in the same fleet window claimed them first.
// History: 0018_approval_operations forced the 0018→0019 renumbering and
// 0020_mcp_grant_actions took 0020 against both pending heads; 0019 closed
// that era and the reservation list drained at 0001..0021.
//
// Window through head 0027: slot 0023 alone is claimed outside this
// tree's embedded set —
//   - 0023: permanently reserved unused (convergence rule: no delivery
//     may take it).
//
// 0022 is present in the embedded set (inventory assets); its former
// reservation was deleted when the migration entered this tree, per the
// rule below. The same holds for 0025 (data classification taxonomies,
// present via e04p01a) and 0024 (fleet registry, E03-P01, present via
// e03p01b): present in the embedded set, former reservations deleted
// on entry.
//
// When a reserved migration promotes into this tree, delete its entry here
// in the same change (an entry whose version IS present would mask nothing —
// the contiguity walk only consults reservedGaps for absent slots — but a
// stale entry after promotion is dead prose).
// The exception mechanism stays as the tripwire: a version absent from
// the embedded set WITHOUT a reservation here still fails the contiguity
// check — the exception is fixed in code, never assumed silently.
var reservedGaps = map[string]string{
	"0023": "permanently reserved unused (ebetaplan3b review2 convergence rule); no delivery may claim 0023",
}

// TestMigrationNumberingContiguousFrom0001 — the numbering discipline the
// README pins: one unbroken 0001..head sequence, so "next free = head+1" is
// unambiguous and the shared set applied by fresh install and the stamp-1
// upgrade cohort is the same 0002..head range in both stories.
func TestMigrationNumberingContiguousFrom0001(t *testing.T) {
	scan := scanEmbeddedNumbering(t)
	if len(scan.violations) > 0 {
		t.Fatalf("embedded migration numbering violations: %v", scan.violations)
	}
	if len(scan.versions) == 0 {
		t.Fatal("no migrations found in embedded set")
	}
	next := 1
	for _, ver := range scan.versions {
		n, err := strconv.Atoi(ver)
		if err != nil {
			t.Fatalf("non-numeric version %q in embedded set", ver)
		}
		for next < n {
			want := fmt.Sprintf("%04d", next)
			if _, reserved := reservedGaps[want]; !reserved {
				t.Fatalf("numbering gap or wrong base: %s is absent before %s (full sequence %v)",
					want, ver, scan.versions)
			}
			next++
		}
		if n != next {
			t.Fatalf("numbering wrong base: %s is out of sequence, expected %s (full sequence %v)",
				ver, fmt.Sprintf("%04d", next), scan.versions)
		}
		next++
	}
}

// numberingContract is what migrations/README.md pins about the numbering:
// the embedded head version and its name, and the next free number.
type numberingContract struct {
	headVersion string
	headName    string
	nextFree    string
}

// The two English README anchors state the numbering contract:
//
//   - Next available migration number: **0016**. …
//   - Current embedded head: **0015** (`delegation_ttl_bound`, …)
var readmeNextFreeRe = regexp.MustCompile(`Next available migration number: \*\*(\d{4})\*\*`)
var readmeHeadRe = regexp.MustCompile(`Current embedded head: \*\*(\d{4})\*\* \(\x60([a-z0-9_]+)\x60`)

// parseNumberingContract extracts the README numbering claims. An error means
// the README no longer states the contract in the documented shape and must
// be re-anchored together with this test.
func parseNumberingContract(readme string) (numberingContract, error) {
	m := readmeNextFreeRe.FindStringSubmatch(readme)
	if m == nil {
		return numberingContract{}, fmt.Errorf(
			"README does not state the next free number (Next available migration number: **NNNN**)")
	}
	h := readmeHeadRe.FindStringSubmatch(readme)
	if h == nil {
		return numberingContract{}, fmt.Errorf(
			"README does not state the embedded head (Current embedded head: **NNNN** (`name`)")
	}
	return numberingContract{headVersion: h[1], headName: h[2], nextFree: m[1]}, nil
}

// contractMismatches compares README claims against the actual embedded set.
func contractMismatches(c numberingContract, scan numberingScan) []string {
	if len(scan.versions) == 0 {
		return []string{"embedded set is empty"}
	}
	head := scan.versions[len(scan.versions)-1]
	nextOfHead := fmt.Sprintf("%04d", func() int {
		n, _ := strconv.Atoi(head)
		return n + 1
	}())

	var bad []string
	if c.headVersion != head {
		bad = append(bad, fmt.Sprintf("README head version %s, embedded head is %s", c.headVersion, head))
	}
	if got := scan.stems[head]; c.headName != got {
		bad = append(bad, fmt.Sprintf("README head name %q, embedded head %s is %q", c.headName, head, got))
	}
	if c.nextFree != nextOfHead {
		bad = append(bad, fmt.Sprintf("README next free number %s, head+1 is %s", c.nextFree, nextOfHead))
	}
	return bad
}

// TestNumberingContractREADMEMatchesEmbeddedSet — migrations/README.md is the
// contract of record for the mirror+numbering discipline (N10-P01-T02); this
// test keeps its pinned numbering synchronized with the embedded set. When a
// new migration lands, the README claims (head version, head name, next free
// number) must be updated in the same change.
func TestNumberingContractREADMEMatchesEmbeddedSet(t *testing.T) {
	readme, err := fs.ReadFile(migrateRootFS, "README.md")
	if err != nil {
		t.Fatalf("read migrations/README.md: %v", err)
	}
	contract, err := parseNumberingContract(string(readme))
	if err != nil {
		t.Fatalf("migrations/README.md must carry the numbering contract: %v", err)
	}
	scan := scanEmbeddedNumbering(t)
	if bad := contractMismatches(contract, scan); len(bad) > 0 {
		t.Fatalf("migrations/README.md numbering contract out of sync with the embedded set — "+
			"update the README claims together with the migrations: %v", bad)
	}
}

// TestNumberingContractCheckDetectsDrift — sensitivity arm so the README
// cross-check above cannot pass vacuously (same pattern as
// TestBaselineSeedRLSCheck_DistinguishesBrokenFromFixed): a wrong pinned head
// must trip all three claims, and realistic prose with a stale next-free
// number must be parsed and rejected.
func TestNumberingContractCheckDetectsDrift(t *testing.T) {
	scan := scanEmbeddedNumbering(t)
	head := scan.versions[len(scan.versions)-1]

	wrong := numberingContract{headVersion: "0001", headName: "init", nextFree: "0042"}
	bad := contractMismatches(wrong, scan)
	joined := strings.Join(bad, "; ")
	for _, claim := range []string{"head version", "head name", "next free"} {
		if !strings.Contains(joined, claim) {
			t.Fatalf("drift detector must flag the %s claim, got only: %v", claim, bad)
		}
	}

	stale := fmt.Sprintf("- Next available migration number: **0001**.\n"+
		"- Current embedded head: **%s** (`%s`, probe).\n", head, scan.stems[head])
	contract, err := parseNumberingContract(stale)
	if err != nil {
		t.Fatalf("realistic README prose must parse: %v", err)
	}
	bad = contractMismatches(contract, scan)
	if len(bad) != 1 || !strings.Contains(bad[0], "next free") {
		t.Fatalf("a stale next-free claim must be the single flagged mismatch, got: %v", bad)
	}
}
