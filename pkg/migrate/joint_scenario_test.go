package migrate

import (
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

// Structural (static) arm of the packet's joint scenario. Without a database
// it pins the anchors the live joint scenario walks — the head version, the
// cohort stamp pair, the downgrade target and its below-target survivor, and
// the probe table's create/reverse pair — so a head move or a probe-table
// rename fails HERE first, before any container is booted. The live arm
// (joint_scenario_integration_test.go, //go:build integration) runs the same
// chain on real pgvector stands; the two arms live in separate files so real
// and structural checks stay explicitly distinguished, and this file can
// never stand in for the live one.

// jointScenarioWalk is the exact version walk of the live joint scenario:
// fresh install (empty DB) and the stamp-1 cohort (baseline stamp) both
// converge to the head, the downgrade target and the below-target survivor
// are pinned by version, and the probe row lives in a table whose up creates
// it and whose down is the structural reverse.
type jointScenarioWalk struct {
	headVersion      int    // the embedded head both stories converge to
	cohortStamp      int    // the baseline version the stamp-1 cohort stands at before upgrading
	downTarget       int    // the intermediate downgrade target
	belowTargetVer   int    // version at or below the target whose object must survive the downgrade
	belowTargetTable string // that survivor object's table
	probeTable       string // the table the live scenario seeds its probe row into
	probeCreateVer   int    // version whose up creates the probe table
	probeDropVer     int    // version whose down drops it (the structural reverse)
}

var jointScenario = jointScenarioWalk{
	headVersion:      27, // 0027_security_inbox (E06-P01 W01-C02); 0023 is the reserved gap (0022 present via e02p01a, 0024 present via e03p01b, 0025 present via e04p01a)
	cohortStamp:      1,
	downTarget:       12,
	belowTargetVer:   12,
	belowTargetTable: "sso_group_role_rules",
	probeTable:       "guard_pack_state",
	probeCreateVer:   13,
	probeDropVer:     13,
}

// jointCreateTableRe matches a CREATE TABLE statement (optionally
// schema-qualified) over comment-stripped SQL; only the table name is
// captured.
var jointCreateTableRe = regexp.MustCompile(`(?m)^\s*CREATE TABLE\s+(?:IF NOT EXISTS\s+)?(?:public\.)?([a-z_]+)`)

// jointDropTableRe matches a DROP TABLE statement's target over
// comment-stripped SQL.
var jointDropTableRe = regexp.MustCompile(`(?mi)\bDROP TABLE\s+(?:IF EXISTS\s+)?(?:public\.)?([a-z_]+)`)

// jointTableNames returns the distinct table names matched by re in
// comment-stripped SQL, in first-occurrence order.
func jointTableNames(re *regexp.Regexp, strippedSQL string) []string {
	var names []string
	for _, m := range re.FindAllStringSubmatch(strippedSQL, -1) {
		if !slices.Contains(names, m[1]) {
			names = append(names, m[1])
		}
	}
	return names
}

// jointEmbeddedSQL returns the comment-stripped body of the embedded
// migration file for a version and direction.
func jointEmbeddedSQL(t *testing.T, ver int, direction, stem string) string {
	t.Helper()
	name := fmt.Sprintf("%04d_%s.%s.sql", ver, stem, direction)
	data, err := migrationsFS.ReadFile("migrations/" + name)
	if err != nil {
		t.Fatalf("embedded migration %s must be readable: %v", name, err)
	}
	return stripSQLLineComments(string(data))
}

// TestJointScenarioAnchorsPresent pins the embedded-set anchors the live
// joint scenario depends on. When the head moves or a probe object is
// renamed, this fails with the re-pin instruction in the same change that
// grows the set (same posture as the README head pin and the live tests'
// runtime version pins).
func TestJointScenarioAnchorsPresent(t *testing.T) {
	scan := scanEmbeddedNumbering(t)
	if len(scan.violations) > 0 {
		t.Fatalf("embedded migration numbering violations: %v", scan.violations)
	}

	// Head pin: the embedded head is exactly the version the live scenario
	// converges to, and nothing stands above it.
	head := fmt.Sprintf("%04d", jointScenario.headVersion)
	if len(scan.versions) == 0 || scan.versions[len(scan.versions)-1] != head {
		t.Fatalf("embedded head moved: joint scenario pins head %s, embedded set tops out at %v — "+
			"re-pin jointScenario (head, down target, probe versions) in the same change that grows the set",
			head, scan.versions)
	}

	// Cohort stamp: the baseline pair the live scenario applies through the
	// subset source must exist with both directions.
	stampStem := scan.stems[fmt.Sprintf("%04d", jointScenario.cohortStamp)]
	if stampStem == "" {
		t.Fatalf("cohort stamp version %04d missing from the embedded set", jointScenario.cohortStamp)
	}
	for _, dir := range []string{"up", "down"} {
		if _, err := fs.ReadFile(migrationsFS,
			"migrations/"+fmt.Sprintf("%04d_%s.%s.sql", jointScenario.cohortStamp, stampStem, dir)); err != nil {
			t.Fatalf("cohort stamp pair must exist in both directions: %v", err)
		}
	}

	// Downgrade target: landable (its up exists) and the below-target
	// survivor object is created exactly there, so the live scenario's
	// "reverting stops at the target" assertion has an anchor.
	target := fmt.Sprintf("%04d", jointScenario.downTarget)
	targetStem := scan.stems[target]
	if targetStem == "" {
		t.Fatalf("downgrade target version %s missing from the embedded set", target)
	}
	survivorVer := fmt.Sprintf("%04d", jointScenario.belowTargetVer)
	survivorUp := jointEmbeddedSQL(t, jointScenario.belowTargetVer, "up", scan.stems[survivorVer])
	if !slices.Contains(jointTableNames(jointCreateTableRe, survivorUp), jointScenario.belowTargetTable) {
		t.Fatalf("below-target survivor table %s is not created by version %s — "+
			"re-pin the joint scenario's below-target survivor", jointScenario.belowTargetTable, survivorVer)
	}

	// Probe pair: exactly one version creates the probe table, exactly one
	// down drops it, and they are the same version — the live scenario's
	// deleted-data claim needs a table with an honest structural reverse.
	var creators, droppers []int
	for _, ver := range scan.versions {
		n, err := strconv.Atoi(ver)
		if err != nil {
			t.Fatalf("embedded version %s is not numeric: %v", ver, err)
		}
		upSQL := jointEmbeddedSQL(t, n, "up", scan.stems[ver])
		if slices.Contains(jointTableNames(jointCreateTableRe, upSQL), jointScenario.probeTable) {
			creators = append(creators, n)
		}
		downSQL := jointEmbeddedSQL(t, n, "down", scan.stems[ver])
		if slices.Contains(jointTableNames(jointDropTableRe, downSQL), jointScenario.probeTable) {
			droppers = append(droppers, n)
		}
	}
	if !slices.Equal(creators, []int{jointScenario.probeCreateVer}) {
		t.Fatalf("probe table %s must be created by exactly version %d, got creators %v — "+
			"re-pin the joint scenario's probe pair", jointScenario.probeTable, jointScenario.probeCreateVer, creators)
	}
	if !slices.Equal(droppers, []int{jointScenario.probeDropVer}) {
		t.Fatalf("probe table %s must be dropped by exactly version %d's down (the structural reverse), got droppers %v — "+
			"the live scenario's deleted-data claim has no anchor without it",
			jointScenario.probeTable, jointScenario.probeDropVer, droppers)
	}
}

// TestJointScenarioAnchorParserCatchesMutations is the sensitivity arm: the
// anchor extraction must be able to fail. Mutated fixtures — a probe table
// with no creator, a down without the structural reverse, a renamed probe
// table — each yield no (or a wrong) match, so an empty or vacuous anchor
// match can never pass silently.
func TestJointScenarioAnchorParserCatchesMutations(t *testing.T) {
	upWithProbe := "CREATE TABLE guard_pack_state (id integer PRIMARY KEY);\n"
	upRenamed := "CREATE TABLE other_thing (id integer PRIMARY KEY);\n"
	downWithDrop := "DROP TABLE IF EXISTS guard_pack_state;\n"
	downWithoutDrop := "-- structure-only reverse of another object\nDROP INDEX idx_other;\n"

	if got := jointTableNames(jointCreateTableRe, stripSQLLineComments(upWithProbe)); !slices.Equal(got, []string{"guard_pack_state"}) {
		t.Fatalf("parser must find the probe creator in a real up fixture, got %v", got)
	}
	if got := jointTableNames(jointCreateTableRe, stripSQLLineComments(upRenamed)); slices.Contains(got, "guard_pack_state") {
		t.Fatalf("a renamed probe table must yield no creator under the pinned name (sensitivity proof), got %v", got)
	}
	if got := jointTableNames(jointDropTableRe, stripSQLLineComments(downWithDrop)); !slices.Equal(got, []string{"guard_pack_state"}) {
		t.Fatalf("parser must find the structural reverse in a real down fixture, got %v", got)
	}
	if got := jointTableNames(jointDropTableRe, stripSQLLineComments(downWithoutDrop)); len(got) != 0 {
		t.Fatalf("a down without the reverse must yield no dropper (sensitivity proof), got %v", got)
	}
}
