package inbox

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// E06-P01 W02-C01: the group-key collision battery. Every law from
// groupkey.go's documentation is pinned here: same finding ⇒ same key;
// different finding ⇒ different key; raw content never enters; the key
// carries no org (isolation is the store's (org_id, group_key) row + RLS).

var gkHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

func gkEvent(eventType, agent, session, summary string) secevents.Event {
	e := secevents.Event{}
	e.SchemaVersion = secevents.SchemaVersion
	e.EventID = "evt-" + uuid.NewString()
	e.EventType = eventType
	e.OrgID = uuid.NewString()
	e.OccurredAt = time.Date(2026, 11, 7, 8, 30, 0, 0, time.UTC)
	if agent != "" {
		e.Identity.Agent = secevents.IDRef{Value: agent, State: secevents.IDKnown}
	}
	if session != "" {
		e.Identity.Session = secevents.IDRef{Value: session, State: secevents.IDKnown}
	}
	e.Summary = summary
	return e
}

func gkKey(t *testing.T, e secevents.Event) string {
	t.Helper()
	k, err := GroupKey(e)
	if err != nil {
		t.Fatalf("GroupKey: %v", err)
	}
	return k
}

func TestGroupKeyDeterministicForSameFinding(t *testing.T) {
	a := gkEvent("tool.deny", "agent-7", "sess-42", "denied rm -rf")
	b := a // struct copy, identical finding
	if gkKey(t, a) != gkKey(t, b) {
		t.Fatal("identical findings must produce the same key")
	}
}

func TestGroupKeyRawContentNeverEnters(t *testing.T) {
	base := gkEvent("tool.deny", "agent-7", "sess-42", "summary A")
	key := gkKey(t, base)

	// Summary is raw text — a secret inside it must not change the key and
	// must not be derivable from the key.
	withSecret := base
	withSecret.Summary = "leaked super-secret-token-abc123 in the summary"
	if gkKey(t, withSecret) != key {
		t.Fatal("summary text must not change the group key (privacy law)")
	}
	if strings.Contains(gkKey(t, withSecret), "secret") {
		t.Fatal("key must not carry raw summary content")
	}

	// Evidence digests reference content; they are content-adjacent metadata
	// and must not split findings either.
	withEvidence := base
	withEvidence.Evidence = []secevents.EvidenceRef{
		{Kind: secevents.EvidencePayloadDigest, Digest: strings.Repeat("d", 64)},
	}
	if gkKey(t, withEvidence) != key {
		t.Fatal("evidence must not change the group key")
	}

	// Delivery facts (event id, timestamp, org) are not finding identity:
	// redelivery re-keys identically; org isolation is the store's law.
	redelivered := base
	redelivered.EventID = "evt-redelivered"
	redelivered.OccurredAt = time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	if gkKey(t, redelivered) != key {
		t.Fatal("event id / occurred_at must not change the group key")
	}

	otherOrg := base
	otherOrg.OrgID = uuid.NewString()
	if gkKey(t, otherOrg) != key {
		t.Fatal("org id must not change the group key — isolation is (org_id, group_key) + RLS, not the key")
	}
}

func TestGroupKeySplitsDifferentFindings(t *testing.T) {
	base := gkEvent("tool.deny", "agent-7", "sess-42", "s")

	// Different category (event type).
	otherType := base
	otherType.EventType = "tool.allow"
	if gkKey(t, otherType) == gkKey(t, base) {
		t.Fatal("different event types must not share a key")
	}

	// Different resource: another agent.
	otherAgent := base
	otherAgent.Identity.Agent = secevents.IDRef{Value: "agent-8", State: secevents.IDKnown}
	if gkKey(t, otherAgent) == gkKey(t, base) {
		t.Fatal("findings about different agents must not share a key")
	}

	// Different resource: an extra session ref widens the tuple.
	wider := base
	wider.Identity.Task = secevents.IDRef{Value: "task-9", State: secevents.IDKnown}
	if gkKey(t, wider) == gkKey(t, base) {
		t.Fatal("a wider resource tuple must not share the key")
	}
}

func TestGroupKeyResourceOrderIsFixed(t *testing.T) {
	// The tuple order comes from the law (agent, session, task, tool), not
	// from construction order: both events describe the same resource.
	a := gkEvent("tool.deny", "agent-7", "sess-42", "s")
	b := gkEvent("tool.deny", "agent-7", "sess-42", "s") // same shape, fresh ids
	if gkKey(t, a) != gkKey(t, b) {
		t.Fatal("same resource set must key identically regardless of construction")
	}
	if ResourceDigest(a) != ResourceDigest(b) {
		t.Fatal("ResourceDigest must be pure")
	}

	// Empty identity is a valid finding without a resource: deterministic,
	// and distinct from any named resource.
	noResource := gkEvent("org.anomaly", "", "", "s")
	d := ResourceDigest(noResource)
	if !gkHex64.MatchString(d) {
		t.Fatalf("empty-resource digest = %q, want 64 hex chars", d)
	}
	if d == ResourceDigest(a) {
		t.Fatal("empty resource must differ from a named resource")
	}
	if gkKey(t, noResource) == gkKey(t, a) {
		t.Fatal("resource-less finding must not collide with a named one (categories differ too)")
	}
}

func TestGroupKeyFormulaPinned(t *testing.T) {
	// Golden pin of the formula itself — the law cannot drift (a formula
	// change must bump GroupKeyVersion and consciously break this test).
	e := gkEvent("tool.deny", "agent-7", "sess-42", "s")
	got := gkKey(t, e)

	resource := ResourceDigest(e)
	resourceSum := sha256.Sum256([]byte("agent=agent-7\x1fsession=sess-42"))
	if resource != hex.EncodeToString(resourceSum[:]) {
		t.Fatalf("ResourceDigest = %s, want sha256 of the fixed tuple", resource)
	}
	parts := strings.Join([]string{GroupKeyVersion, "tool.deny", SeverityLow, resource}, "|")
	want := sha256.Sum256([]byte(parts))
	if got != hex.EncodeToString(want[:]) {
		t.Fatalf("GroupKey = %s, want sha256(%q) = %s", got, parts, hex.EncodeToString(want[:]))
	}
	if !gkHex64.MatchString(got) {
		t.Fatalf("key %q is not 64 lowercase hex chars", got)
	}
}

func TestGroupKeyEmptyCategoryRefused(t *testing.T) {
	e := gkEvent("", "agent-7", "", "s")
	if _, err := GroupKey(e); err == nil {
		t.Fatal("empty event type must be refused, not keyed")
	}
}
