package sovereign

// N09-P01-T09 [compatibility] — old/new configuration walk for pkg/sovereign.
//
// The walk proves the egress rollout and rollback are transparent by driving
// the real decode/consumer pair (json.Unmarshal → Policy.Allows /
// CheckEgress) over the historical and current wire shapes:
//
//	legacy cache JSON   pre-egress payload (capitalized Go field names,
//	                    the no-tag marshaling of the era) → Egress=nil and
//	                    byte-identical re-marshal (no egress key leaks)
//	modern cache JSON   egress map with per-kind profiles → full matrix,
//	                    org-wide rules still composing on top
//	legacy DB row       4-column org_sovereignty_policy row through the real
//	                    PolicyStore with an unreachable cache (the T08
//	                    dead-redis pattern) → same decisions
//	documented tolerance unknown tier names fail open for non-CN models
//	                    (Rank normalization), CN and exclusions still hold
//	closed egress set   unknown kind keys decode but every standard caller
//	                    gates kinds through Valid() — pinned at this layer
//
// Existing coverage intentionally not duplicated: the CheckEgress matrix and
// closed-set probes (egress_test.go), denial-order rules (T07), outage
// fail-open/recovery (T08).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// t09LegacyPolicyJSON is the pre-egress cache payload: the fields Policy
// marshaled before Egress existed (no json tags → Go field names).
const t09LegacyPolicyJSON = `{"RequiredTier":"full","ExcludedCountries":["RU"],"BuyerJurisdiction":"DE","CNAllowed":false}`

// t09Model builds a ModelMeta for the walk.
func t09Model(name, country, tier string, cn bool) ModelMeta {
	return ModelMeta{ModelName: name, Country: country, Jurisdiction: country, Tier: Tier(tier), CNFlagged: cn}
}

// TestN09P1T09_Compat_LegacyPolicyJSONWithoutEgressDecodesTransparently pins
// rollback transparency: a cache payload written before the egress field
// decodes to Egress=nil, behaves identically to the historical build, and
// re-marshals byte-equivalently — a rollback/re-upgrade cycle writes nothing
// a pre-egress reader cannot parse.
func TestN09P1T09_Compat_LegacyPolicyJSONWithoutEgressDecodesTransparently(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(t09LegacyPolicyJSON), &p); err != nil {
		t.Fatalf("legacy cache JSON must decode: %v", err)
	}
	if p.Egress != nil {
		t.Fatalf("legacy payload must decode with Egress=nil, got %v", p.Egress)
	}
	if p.RequiredTier != TierFull || p.BuyerJurisdiction != "DE" || p.CNAllowed {
		t.Fatalf("legacy fields decoded wrong: %+v", p)
	}

	// Historical behavior is preserved end to end.
	if !p.Allows(t09Model("eu-claude", "DE", "full", false)) {
		t.Fatal("legacy policy must admit the same-jurisdiction full model")
	}
	if p.Allows(t09Model("cn-model", "CN", "full", true)) {
		t.Fatal("legacy CN-off default must hold after decode")
	}
	if p.Allows(t09Model("ru-model", "RU", "full", false)) {
		t.Fatal("legacy org-wide exclusion must hold after decode")
	}
	if ok, reason := p.CheckEgress(EgressLogs, "US"); !ok || reason != "" {
		t.Fatalf("legacy policy without per-kind rules must allow logs to US, got ok=%v reason=%q", ok, reason)
	}

	// Re-marshal is byte-equivalent to the legacy shape (egress omitted).
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	if strings.Contains(string(raw), "egress") {
		t.Fatalf("round-trip must not introduce an egress key for legacy data, got %s", raw)
	}
	var again Policy
	if err := json.Unmarshal(raw, &again); err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if !again.Allows(t09Model("eu-claude", "DE", "full", false)) || again.Allows(t09Model("ru-model", "RU", "full", false)) {
		t.Fatal("round-trip changed the policy behavior")
	}
}

// TestN09P1T09_Compat_ModernPolicyJSONWithEgressValidated walks the modern
// wire shape — an egress map with per-kind profiles — through the same
// decode/consumer pair: per-kind rules apply, org-wide exclusions still win
// on kinds without profiles, and an unknown kind key can only ever matter to
// a caller that skips the closed-set Valid() gate.
func TestN09P1T09_Compat_ModernPolicyJSONWithEgressValidated(t *testing.T) {
	modern := `{"RequiredTier":"full","ExcludedCountries":["RU"],
		"Egress":{
			"inference":{"AllowedCountries":["DE"]},
			"logs":{"ExcludedCountries":["RU"]}
		}}`
	var p Policy
	if err := json.Unmarshal([]byte(modern), &p); err != nil {
		t.Fatalf("modern cache JSON must decode: %v", err)
	}
	if len(p.Egress) != 2 {
		t.Fatalf("egress map: got %d profiles, want 2", len(p.Egress))
	}

	if ok, reason := p.CheckEgress(EgressInference, "DE"); !ok {
		t.Fatalf("inference to DE must be allowed by the allowlist, denied reason=%q", reason)
	}
	if ok, reason := p.CheckEgress(EgressInference, "US"); ok || reason != DenialKindNotAllowed {
		t.Fatalf("inference to US must be kind_not_allowed, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := p.CheckEgress(EgressLogs, "RU"); ok || reason != DenialKindExcluded {
		t.Fatalf("logs to RU must be kind_excluded, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := p.CheckEgress(EgressExport, "US"); !ok || reason != "" {
		t.Fatalf("export to US has no profile — org-wide only, got ok=%v reason=%q", ok, reason)
	}
	// Org-wide exclusion composes on top, case-insensitively.
	if ok, reason := p.CheckEgress(EgressExport, "ru"); ok || reason != DenialOrgExcluded {
		t.Fatalf("export to RU must be org_excluded, got ok=%v reason=%q", ok, reason)
	}
	if !p.Allows(t09Model("eu-claude", "DE", "full", false)) || p.Allows(t09Model("ru-model", "RU", "full", false)) {
		t.Fatal("modern payload must preserve the org-wide model rules")
	}

	// The closed set is the caller-side gate: an unknown kind key decodes
	// (forward compatibility with newer writers) but reports invalid here.
	var future Policy
	futureJSON := `{"Egress":{"teleport":{"AllowedCountries":["DE"]}}}`
	if err := json.Unmarshal([]byte(futureJSON), &future); err != nil {
		t.Fatalf("unknown kind key must still decode: %v", err)
	}
	if EgressKind("teleport").Valid() {
		t.Fatal("unknown kind must not report valid")
	}
}

// TestN09P1T09_Compat_LegacyDBRowDrivesStoreWithDeadCache walks the
// historical persistence shape — the 4-column org_sovereignty_policy row —
// through the real PolicyStore with an unreachable cache (the T08
// dead-redis pattern): the store falls back to Postgres and the decoded
// policy keeps the exact legacy behavior.
func TestN09P1T09_Compat_LegacyDBRowDrivesStoreWithDeadCache(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	pg := &t08PgQueryer{row: &t08PgRow{reqTier: "full", excl: []string{"RU"}, buyer: "DE", cn: false}}

	store := NewPolicyStore(rdb, pg)
	p := store.Get(context.Background(), "org-legacy")

	if p.RequiredTier != TierFull || len(p.ExcludedCountries) != 1 || p.Egress != nil {
		t.Fatalf("legacy DB row decoded wrong: %+v", p)
	}
	if !p.Allows(t09Model("eu-claude", "DE", "full", false)) {
		t.Fatal("legacy DB row must admit the same-jurisdiction full model")
	}
	if p.Allows(t09Model("cn-model", "CN", "full", true)) {
		t.Fatal("legacy DB row must keep the CN-off default")
	}
	if ok, reason := p.CheckEgress(EgressExport, "RU"); ok || reason != DenialOrgExcluded {
		t.Fatalf("legacy DB row must enforce org-wide exclusions, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := p.CheckEgress(EgressInference, "US"); !ok {
		t.Fatal("legacy DB row has no per-kind rules — inference to US must pass")
	}

	// A corrupt cache payload is exactly what drives the same DB fall-back:
	// the decode gate rejects it before any policy is served from cache.
	if err := json.Unmarshal([]byte("not-json{{"), &Policy{}); err == nil {
		t.Fatal("malformed cache JSON must fail the decode gate that routes Get to the DB")
	}
}

// TestN09P1T09_Compat_UnknownTierNameFailsOpenForNonCNModels pins the
// documented normalization tolerance: an unsupported required_tier value
// (legacy or typoed admin input) ranks as zero, so it never blocks a non-CN
// model — while the CN guard and org-wide exclusions stay fully enforced.
// The walk goes through the real store with the unsupported row.
func TestN09P1T09_Compat_UnknownTierNameFailsOpenForNonCNModels(t *testing.T) {
	if Rank(Tier("bogus")) != 0 {
		t.Fatalf("unknown tier rank: got %d, want 0 (fail-open normalization)", Rank(Tier("bogus")))
	}

	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	pg := &t08PgQueryer{row: &t08PgRow{reqTier: "bogus", excl: []string{"RU"}, buyer: "DE", cn: false}}

	p := NewPolicyStore(rdb, pg).Get(context.Background(), "org-typo")
	if p.RequiredTier != Tier("bogus") {
		t.Fatalf("unsupported tier must pass through unrewritten, got %q", p.RequiredTier)
	}

	for _, tier := range []string{"foreign", "partial", "open_weights", "full"} {
		if !p.Allows(t09Model("m-"+tier, "US", tier, false)) {
			t.Fatalf("unsupported required_tier blocked a %s model — fail-open violated", tier)
		}
	}
	if p.Allows(t09Model("cn-model", "CN", "full", true)) {
		t.Fatal("tier normalization must never bypass the CN guard")
	}
	if p.Allows(t09Model("ru-model", "RU", "full", false)) {
		t.Fatal("tier normalization must never bypass org-wide exclusions")
	}
}
