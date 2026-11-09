package cache

// N03-P04 review follow-up: the similarity-admission stamp must describe the
// rule that actually admitted an entry. The package-level
// SemanticAdmissionVersion() names the PACKAGE DEFAULTS (0.95 / 100); a
// SemanticCache built with explicit non-default parameters stamps its own
// constructor-resolved rule, so cross-rule semantic lookups degrade to
// self-healing misses (SpaceMatch strict equality) instead of serving
// entries admitted under another regime. For the production defaults the
// instance stamp is byte-identical to the package stamp — entries written
// before per-instance stamps existed stay compatible.

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Production defaults: NewSemanticCache(pool, 0, 0) resolves (0.95, 100) and
// must stamp EXACTLY the package stamp — byte-identical output keeps the
// accepted T02 writer stamps and SpaceMatch compatibility intact.
func TestSemanticAdmissionVersion_DefaultsMatchPackageStamp(t *testing.T) {
	assert.Equal(t, "sem1:0.9500:cosine:100", SemanticAdmissionVersion())

	sc := NewSemanticCache(nil, 0, 0)
	assert.Equal(t, SemanticAdmissionVersion(), sc.AdmissionVersion(),
		"default construction must stamp the same rule as the package stamp")

	// Explicitly passing the defaults resolves to the same stamp.
	assert.Equal(t, sc.AdmissionVersion(), NewSemanticCache(nil, 0.95, 100).AdmissionVersion())
}

// A non-default rule stamps differently, and strict SpaceMatch degrades
// cross-rule entries to misses in BOTH directions — an entry admitted under
// one regime is never served by a lookup running another.
func TestSemanticAdmissionVersion_NonDefaultRuleStampsAndMisses(t *testing.T) {
	strict := NewSemanticCache(nil, 0.90, 50)
	v := strict.AdmissionVersion()
	assert.Equal(t, "sem1:0.9000:cosine:50", v)
	assert.NotEqual(t, SemanticAdmissionVersion(), v)

	// The stamp flows through the seal/open envelope unchanged.
	sealed, err := SealEntryVersioned(json.RawMessage(`{"id":"cmpl-1"}`),
		RouteIdentity{OrgID: "org-1", Model: "gpt-4o"}, "emb1:a", v)
	require.NoError(t, err)
	prov, _, ok := OpenEntry(sealed)
	require.True(t, ok)
	assert.Equal(t, v, prov.ThresholdVer)

	// Cross-rule lookups miss in both directions; same-rule still matches.
	entryDefault := Provenance{EmbedVer: "emb1:a", ThresholdVer: SemanticAdmissionVersion()}
	entryStrict := Provenance{EmbedVer: "emb1:a", ThresholdVer: v}
	assert.False(t, entryDefault.SpaceMatch("emb1:a", v),
		"default-rule entry must miss under the non-default rule")
	assert.False(t, entryStrict.SpaceMatch("emb1:a", SemanticAdmissionVersion()),
		"non-default-rule entry must miss under the default rule")
	assert.True(t, entryStrict.SpaceMatch("emb1:a", v),
		"same-rule lookup still matches")
}

// Honesty edge cases: a nil cache falls back to the package stamp (no rule
// of its own to derive), while a zero-value cache stamps the rule its
// fields actually express instead of pretending to run the defaults.
func TestSemanticAdmissionVersion_NilAndZeroValueCache(t *testing.T) {
	var nilCache *SemanticCache
	assert.Equal(t, SemanticAdmissionVersion(), nilCache.AdmissionVersion())

	assert.Equal(t, "sem1:0.0000:cosine:0", (&SemanticCache{}).AdmissionVersion(),
		"zero-value cache must stamp its actual fields, not the package defaults")
}
