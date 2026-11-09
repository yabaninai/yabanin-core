package pricing

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// refFixture returns a minimal valid active entry with one token rate.
func refFixture(t *testing.T) Catalog {
	t.Helper()
	amount := 0.5
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "v1",
		GeneratedAt:   "2026-10-01",
		Source:        "test",
		ReviewSLADays: 90,
		Models: []RefModel{{
			Provider:      "openai",
			Model:         "gpt-test",
			Aliases:       []string{"gpt-test-2024"},
			Currency:      "USD",
			EffectiveFrom: "2026-01-01",
			VerifiedAt:    "2026-09-30",
			Status:        RefStatusActive,
			Sources: []RefSource{{
				Kind:       RefSourceURL,
				Ref:        "https://openai.example/pricing",
				VerifiedAt: "2026-09-30",
			}},
			Rates: []RefRate{{
				Axis:   AxisInput,
				Unit:   RefUnitPer1MTokens,
				Amount: &amount,
			}},
		}},
	}
}

func TestValidateCatalogAcceptsFixture(t *testing.T) {
	c := refFixture(t)
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("fixture must validate: %v", err)
	}
}

func TestValidateCatalogHeaderProblems(t *testing.T) {
	tests := []struct {
		name  string
		mutcb func(c *Catalog)
		want  string // substring of the aggregated error
	}{
		{
			name:  "schema version mismatch",
			mutcb: func(c *Catalog) { c.SchemaVersion = 99 },
			want:  "schema_version: must be 1",
		},
		{
			name:  "missing version",
			mutcb: func(c *Catalog) { c.Version = " " },
			want:  "version: catalog version is required",
		},
		{
			name:  "missing source",
			mutcb: func(c *Catalog) { c.Source = "" },
			want:  "source: assembly source is required",
		},
		{
			name:  "bad generated_at",
			mutcb: func(c *Catalog) { c.GeneratedAt = "unknown" },
			want:  "generated_at:",
		},
		{
			name:  "malformed supersedes",
			mutcb: func(c *Catalog) { c.Supersedes = "deadbeef" },
			want:  "supersedes: must be a 64-hex digest",
		},
		{
			name:  "malformed digest",
			mutcb: func(c *Catalog) { c.Digest = "zz" },
			want:  "digest: must be a 64-hex digest",
		},
		{
			name:  "negative review sla",
			mutcb: func(c *Catalog) { c.ReviewSLADays = -1 },
			want:  "review_sla_days: must not be negative",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := refFixture(t)
			tt.mutcb(&c)
			err := ValidateCatalog(c)
			if err == nil {
				t.Fatalf("expected problem containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q must contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateCatalogDigestMustMatchContent(t *testing.T) {
	c := refFixture(t)
	sealed, err := SealCatalog(c)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := ValidateCatalog(sealed); err != nil {
		t.Fatalf("sealed catalog must validate: %v", err)
	}

	// Tampering with content after sealing must break the digest check.
	sealed.Models[0].Model = "gpt-renamed"
	err = ValidateCatalog(sealed)
	if err == nil || !strings.Contains(err.Error(), "digest: does not match content") {
		t.Fatalf("tampered content must fail digest verification, got %v", err)
	}
}

func TestCatalogDigestCanonicalAndContentSensitive(t *testing.T) {
	c := refFixture(t)
	d1, err := CatalogDigest(c)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	// Content sensitivity: adding a second model to the snapshot must
	// change the digest. (Ordering invariance itself is pinned by the
	// fully-permuted same-content subtest below.)
	reordered := refFixture(t)
	reordered.Models[0].Aliases = []string{"gpt-test-2024"} // same content
	first := reordered.Models[0]
	rate := first.Rates[0]
	first.Rates = []RefRate{rate}
	second := RefModel{
		Provider:      "openai",
		Model:         "gpt-other",
		Currency:      "USD",
		EffectiveFrom: "2026-01-01",
		VerifiedAt:    "2026-09-30",
		Status:        RefStatusActive,
		Sources: []RefSource{{
			Kind:       RefSourceURL,
			Ref:        "https://openai.example/other",
			VerifiedAt: "2026-09-30",
		}},
	}
	amount := 1.5
	second.Rates = []RefRate{{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &amount}}
	reordered.Models = []RefModel{second, first} // reverse order
	d2, err := CatalogDigest(reordered)
	if err != nil {
		t.Fatalf("digest reordered: %v", err)
	}
	if d1 == d2 {
		t.Fatal("different content must produce a different digest")
	}

	// Same content with a freshly allocated Amount pointer (same value):
	// the digest keys on values, not pointer identity.
	sameContent := refFixture(t)
	sameContent.Models[0].Rates[0].Amount = new(float64)
	*sameContent.Models[0].Rates[0].Amount = 0.5
	d3, err := CatalogDigest(sameContent)
	if err != nil {
		t.Fatalf("digest same: %v", err)
	}
	if d1 != d3 {
		t.Fatalf("identical content must digest identically: %s vs %s", d1, d3)
	}

	// F1 (ref01-review-20261101): same content, every ordering the
	// canonicalization normalizes permuted — model order, aliases, rate
	// order, per-rate evidence, sources, conflicts — must not move the
	// digest.
	t.Run("same content fully permuted digests equal", func(t *testing.T) {
		base := digestPermutationFixture()
		if err := ValidateCatalog(base); err != nil {
			t.Fatalf("fixture must be a valid catalog: %v", err)
		}
		want, err := CatalogDigest(base)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}

		permuted := digestPermutationFixture()
		gpt := permuted.Models[0]
		out := gpt.Rates[0] // output, carries evidence
		cr := gpt.Rates[2]  // cache_read, carries evidence
		out.Evidence = []RefEvidence{out.Evidence[1], out.Evidence[0]}
		cr.Evidence = []RefEvidence{cr.Evidence[1], cr.Evidence[0]}
		in := 0.5 // fresh Amount pointer: values, not pointer identity
		gpt.Rates = []RefRate{cr, {Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in}, out}
		gpt.Aliases = []string{gpt.Aliases[1], gpt.Aliases[0]}
		gpt.Sources = []RefSource{gpt.Sources[1], gpt.Sources[0]}
		gpt.Conflicts = []RefConflict{gpt.Conflicts[1], gpt.Conflicts[0]}
		permuted.Models = []RefModel{permuted.Models[2], permuted.Models[1], gpt} // models reversed

		got, err := CatalogDigest(permuted)
		if err != nil {
			t.Fatalf("digest permuted: %v", err)
		}
		if got != want {
			t.Fatalf("identical content with permuted slice order must digest identically:\ngot  %s\nwant %s", got, want)
		}
	})
}

// digestPermutationFixture builds a catalog exercising every ordering the
// canonicalization normalizes: three models (so both the provider and the
// model comparator keys are load-bearing), two aliases (unsorted), two
// sources (unsorted), three rates out of canonical axis order, two-element
// per-rate evidence (unsorted) and two resolved conflicts. Every copy
// carries identical content; tests permute slice order and require the
// digest to stay put. The conflicting evidence is resolved exactly as
// §Conflicts requires (amount equals one observed value + a RefConflict).
func digestPermutationFixture() Catalog {
	in, out, altOut, cr, altCr := 0.5, 1.5, 1.55, 0.05, 0.06
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "v1",
		GeneratedAt:   "2026-10-01",
		Source:        "test",
		Models: []RefModel{
			{
				Provider:      "openai",
				Model:         "gpt-test",
				Aliases:       []string{"gpt-alias-b", "gpt-alias-a"}, // unsorted on purpose
				Currency:      "USD",
				EffectiveFrom: "2026-01-01",
				VerifiedAt:    "2026-09-30",
				Status:        RefStatusActive,
				Sources: []RefSource{
					{Kind: RefSourceURL, Ref: "https://openai.example/secondary", VerifiedAt: "2026-09-29"},
					{Kind: RefSourceURL, Ref: "https://openai.example/pricing", VerifiedAt: "2026-09-30"},
				},
				Rates: []RefRate{
					{
						Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: &out,
						Evidence: []RefEvidence{
							{Ref: "https://openai.example/secondary", Amount: altOut, At: "2026-09-28"},
							{Ref: "https://openai.example/pricing", Amount: out, At: "2026-09-30"},
						},
					},
					{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in},
					{
						Axis: AxisCacheRead, Unit: RefUnitPer1MTokens, Amount: &altCr,
						Evidence: []RefEvidence{
							{Ref: "https://openai.example/pricing", Amount: cr, At: "2026-09-29"},
							{Ref: "https://openai.example/secondary", Amount: altCr, At: "2026-09-30"},
						},
					},
				},
				Conflicts: []RefConflict{
					{Axis: AxisOutput, Ref: "https://openai.example/pricing", Reason: "primary provider page outranks the mirror"},
					{Axis: AxisCacheRead, Ref: "https://openai.example/secondary", Reason: "primary page dropped the cache row; mirror confirmed"},
				},
			},
			// Two anthropic drafts so the model sort exercises both the
			// provider and the model comparator keys (deeper scoping
			// tiebreaks — region/tier/band — cannot occur in a valid
			// catalog: ValidateCatalog rejects duplicate (provider, model)
			// identities before they can differ there).
			{Provider: "anthropic", Model: "claude-zulu", Currency: "USD", Status: RefStatusDraft},
			{Provider: "anthropic", Model: "claude-test", Currency: "USD", Status: RefStatusDraft},
		},
	}
}

func TestCatalogDigestExcludesDigestField(t *testing.T) {
	c := refFixture(t)
	d1, err := CatalogDigest(c)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	c.Digest = strings.Repeat("a", 64)
	d2, err := CatalogDigest(c)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	if d1 != d2 {
		t.Fatal("the Digest field itself must be excluded from the digest input")
	}
}

func TestValidateCatalogChain(t *testing.T) {
	first := refFixture(t)
	first.Version = "v1"
	first, err := SealCatalog(first)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	second := refFixture(t)
	second.Version = "v2"
	second.Supersedes = first.Digest
	second.Models[0].Model = "gpt-test-v2"
	if err := ValidateCatalogChain(first, second); err != nil {
		t.Fatalf("valid chain must pass: %v", err)
	}

	t.Run("broken chain", func(t *testing.T) {
		bad := second
		bad.Supersedes = strings.Repeat("f", 64)
		err := ValidateCatalogChain(first, bad)
		if err == nil || !strings.Contains(err.Error(), "but previous snapshot digests to") {
			t.Fatalf("broken chain must fail, got %v", err)
		}
	})

	t.Run("missing supersedes", func(t *testing.T) {
		orphan := second
		orphan.Supersedes = ""
		err := ValidateCatalogChain(first, orphan)
		if err == nil || !strings.Contains(err.Error(), "does not declare a predecessor") {
			t.Fatalf("missing supersedes must fail, got %v", err)
		}
	})
}

func TestValidateCatalogModelProblems(t *testing.T) {
	tests := []struct {
		name  string
		mutcb func(m *RefModel)
		want  string
	}{
		{
			name:  "missing provider",
			mutcb: func(m *RefModel) { m.Provider = "" },
			want:  "provider is required",
		},
		{
			name:  "missing model",
			mutcb: func(m *RefModel) { m.Model = " " },
			want:  "model is required",
		},
		{
			name:  "unknown status",
			mutcb: func(m *RefModel) { m.Status = "live" },
			want:  `status: must be draft, active or retired`,
		},
		{
			name:  "non-USD currency",
			mutcb: func(m *RefModel) { m.Currency = "EUR" },
			want:  "currency: must be USD",
		},
		{
			name:  "active without sources",
			mutcb: func(m *RefModel) { m.Sources = nil },
			want:  "an active entry needs at least one primary source",
		},
		{
			name:  "active without verified_at",
			mutcb: func(m *RefModel) { m.VerifiedAt = "" },
			want:  "an active entry must carry a verification instant",
		},
		{
			name:  "unknown source kind",
			mutcb: func(m *RefModel) { m.Sources[0].Kind = "rumor" },
			want:  "kind: must be",
		},
		{
			name:  "empty source ref",
			mutcb: func(m *RefModel) { m.Sources[0].Ref = " " },
			want:  "source ref is required",
		},
		{
			name: "duplicate source ref",
			mutcb: func(m *RefModel) {
				m.Sources = append(m.Sources, m.Sources[0])
			},
			want: "duplicate source ref",
		},
		{
			name:  "alias shadows model name",
			mutcb: func(m *RefModel) { m.Aliases = []string{"gpt-test"} },
			want:  "shadows the model name",
		},
		{
			name:  "alias with surrounding whitespace",
			mutcb: func(m *RefModel) { m.Aliases = []string{" gpt-alias"} },
			want:  "must not have leading or trailing whitespace",
		},
		{
			name:  "empty alias",
			mutcb: func(m *RefModel) { m.Aliases = []string{"  "} },
			want:  "alias is empty",
		},
		{
			name:  "duplicate alias",
			mutcb: func(m *RefModel) { m.Aliases = []string{"x", "x"} },
			want:  "duplicate alias",
		},
		{
			name:  "window closes before it opens",
			mutcb: func(m *RefModel) { m.EffectiveTo = "2025-01-01" },
			want:  "effective window closes at or before it opens",
		},
		{
			name:  "bad effective_from",
			mutcb: func(m *RefModel) { m.EffectiveFrom = "not-a-date" },
			want:  "effective_from:",
		},
		{
			name:  "bad effective_to",
			mutcb: func(m *RefModel) { m.EffectiveTo = "2026/01/01" },
			want:  "effective_to:",
		},
		{
			name:  "bad verified_at",
			mutcb: func(m *RefModel) { m.VerifiedAt = "soon" },
			want:  "verified_at:",
		},
		{
			name: "conflicting evidence without resolution",
			mutcb: func(m *RefModel) {
				lo, hi := 1.0, 2.0
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: lo, At: "2026-09-30"},
					{Ref: "https://mirror.example/pricing", Amount: hi},
				}
			},
			want: "conflicting evidence on axis \"input\" without a resolution",
		},
		{
			name: "conflict resolution names unobserved amount",
			mutcb: func(m *RefModel) {
				lo, hi, wrong := 1.0, 2.0, 3.0
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: lo},
					{Ref: "https://mirror.example/pricing", Amount: hi},
				}
				m.Rates[0].Amount = &wrong
				m.Conflicts = []RefConflict{{Axis: AxisInput, Ref: m.Sources[0].Ref, Reason: "primary wins"}}
			},
			want: "without a resolution choosing one observed amount",
		},
		{
			name: "conflict resolution names unknown source",
			mutcb: func(m *RefModel) {
				lo, hi := 1.0, 2.0
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: lo},
					{Ref: "https://mirror.example/pricing", Amount: hi},
				}
				m.Rates[0].Amount = &hi
				m.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "https://mirror.example/pricing", Reason: "mirror"}}
			},
			want: "is not one of the entry's sources",
		},
		{
			name: "conflict resolution without reason",
			mutcb: func(m *RefModel) {
				lo, hi := 1.0, 2.0
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: lo},
					{Ref: "https://mirror.example/pricing", Amount: hi},
				}
				m.Rates[0].Amount = &hi
				m.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "https://mirror.example/pricing"}}
			},
			want: "conflict resolution needs a reason",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := refFixture(t)
			tt.mutcb(&c.Models[0])
			err := ValidateCatalog(c)
			if err == nil {
				t.Fatalf("expected problem containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q must contain %q", err, tt.want)
			}
		})
	}
}

func TestValidateCatalogAcceptsResolvedConflict(t *testing.T) {
	c := refFixture(t)
	m := &c.Models[0]
	lo, hi := 1.0, 2.0
	m.Rates[0].Evidence = []RefEvidence{
		{Ref: m.Sources[0].Ref, Amount: lo, At: "2026-09-30"},
		{Ref: "https://mirror.example/pricing", Amount: hi, At: "2026-09-29"},
	}
	m.Rates[0].Amount = &lo // primary source wins
	m.Conflicts = []RefConflict{{
		Axis:   AxisInput,
		Ref:    m.Sources[0].Ref,
		Reason: "primary provider page outranks mirror scrape",
	}}
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("resolved conflict must validate: %v", err)
	}
}

func TestValidateCatalogRateProblems(t *testing.T) {
	tests := []struct {
		name  string
		mutcb func(r *RefRate)
		want  string
	}{
		{
			name:  "unknown axis",
			mutcb: func(r *RefRate) { r.Axis = "gpu_hour" },
			want:  `axis: unknown axis "gpu_hour"`,
		},
		{
			name:  "unit does not match axis",
			mutcb: func(r *RefRate) { r.Unit = UnitPerImage },
			want:  `axis "input" must use unit "per_1m_tokens"`,
		},
		{
			name: "duplicate axis",
			mutcb: func(r *RefRate) {
			},
		},
		{
			name:  "negative amount",
			mutcb: func(r *RefRate) { v := -0.1; r.Amount = &v },
			want:  "negative price",
		},
		{
			name:  "NaN amount",
			mutcb: func(r *RefRate) { v := math.NaN(); r.Amount = &v },
			want:  "not a finite number",
		},
		{
			name:  "negative evidence amount",
			mutcb: func(r *RefRate) { r.Evidence = []RefEvidence{{Ref: "x", Amount: -1}} },
			want:  "negative price",
		},
		{
			name:  "empty evidence ref",
			mutcb: func(r *RefRate) { r.Evidence = []RefEvidence{{Ref: "", Amount: 1}} },
			want:  "evidence ref is required",
		},
		{
			name: "duplicate evidence ref",
			mutcb: func(r *RefRate) {
				r.Evidence = []RefEvidence{{Ref: "x", Amount: 1}, {Ref: "x", Amount: 1}}
			},
			want: "duplicate evidence ref",
		},
		{
			name:  "bad evidence timestamp",
			mutcb: func(r *RefRate) { r.Evidence = []RefEvidence{{Ref: "x", Amount: 1, At: "yesterday"}} },
			want:  "at:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := refFixture(t)
			if tt.name == "duplicate axis" {
				c.Models[0].Rates = []RefRate{
					{Axis: AxisInput, Unit: RefUnitPer1MTokens},
					{Axis: AxisInput, Unit: RefUnitPer1MTokens},
				}
				err := ValidateCatalog(c)
				if err == nil || !strings.Contains(err.Error(), "duplicate rate for axis \"input\"") {
					t.Fatalf("duplicate axis must fail, got %v", err)
				}
				return
			}
			tt.mutcb(&c.Models[0].Rates[0])
			err := ValidateCatalog(c)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected problem containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestValidateCatalogZeroAmountIsLegitimateFree(t *testing.T) {
	c := refFixture(t)
	free := 0.0
	c.Models[0].Rates[0].Amount = &free
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("explicit zero must validate: %v", err)
	}
}

func TestValidateCatalogDraftEntryNeedsNoSources(t *testing.T) {
	c := refFixture(t)
	m := c.Models[0]
	m.Status = RefStatusDraft
	m.Sources = nil
	m.VerifiedAt = ""
	c.Models[0] = m
	if err := ValidateCatalog(c); err != nil {
		t.Fatalf("draft entry without sources/verification must validate: %v", err)
	}
}

func TestValidateCatalogDuplicateIdentity(t *testing.T) {
	c := refFixture(t)
	dup := c.Models[0]
	dup.Rates = nil
	c.Models = append(c.Models, dup)
	err := ValidateCatalog(c)
	if err == nil || !strings.Contains(err.Error(), "duplicate entry for openai:gpt-test") {
		t.Fatalf("duplicate identity must fail, got %v", err)
	}
}

// TestValidateCatalogRejectsUntrimmedAlias pins the F3 semantics: aliases
// resolve by exact string match (ResolveModel compares the stored string),
// so an alias that only matches after trimming is rejected at validation
// rather than silently normalized inside the caller's slice — what
// validates is exactly what resolves.
func TestValidateCatalogRejectsUntrimmedAlias(t *testing.T) {
	c := refFixture(t)
	c.Models[0].Aliases = append(c.Models[0].Aliases, " gpt-test-2024")
	err := ValidateCatalog(c)
	if err == nil || !strings.Contains(err.Error(), `alias " gpt-test-2024" must not have leading or trailing whitespace`) {
		t.Fatalf("padded alias must be rejected, got %v", err)
	}
	// The trimmed-into-nothing case keeps its original finding.
	blank := refFixture(t)
	blank.Models[0].Aliases = []string{"  "}
	if err := ValidateCatalog(blank); err == nil || !strings.Contains(err.Error(), "alias is empty") {
		t.Fatalf("whitespace-only alias must stay an empty-alias problem, got %v", err)
	}
}

func TestValidateCatalogAliasCollidesWithExistingModel(t *testing.T) {
	c := refFixture(t)
	other := RefModel{
		Provider: "openai",
		Model:    "gpt-test-2024", // the fixture entry's alias
		Currency: "USD",
		Status:   RefStatusDraft,
		Sources:  nil,
		Rates:    nil,
		Aliases:  []string{"gpt-test"}, // also collides with model name
	}
	c.Models = append(c.Models, other)
	err := ValidateCatalog(c)
	if err == nil {
		t.Fatal("alias colliding with an existing model name must fail")
	}
	if !strings.Contains(err.Error(), "collides with an existing model name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEntryEffectiveHalfOpenWindow(t *testing.T) {
	m := RefModel{EffectiveFrom: "2026-01-01", EffectiveTo: "2026-06-01"}
	tests := []struct {
		at   string
		want bool
	}{
		{"2025-12-31", false},
		{"2026-01-01", true},  // from is inclusive
		{"2026-03-15", true},  // inside
		{"2026-06-01", false}, // to is exclusive
		{"2027-01-01", false},
	}
	for _, tt := range tests {
		at, err := parseRefTime(tt.at)
		if err != nil {
			t.Fatalf("parse %s: %v", tt.at, err)
		}
		if got := EntryEffective(m, at); got != tt.want {
			t.Fatalf("EntryEffective at %s = %v, want %v", tt.at, got, tt.want)
		}
	}

	open := RefModel{}
	if !EntryEffective(open, time.Now()) {
		t.Fatal("empty bounds must be open on both sides")
	}
}

func TestEntryServeableStatusGate(t *testing.T) {
	at, err := parseRefTime("2026-05-01")
	if err != nil {
		t.Fatal(err)
	}
	m := RefModel{EffectiveFrom: "2026-01-01", Status: RefStatusActive}
	if !EntryServeable(m, at) {
		t.Fatal("active entry inside its window must be serveable")
	}
	m.Status = RefStatusDraft
	if EntryServeable(m, at) {
		t.Fatal("draft entries are never serveable")
	}
	m.Status = RefStatusRetired
	m.EffectiveTo = "2030-01-01" // window still open
	if EntryServeable(m, at) {
		t.Fatal("retired entries are never serveable even with an open window")
	}
}

func TestRateAndRateAmountDistinguishUnpricedFromFree(t *testing.T) {
	free := 0.0
	m := RefModel{Rates: []RefRate{
		{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &free},
		{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: nil},
	}}

	// Explicit zero: priced and free.
	amount, priced := RateAmount(m, AxisInput)
	if !priced || amount != 0 {
		t.Fatalf("explicit zero must be priced at 0, got priced=%v amount=%v", priced, amount)
	}
	r, ok := Rate(m, AxisInput)
	if !ok || r.Amount == nil || *r.Amount != 0 {
		t.Fatalf("explicit zero rate must be present with non-nil amount, got %+v ok=%v", r, ok)
	}

	// Explicitly unpriced: known axis, unknown amount — never free.
	if _, priced := RateAmount(m, AxisOutput); priced {
		t.Fatal("nil amount must not report as priced")
	}
	if r, ok := Rate(m, AxisOutput); !ok || r.Amount != nil {
		t.Fatalf("unpriced axis must return the rate record with nil amount, got %+v ok=%v", r, ok)
	}

	// Absent axis.
	if _, priced := RateAmount(m, AxisImage); priced {
		t.Fatal("absent axis must not report as priced")
	}
	if _, ok := Rate(m, AxisImage); ok {
		t.Fatal("absent axis must not return a rate record")
	}
}

func TestResolveModelExactThenAlias(t *testing.T) {
	c := refFixture(t)
	holder := RefModel{
		Provider: "openai", Model: "gpt-alias-holder",
		Aliases: []string{"holder-alias"}, Currency: "USD", Status: RefStatusDraft,
	}
	c.Models = append(c.Models, holder)

	m, ok := ResolveModel(c, "openai", "gpt-test")
	if !ok || m.Model != "gpt-test" {
		t.Fatalf("exact name must win, got %+v ok=%v", m, ok)
	}
	m, ok = ResolveModel(c, "openai", "gpt-test-2024")
	if !ok || m.Model != "gpt-test" {
		t.Fatalf("alias must resolve to its target entry, got %+v ok=%v", m, ok)
	}
	m, ok = ResolveModel(c, "openai", "holder-alias")
	if !ok || m.Model != "gpt-alias-holder" {
		t.Fatalf("other alias must resolve to its own entry, got %+v ok=%v", m, ok)
	}
	if _, ok := ResolveModel(c, "openai", "missing"); ok {
		t.Fatal("unknown name must not resolve")
	}
	if _, ok := ResolveModel(c, "anthropic", "gpt-test"); ok {
		t.Fatal("cross-provider match must not resolve")
	}
}

func TestStaleModelsReviewSLA(t *testing.T) {
	c := refFixture(t) // SLA 90 days, verified 2026-09-30
	now, err := parseRefTime("2026-12-29")
	if err != nil {
		t.Fatal(err)
	}
	// 2026-12-29 is day 90 of the 90-day SLA — the last fresh day; the
	// entry turns stale on day 91 (2026-12-30).
	if stale := StaleModels(c, now); len(stale) != 0 {
		t.Fatalf("day 90 must still be fresh, got %v", stale)
	}
	later, _ := parseRefTime("2026-12-30") // day 91
	stale := StaleModels(c, later)
	if len(stale) != 1 || stale[0] != "openai:gpt-test" {
		t.Fatalf("day 91 must be stale, got %v", stale)
	}

	// Draft entries never participate.
	draft := refFixture(t)
	draft.Models = append(draft.Models, RefModel{
		Provider: "openai", Model: "gpt-draft", Currency: "USD",
		Status: RefStatusDraft, VerifiedAt: "2026-01-01",
	})
	if stale := StaleModels(draft, later); len(stale) != 1 || stale[0] != "openai:gpt-test" {
		t.Fatalf("draft entries must be excluded, got %v", stale)
	}

	// No SLA configured: nothing is stale.
	noSLA := refFixture(t)
	noSLA.ReviewSLADays = 0
	if stale := StaleModels(noSLA, later); len(stale) != 0 {
		t.Fatalf("no SLA must report nothing stale, got %v", stale)
	}
}

func TestCanonicalCatalogJSONIsSortedAndStable(t *testing.T) {
	c := refFixture(t)
	c.Models = append(c.Models, RefModel{
		Provider: "anthropic", Model: "claude-test", Currency: "USD", Status: RefStatusDraft,
	})
	b1, err := CanonicalCatalogJSON(c)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	b2, err := CanonicalCatalogJSON(c)
	if err != nil {
		t.Fatalf("canonical json: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatal("canonical form must be deterministic")
	}

	// anthropic < openai: canonical order is by provider.
	var doc struct {
		Models []struct {
			Provider string `json:"provider"`
		} `json:"models"`
	}
	if err := json.Unmarshal(b1, &doc); err != nil {
		t.Fatalf("unmarshal canonical json: %v", err)
	}
	if len(doc.Models) != 2 || doc.Models[0].Provider != "anthropic" || doc.Models[1].Provider != "openai" {
		t.Fatalf("canonical model order must be sorted by provider, got %v", doc.Models)
	}
}

func TestRefAxisUnit(t *testing.T) {
	if unit, ok := RefAxisUnit(AxisImage); !ok || unit != RefUnitPerImage {
		t.Fatalf("image axis must pair with %s, got %s ok=%v", RefUnitPerImage, unit, ok)
	}
	if _, ok := RefAxisUnit("gpu_hour"); ok {
		t.Fatal("unknown axis must not be part of the vocabulary")
	}
}
