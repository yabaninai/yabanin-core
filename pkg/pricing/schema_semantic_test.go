package pricing

import (
	"errors"
	"math"
	"strings"
	"testing"
)

// This suite pins the public validation contract of ValidateCatalog as
// documented in SCHEMA.md. Fixtures are built independently of the unit-test
// fixtures in schema_test.go so drift in one suite cannot hide a contract
// change in the other. Each case is self-contained.

// semanticCatalog assembles a minimal auditable snapshot header around the
// given models (SCHEMA.md "Snapshot header").
func semanticCatalog(models ...RefModel) Catalog {
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "sem-1",
		GeneratedAt:   "2026-11-01",
		Source:        "semantic-contract-suite",
		Models:        models,
	}
}

// semanticActiveModel is the smallest fully-reviewed, serveable entry:
// active, USD, in-force window, one primary source, verified, input and
// output priced. Every case mutates a fresh copy.
func semanticActiveModel() RefModel {
	in, out := 3.0, 6.0
	return RefModel{
		Provider:      "openai",
		Model:         "gpt-sem",
		Currency:      "USD",
		Status:        RefStatusActive,
		EffectiveFrom: "2026-01-01",
		EffectiveTo:   "2027-01-01",
		VerifiedAt:    "2026-10-30",
		Sources: []RefSource{{
			Kind:       RefSourceURL,
			Ref:        "https://openai.com/api/pricing/",
			VerifiedAt: "2026-10-30",
		}},
		Rates: []RefRate{
			{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in},
			{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: &out},
		},
	}
}

// semanticDraftModel is the smallest legal draft: no sources, no review,
// no window (SCHEMA.md: only active entries need sources and a review).
func semanticDraftModel() RefModel {
	in := 1.0
	return RefModel{
		Provider: "anthropic",
		Model:    "claude-sem",
		Currency: "USD",
		Status:   RefStatusDraft,
		Rates:    []RefRate{{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &in}},
	}
}

func TestSemanticValidateCatalogAccepts(t *testing.T) {
	cases := []struct {
		name  string
		build func() Catalog
	}{
		{
			name:  "reviewed active entry with window and primary source",
			build: func() Catalog { return semanticCatalog(semanticActiveModel()) },
		},
		{
			name: "draft entry without sources or review instant",
			build: func() Catalog {
				return semanticCatalog(semanticDraftModel())
			},
		},
		{
			name: "retired entry without sources",
			build: func() Catalog {
				m := semanticDraftModel()
				m.Status = RefStatusRetired
				return semanticCatalog(m)
			},
		},
		{
			name: "unpriced axis is not a free rate",
			build: func() Catalog {
				m := semanticDraftModel()
				m.Rates = append(m.Rates, RefRate{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: nil})
				return semanticCatalog(m)
			},
		},
		{
			name: "zero amount is an explicit free rate",
			build: func() Catalog {
				m := semanticDraftModel()
				free := 0.0
				m.Rates = append(m.Rates, RefRate{Axis: AxisImage, Unit: RefUnitPerImage, Amount: &free})
				return semanticCatalog(m)
			},
		},
		{
			name: "half-open window with only a lower bound",
			build: func() Catalog {
				m := semanticActiveModel()
				m.EffectiveTo = ""
				return semanticCatalog(m)
			},
		},
		{
			name: "half-open window with only an upper bound",
			build: func() Catalog {
				m := semanticActiveModel()
				m.EffectiveFrom = ""
				return semanticCatalog(m)
			},
		},
		{
			name: "full RFC3339 instants accepted for window and review",
			build: func() Catalog {
				m := semanticActiveModel()
				m.EffectiveFrom = "2026-01-01T00:00:00Z"
				m.EffectiveTo = "2027-01-01T00:00:00Z"
				m.VerifiedAt = "2026-10-30T12:00:00Z"
				return semanticCatalog(m)
			},
		},
		{
			name: "currency code is case and whitespace insensitive",
			build: func() Catalog {
				m := semanticActiveModel()
				m.Currency = " usd "
				return semanticCatalog(m)
			},
		},
		{
			name: "aliases resolve within the provider namespace",
			build: func() Catalog {
				m := semanticActiveModel()
				m.Aliases = []string{"gpt-sem-alias", "gpt-sem-v2"}
				return semanticCatalog(m)
			},
		},
		{
			name: "same model name under different providers is two entries",
			build: func() Catalog {
				a := semanticActiveModel()
				b := semanticActiveModel()
				b.Provider = "azure"
				return semanticCatalog(a, b)
			},
		},
		{
			// Amounts are compared on the 1e-12 storage grid: observations
			// differing by less than half a grid step agree.
			name: "agreeing evidence at storage precision is not a conflict",
			build: func() Catalog {
				m := semanticActiveModel()
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: 3.0, At: "2026-10-30"},
					{Ref: m.Sources[0].Ref + "#archive", Amount: 3.0 + 4e-13, At: "2026-10-29"},
				}
				return semanticCatalog(m)
			},
		},
		{
			name: "resolved evidence conflict records the chosen observation",
			build: func() Catalog {
				m := semanticActiveModel()
				observed := 4.0
				m.Rates[0].Amount = &observed
				m.Rates[0].Evidence = []RefEvidence{
					{Ref: m.Sources[0].Ref, Amount: 3.0, At: "2026-10-30"},
					{Ref: "mirror", Amount: 4.0, At: "2026-10-29"},
				}
				m.Sources = append(m.Sources, RefSource{Kind: RefSourceURL, Ref: "mirror", VerifiedAt: "2026-10-30"})
				m.Conflicts = []RefConflict{{Axis: AxisInput, Ref: "mirror", Reason: "later observation is authoritative"}}
				return semanticCatalog(m)
			},
		},
		{
			name: "scoped axes pair with their non-token units",
			build: func() Catalog {
				m := semanticDraftModel()
				sec, chars := 0.02, 0.0001
				m.Rates = append(m.Rates,
					RefRate{Axis: AxisAudioSecond, Unit: RefUnitPerAudioSecond, Amount: &sec},
					RefRate{Axis: AxisCharacter, Unit: RefUnitPerCharacter, Amount: &chars},
				)
				return semanticCatalog(m)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateCatalog(tc.build()); err != nil {
				t.Fatalf("ValidateCatalog rejected a contract-valid snapshot: %v", err)
			}
		})
	}
}

func TestSemanticValidateCatalogRejects(t *testing.T) {
	base := func() Catalog { return semanticCatalog(semanticActiveModel()) }
	cases := []struct {
		name    string
		mutate  func(*Catalog)
		wantErr string // exact path + message fragment of the required finding
	}{
		{
			name:    "empty provider",
			mutate:  func(c *Catalog) { c.Models[0].Provider = "" },
			wantErr: "models[0].provider: provider is required",
		},
		{
			name:    "whitespace provider",
			mutate:  func(c *Catalog) { c.Models[0].Provider = "   " },
			wantErr: "models[0].provider: provider is required",
		},
		{
			name:    "empty model",
			mutate:  func(c *Catalog) { c.Models[0].Model = "" },
			wantErr: "models[0].model: model is required",
		},
		{
			name: "missing identity short-circuits remaining model checks",
			mutate: func(c *Catalog) {
				c.Models[0].Provider = ""
				c.Models[0].Status = "live"
				c.Models[0].Currency = "EUR"
			},
			// The identity gate is the whole report for this entry: later
			// model-level checks (status, currency, window) never run for
			// an entry without an identity.
			wantErr: "models[0].provider: provider is required",
		},
		{
			name:    "unknown status",
			mutate:  func(c *Catalog) { c.Models[0].Status = "live" },
			wantErr: `models[0].status: must be draft, active or retired, got "live"`,
		},
		{
			name:    "non-USD currency",
			mutate:  func(c *Catalog) { c.Models[0].Currency = "EUR" },
			wantErr: `models[0].currency: must be USD, got "EUR"`,
		},
		{
			name:    "empty currency",
			mutate:  func(c *Catalog) { c.Models[0].Currency = "" },
			wantErr: `models[0].currency: must be USD, got ""`,
		},
		{
			name:    "malformed verified_at",
			mutate:  func(c *Catalog) { c.Models[0].VerifiedAt = "yesterday" },
			wantErr: "models[0].verified_at:",
		},
		{
			name:    "active entry without review instant",
			mutate:  func(c *Catalog) { c.Models[0].VerifiedAt = "" },
			wantErr: "models[0].verified_at: an active entry must carry a verification instant",
		},
		{
			name:    "active entry without sources",
			mutate:  func(c *Catalog) { c.Models[0].Sources = nil },
			wantErr: "models[0].sources: an active entry needs at least one primary source",
		},
		{
			name:    "malformed effective_from",
			mutate:  func(c *Catalog) { c.Models[0].EffectiveFrom = "2026/01/01" },
			wantErr: "models[0].effective_from:",
		},
		{
			name:    "malformed effective_to",
			mutate:  func(c *Catalog) { c.Models[0].EffectiveTo = "Jan 1 2027" },
			wantErr: "models[0].effective_to:",
		},
		{
			name: "window closes exactly at open",
			mutate: func(c *Catalog) {
				c.Models[0].EffectiveTo = c.Models[0].EffectiveFrom
			},
			wantErr: "models[0]: effective window closes at or before it opens",
		},
		{
			name: "inverted window",
			mutate: func(c *Catalog) {
				c.Models[0].EffectiveFrom = "2027-01-01"
				c.Models[0].EffectiveTo = "2026-01-01"
			},
			wantErr: "models[0]: effective window closes at or before it opens",
		},
		{
			name:    "empty alias",
			mutate:  func(c *Catalog) { c.Models[0].Aliases = []string{"   "} },
			wantErr: "models[0].aliases[0]: alias is empty",
		},
		{
			name:    "padded alias",
			mutate:  func(c *Catalog) { c.Models[0].Aliases = []string{" gpt-sem-alias"} },
			wantErr: `models[0].aliases[0]: alias " gpt-sem-alias" must not have leading or trailing whitespace`,
		},
		{
			name:    "alias shadows its own model name",
			mutate:  func(c *Catalog) { c.Models[0].Aliases = []string{"gpt-sem"} },
			wantErr: `models[0].aliases[0]: alias "gpt-sem" shadows the model name`,
		},
		{
			name: "duplicate model identity",
			mutate: func(c *Catalog) {
				c.Models = append(c.Models, semanticActiveModel())
			},
			wantErr: "models[1]: duplicate entry for openai:gpt-sem (first at models[0])",
		},
		{
			// Identity is (provider, model): region/tier/context_band scope
			// entries but do not participate in the duplicate key (see
			// SCHEMA.md "Model identity" for the documented 5-tuple; the
			// validator's key is provider+model today).
			name: "duplicate identity across regions is still a duplicate",
			mutate: func(c *Catalog) {
				dup := semanticActiveModel()
				dup.Region = "eu"
				c.Models = append(c.Models, dup)
			},
			wantErr: "models[1]: duplicate entry for openai:gpt-sem (first at models[0])",
		},
		{
			name: "second model name colliding with a registered alias",
			mutate: func(c *Catalog) {
				c.Models[0].Aliases = []string{"frozen-name"}
				dup := semanticActiveModel()
				dup.Model = "frozen-name"
				c.Models = append(c.Models, dup)
			},
			wantErr: `models[1]: model name "frozen-name" collides with an existing alias in openai`,
		},
		{
			name: "duplicate alias within the provider",
			mutate: func(c *Catalog) {
				c.Models[0].Aliases = []string{"dup-alias"}
				second := semanticActiveModel()
				second.Model = "gpt-sem-2"
				second.Aliases = []string{"dup-alias"}
				c.Models = append(c.Models, second)
			},
			wantErr: `models[1].aliases[0]: duplicate alias "dup-alias" for openai (first at models[0])`,
		},
		{
			name: "alias colliding with an existing model name",
			mutate: func(c *Catalog) {
				second := semanticActiveModel()
				second.Model = "gpt-sem-2"
				second.Aliases = []string{"gpt-sem"}
				c.Models = append(c.Models, second)
			},
			wantErr: `models[1].aliases[0]: alias "gpt-sem" collides with an existing model name in openai`,
		},
		{
			name:    "unknown rate axis",
			mutate:  func(c *Catalog) { c.Models[0].Rates[0].Axis = "gpu_hour" },
			wantErr: `models[0].rates[0].axis: unknown axis "gpu_hour"`,
		},
		{
			name:    "unit not paired with its axis",
			mutate:  func(c *Catalog) { c.Models[0].Rates[0].Unit = RefUnitPerImage },
			wantErr: `models[0].rates[0].unit: axis "input" must use unit "per_1m_tokens"`,
		},
		{
			name: "two rates on one axis",
			mutate: func(c *Catalog) {
				extra := 9.0
				c.Models[0].Rates = append(c.Models[0].Rates, RefRate{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &extra})
			},
			wantErr: `models[0].rates[2].axis: duplicate rate for axis "input" (first at rates[0])`,
		},
		{
			name: "NaN price",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Amount = refFloat(math.NaN())
			},
			wantErr: "models[0].rates[0].amount: not a finite number",
		},
		{
			name: "infinite price",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Amount = refFloat(math.Inf(1))
			},
			wantErr: "models[0].rates[0].amount: not a finite number",
		},
		{
			name:    "negative price",
			mutate:  func(c *Catalog) { c.Models[0].Rates[0].Amount = refFloat(-1) },
			wantErr: "models[0].rates[0].amount: negative price",
		},
		{
			name: "evidence without a ref",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{{Ref: " ", Amount: 3.0}}
			},
			wantErr: "models[0].rates[0].evidence[0].ref: evidence ref is required",
		},
		{
			name: "duplicate evidence ref",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{
					{Ref: "a", Amount: 3.0, At: "2026-10-30"},
					{Ref: "a", Amount: 3.0, At: "2026-10-29"},
				}
			},
			wantErr: `models[0].rates[0].evidence[1].ref: duplicate evidence ref "a"`,
		},
		{
			name: "negative evidence amount",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{{Ref: "a", Amount: -3.0}}
			},
			wantErr: "models[0].rates[0].evidence[0].amount: negative price",
		},
		{
			name: "malformed evidence instant",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{{Ref: "a", Amount: 3.0, At: "recently"}}
			},
			wantErr: "models[0].rates[0].evidence[0].at:",
		},
		{
			name:    "unknown source kind",
			mutate:  func(c *Catalog) { c.Models[0].Sources[0].Kind = "blog" },
			wantErr: `models[0].sources[0].kind: must be "url" or "internal_evidence"`,
		},
		{
			name:    "source without a ref",
			mutate:  func(c *Catalog) { c.Models[0].Sources[0].Ref = " " },
			wantErr: "models[0].sources[0].ref: source ref is required",
		},
		{
			name: "duplicate source ref",
			mutate: func(c *Catalog) {
				c.Models[0].Sources = append(c.Models[0].Sources, c.Models[0].Sources[0])
			},
			wantErr: `models[0].sources[1].ref: duplicate source ref "https://openai.com/api/pricing/"`,
		},
		{
			name:    "malformed source verified_at",
			mutate:  func(c *Catalog) { c.Models[0].Sources[0].VerifiedAt = "2026.10.30" },
			wantErr: "models[0].sources[0].verified_at:",
		},
		{
			name: "conflict on an unknown axis",
			mutate: func(c *Catalog) {
				c.Models[0].Conflicts = []RefConflict{{Axis: "gpu_hour", Ref: "mirror", Reason: "why"}}
			},
			wantErr: `models[0].conflicts[0].axis: unknown axis "gpu_hour"`,
		},
		{
			name:    "conflict without a chosen ref",
			mutate:  func(c *Catalog) { c.Models[0].Conflicts = []RefConflict{{Axis: AxisInput, Ref: "", Reason: "why"}} },
			wantErr: "models[0].conflicts[0].ref: conflict resolution needs the chosen source ref",
		},
		{
			name: "conflict resolution naming an unlisted source",
			mutate: func(c *Catalog) {
				c.Models[0].Conflicts = []RefConflict{{Axis: AxisInput, Ref: "not-a-source", Reason: "why"}}
			},
			wantErr: `models[0].conflicts[0].ref: chosen source "not-a-source" is not one of the entry's sources`,
		},
		{
			name:    "conflict without a reason",
			mutate:  func(c *Catalog) { c.Models[0].Conflicts = []RefConflict{{Axis: AxisInput, Ref: "mirror", Reason: " "}} },
			wantErr: "models[0].conflicts[0].reason: conflict resolution needs a reason",
		},
		{
			name: "conflicting evidence without a resolution",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{
					{Ref: "a", Amount: 3.0, At: "2026-10-30"},
					{Ref: "b", Amount: 4.0, At: "2026-10-29"},
				}
			},
			wantErr: `models[0].rates[0]: conflicting evidence on axis "input" without a resolution choosing one observed amount`,
		},
		{
			// Boundary of the 1e-12 storage grid: observations a full grid
			// step apart are a conflict and must be resolved explicitly.
			name: "evidence one grid step apart is a conflict",
			mutate: func(c *Catalog) {
				c.Models[0].Rates[0].Evidence = []RefEvidence{
					{Ref: "a", Amount: 3.0, At: "2026-10-30"},
					{Ref: "b", Amount: 3.0 + 1e-12, At: "2026-10-29"},
				}
			},
			wantErr: `models[0].rates[0]: conflicting evidence on axis "input" without a resolution choosing one observed amount`,
		},
		{
			name: "resolution choosing an amount no source observed",
			mutate: func(c *Catalog) {
				other := 5.0
				c.Models[0].Rates[0].Amount = &other
				c.Models[0].Rates[0].Evidence = []RefEvidence{
					{Ref: "a", Amount: 3.0, At: "2026-10-30"},
					{Ref: "b", Amount: 4.0, At: "2026-10-29"},
				}
				c.Models[0].Sources = append(c.Models[0].Sources, RefSource{Kind: RefSourceURL, Ref: "b", VerifiedAt: "2026-10-30"})
				c.Models[0].Conflicts = []RefConflict{{Axis: AxisInput, Ref: "b", Reason: "wrong choice"}}
			},
			wantErr: `models[0].rates[0]: conflicting evidence on axis "input" without a resolution choosing one observed amount`,
		},
		{
			name:    "wrong schema version",
			mutate:  func(c *Catalog) { c.SchemaVersion = RefSchemaVersion + 1 },
			wantErr: "schema_version: must be 1",
		},
		{
			name:    "missing catalog version",
			mutate:  func(c *Catalog) { c.Version = " " },
			wantErr: "version: catalog version is required",
		},
		{
			name:    "missing assembly source",
			mutate:  func(c *Catalog) { c.Source = "" },
			wantErr: "source: assembly source is required",
		},
		{
			name:    "malformed generated_at",
			mutate:  func(c *Catalog) { c.GeneratedAt = "now" },
			wantErr: "generated_at:",
		},
		{
			name:    "negative review SLA",
			mutate:  func(c *Catalog) { c.ReviewSLADays = -1 },
			wantErr: "review_sla_days: must not be negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base()
			tc.mutate(&c)
			err := ValidateCatalog(c)
			if err == nil {
				t.Fatalf("ValidateCatalog accepted a contract-invalid snapshot (%s)", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateCatalog error %q does not carry the required finding %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSemanticValidateCatalogRejectsWholeSnapshot(t *testing.T) {
	m := semanticActiveModel()
	m.Currency = "EUR"
	m.Status = "live"
	err := ValidateCatalog(semanticCatalog(m))
	if err == nil {
		t.Fatal("any finding must reject the whole snapshot")
	}
	var catalogErr *CatalogError
	if !errors.As(err, &catalogErr) {
		t.Fatalf("ValidateCatalog must return *CatalogError, got %T", err)
	}
	if len(catalogErr.Problems) != 2 {
		t.Fatalf("want both the status and the currency finding, got %d: %v", len(catalogErr.Problems), catalogErr.Problems)
	}
	if catalogErr.Problems[0].Path != "models[0].status" || catalogErr.Problems[1].Path != "models[0].currency" {
		t.Fatalf("findings must be reported in declaration order (status before currency), got %v", catalogErr.Problems)
	}
}

// refFloat is a local helper so the suite stays independent of fixture
// helpers defined in schema_test.go.
func refFloat(v float64) *float64 { return &v }
