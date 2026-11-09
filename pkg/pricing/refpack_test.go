package pricing

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CORE-REF-03 RED tests (PREP/COREREF-03 §4 — written first, watched failing,
// then made green for the right reason). Each test carries the invariant it
// guards and the mutation probe that must flip it.
//
// Item 8 of the prep (reuse, don't duplicate) is honored by construction:
// digest permutation is pinned by REF-01 F1 (schema_test.go
// TestCatalogDigestPermutation) and merge resolution by REF-01 F2
// (schema_convert_test.go); these tests reference those contracts and add
// only envelope-level coverage.

// rawEnvelope mirrors the RefPack field order for byte-level envelope
// surgery in the tamper tests. It must stay in sync with RefPack.
type rawEnvelope struct {
	PackSchemaVersion int             `json:"pack_schema_version"`
	Catalog           json.RawMessage `json:"catalog"`
	CatalogDigest     string          `json:"catalog_digest"`
	PackSHA256        string          `json:"pack_sha256"`
	Notices           []string        `json:"notices,omitempty"`
}

// refPackTestCatalog builds a minimal valid draft catalog with two models
// whose declaration order is deliberately non-canonical (zeta before alpha)
// so ordering bugs surface as byte/diff differences.
func refPackTestCatalog() Catalog {
	amtA := 3.0
	amtZIn := 7.5
	amtZOut := 9.0
	return Catalog{
		SchemaVersion: RefSchemaVersion,
		Version:       "0.1.0-test",
		GeneratedAt:   "2026-11-02",
		Source:        "refpack test assembly (deterministic fixture)",
		ReviewSLADays: 90,
		Models: []RefModel{
			{
				Provider: "zprov", Model: "zeta-model",
				Currency: "USD", Status: RefStatusDraft,
				EffectiveFrom: "2026-11-01", VerifiedAt: "2026-11-02",
				Aliases: []string{"zeta-alias-b", "zeta-alias-a"},
				// Non-canonical axis order in the slice (output before
				// input): canonicalization must not care.
				Rates: []RefRate{
					{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: &amtZOut},
					{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &amtZIn},
				},
				Reviewer: "fixture-reviewer",
			},
			{
				Provider: "aprov", Model: "alpha-model",
				Currency: "USD", Status: RefStatusDraft,
				EffectiveFrom: "2026-11-01", VerifiedAt: "2026-11-02",
				Aliases:  []string{"alpha-alias"},
				Rates:    []RefRate{{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: &amtA}},
				Reviewer: "fixture-reviewer",
			},
		},
	}
}

// sealedCatalogJSON seals c and returns its JSON encoding (any valid
// encoding is accepted by BuildRefPack; the pack canonicalizes internally).
func sealedCatalogJSON(t *testing.T, c Catalog) []byte {
	t.Helper()
	sealed, err := SealCatalog(c)
	if err != nil {
		t.Fatalf("seal fixture catalog: %v", err)
	}
	b, err := json.Marshal(sealed)
	if err != nil {
		t.Fatalf("marshal fixture catalog: %v", err)
	}
	return b
}

func mustBuildPack(t *testing.T, catalogJSON []byte, notices []string) []byte {
	t.Helper()
	p, err := BuildRefPack(catalogJSON, notices)
	if err != nil {
		t.Fatalf("BuildRefPack: %v", err)
	}
	b, err := MarshalRefPack(p)
	if err != nil {
		t.Fatalf("MarshalRefPack: %v", err)
	}
	return b
}

// TestRefPackDeterministicBytes pins the envelope byte format: same inputs
// (and permuted input order) → byte-identical envelope across invocations.
//
// Mutation probe: sneaking a time.Now() or a map-ordered field into the
// envelope build must flip this test.
func TestRefPackDeterministicBytes(t *testing.T) {
	c := refPackTestCatalog()
	sealed := sealedCatalogJSON(t, c)

	first := mustBuildPack(t, sealed, []string{"pkg/pricing/NOTICE-litellm.txt"})
	second := mustBuildPack(t, sealed, []string{"pkg/pricing/NOTICE-litellm.txt"})
	if !bytes.Equal(first, second) {
		t.Fatalf("identical inputs produced different envelope bytes (%d vs %d bytes)", len(first), len(second))
	}

	// Permuted input: reversed model order, reversed aliases, reversed
	// axis order must not change bytes — same content, different order.
	permuted := refPackTestCatalog()
	permuted.Models[0], permuted.Models[1] = permuted.Models[1], permuted.Models[0]
	// After the swap Models[1] is zeta: reorder its aliases and axes —
	// same content, different slice order.
	permuted.Models[1].Aliases = []string{"zeta-alias-a", "zeta-alias-b"}
	permuted.Models[1].Rates = []RefRate{
		{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: ptrFloat(7.5)},
		{Axis: AxisOutput, Unit: RefUnitPer1MTokens, Amount: ptrFloat(9.0)},
	}
	permutedSealed := sealedCatalogJSON(t, permuted)
	third := mustBuildPack(t, permutedSealed, []string{"pkg/pricing/NOTICE-litellm.txt"})
	if !bytes.Equal(first, third) {
		t.Fatalf("permuted input order changed the envelope bytes: canonicalization leaked into the pack build")
	}

	// Notice list is normalized: duplicates and unordered input must not
	// change the bytes.
	fourth := mustBuildPack(t, sealed, []string{
		"pkg/pricing/NOTICE-litellm.txt", "pkg/pricing/NOTICE-litellm.txt",
	})
	if !bytes.Equal(first, fourth) {
		t.Fatalf("duplicate notice refs changed the envelope bytes")
	}

	// Envelope round-trip: the built bytes must parse back to the same
	// declared values.
	pack, _, err := LoadRefPack(first)
	if err != nil {
		t.Fatalf("LoadRefPack(built pack): %v", err)
	}
	if pack.PackSchemaVersion != RefPackSchemaVersion {
		t.Fatalf("pack_schema_version = %d, want %d", pack.PackSchemaVersion, RefPackSchemaVersion)
	}
	if pack.CatalogDigest == "" || pack.PackSHA256 == "" {
		t.Fatalf("built pack must carry both digests, got catalog_digest=%q pack_sha256=%q", pack.CatalogDigest, pack.PackSHA256)
	}
}

// TestRefPackTamperRefused pins the three independent fail-closed checks
// (PREP/COREREF-03 §3): envelope pack_sha256, catalog digest, schema
// validation. Any single flipped byte must be refused with expected-vs-actual
// in the error — never trusted, never warned about.
func TestRefPackTamperRefused(t *testing.T) {
	c := refPackTestCatalog()
	packBytes := mustBuildPack(t, sealedCatalogJSON(t, c), nil)

	var env rawEnvelope
	if err := json.Unmarshal(packBytes, &env); err != nil {
		t.Fatalf("decode built envelope: %v", err)
	}

	t.Run("flipped amount in catalog body refused", func(t *testing.T) {
		tampered := env
		body := string(tampered.Catalog)
		if !strings.Contains(body, `"amount":3`) {
			t.Fatalf("fixture body lost its amount marker; update the fixture, the probe, or both")
		}
		tampered.Catalog = json.RawMessage(strings.Replace(body, `"amount":3`, `"amount":4`, 1))
		b, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("remarshal: %v", err)
		}
		_, _, err = LoadRefPack(b)
		if err == nil {
			t.Fatalf("tampered catalog body accepted: content/digest check did not run fail-closed")
		}
		if !strings.Contains(err.Error(), "digest") {
			t.Fatalf("tamper error must identify the digest check, got: %v", err)
		}
	})

	t.Run("flipped pack_sha256 refused with expected vs actual", func(t *testing.T) {
		tampered := env
		fake := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
		if fake == tampered.PackSHA256 {
			t.Fatalf("probe digest collides with the real pack digest; change the fake")
		}
		tampered.PackSHA256 = fake
		b, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("remarshal: %v", err)
		}
		_, _, err = LoadRefPack(b)
		if err == nil {
			t.Fatalf("pack with wrong pack_sha256 accepted")
		}
		// Expected vs actual must both be named so an operator can
		// reconcile which side moved.
		if !strings.Contains(err.Error(), fake) {
			t.Fatalf("pack digest error must name the declared (actual) digest %s, got: %v", fake, err)
		}
		if !strings.Contains(err.Error(), env.PackSHA256) {
			t.Fatalf("pack digest error must name the expected digest %s, got: %v", env.PackSHA256, err)
		}
	})

	t.Run("stripped pack_sha256 refused", func(t *testing.T) {
		tampered := env
		tampered.PackSHA256 = ""
		b, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("remarshal: %v", err)
		}
		_, _, err = LoadRefPack(b)
		if err == nil {
			t.Fatalf("envelope without pack_sha256 accepted: absent verification is not verification")
		}
	})

	t.Run("flipped catalog_digest refused", func(t *testing.T) {
		tampered := env
		tampered.CatalogDigest = "0000000000000000000000000000000000000000000000000000000000000000"
		b, err := json.Marshal(tampered)
		if err != nil {
			t.Fatalf("remarshal: %v", err)
		}
		_, _, err = LoadRefPack(b)
		if err == nil {
			t.Fatalf("pack with wrong catalog_digest accepted")
		}
	})

	t.Run("unsealed input refused at build", func(t *testing.T) {
		c := refPackTestCatalog()
		raw, err := json.Marshal(c) // digest field never set
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, err := BuildRefPack(raw, nil); err == nil {
			t.Fatalf("BuildRefPack accepted unsealed (digest-less) catalog JSON")
		}
	})
}

// TestRefChainRollbackBothWays pins the Supersedes chain: a successor must
// name the actual digest of the snapshot it replaces; a forged pointer is
// refused; the reverse direction is not a valid chain (v1 declares no
// predecessor); and rollback is a NEW snapshot restoring prior content with
// Supersedes pointed at the snapshot being rolled back — after which loading
// the old pack again still verifies (history is immutable).
func TestRefChainRollbackBothWays(t *testing.T) {
	v1 := refPackTestCatalog()
	v1JSON := sealedCatalogJSON(t, v1)
	pack1 := mustBuildPack(t, v1JSON, nil)

	d1, err := CatalogDigest(v1)
	if err != nil {
		t.Fatalf("digest v1: %v", err)
	}

	v2 := refPackTestCatalog()
	v2.Version = "0.2.0-test"
	v2.Supersedes = d1
	v2JSON := sealedCatalogJSON(t, v2)
	pack2 := mustBuildPack(t, v2JSON, nil)

	if err := VerifyRefPackChain(pack1, pack2); err != nil {
		t.Fatalf("v2 supersedes digest(v1) must verify: %v", err)
	}

	t.Run("forged supersedes pointer refused", func(t *testing.T) {
		forged := refPackTestCatalog()
		forged.Version = "0.2.0-test"
		forged.Supersedes = "1111111111111111111111111111111111111111111111111111111111111111"
		forgedPack := mustBuildPack(t, sealedCatalogJSON(t, forged), nil)
		err := VerifyRefPackChain(pack1, forgedPack)
		if err == nil {
			t.Fatalf("chain accepted a successor that names a digest the predecessor does not have")
		}
		if !strings.Contains(err.Error(), d1) {
			t.Fatalf("chain error must name the predecessor's actual digest %s, got: %v", d1, err)
		}
	})

	t.Run("reverse direction is not a chain", func(t *testing.T) {
		if err := VerifyRefPackChain(pack2, pack1); err == nil {
			t.Fatalf("chain accepted the reverse direction; genesis declares no predecessor")
		}
	})

	t.Run("rollback is a new snapshot restoring prior content", func(t *testing.T) {
		d2, err := CatalogDigest(v2)
		if err != nil {
			t.Fatalf("digest v2: %v", err)
		}
		v3 := refPackTestCatalog() // prior content restored
		v3.Version = "0.1.1-rollback"
		v3.Supersedes = d2
		v3JSON := sealedCatalogJSON(t, v3)
		pack3 := mustBuildPack(t, v3JSON, nil)
		if err := VerifyRefPackChain(pack2, pack3); err != nil {
			t.Fatalf("rollback snapshot must supersede the snapshot it rolls back: %v", err)
		}
		// History is immutable: after the rollback the v1 pack still
		// verifies standalone, and the original v1→v2 link still holds.
		if _, _, err := LoadRefPack(pack1); err != nil {
			t.Fatalf("v1 pack must keep verifying after rollback: %v", err)
		}
		if err := VerifyRefPackChain(pack1, pack2); err != nil {
			t.Fatalf("v1→v2 chain link must stay verifiable after rollback: %v", err)
		}
	})
}

// TestRefLoaderHermeticOffline pins hermeticity two ways: statically (the
// pack/loader file imports no network/process/file machinery — same
// technique as consumers_test.go) and behaviorally (build+load run from pure
// []byte with no other I/O).
func TestRefLoaderHermeticOffline(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "pkg", "pricing", "refpack.go"))
	if err != nil {
		t.Fatalf("read refpack.go: %v", err)
	}
	for _, forbidden := range []string{
		`"net/http"`, `"net"`, `http.Get`, `http.Post`, `http.NewRequest`,
		`os.Open`, `os.ReadFile`, `os.Create`, `exec.Command`,
	} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("refpack.go must stay hermetic: found %s", forbidden)
		}
	}

	// Behavioral half: the full build→load cycle on pure bytes, no fixtures
	// on disk, no environment.
	c := refPackTestCatalog()
	b := mustBuildPack(t, sealedCatalogJSON(t, c), nil)
	if _, _, err := LoadRefPack(b); err != nil {
		t.Fatalf("hermetic build→load failed: %v", err)
	}
}

// TestRefreshDiffDeterministic pins the review-diff tool: deterministic
// output (identical text twice, canonical entry order regardless of input
// order), and refusal to bless a draft→active promotion without reviewer or
// sources (the diff is the review gate; it never auto-promotes).
func TestRefreshDiffDeterministic(t *testing.T) {
	oldCat := refPackTestCatalog()
	oldCat.Version = "0.1.0-diff"
	oldJSON := sealedCatalogJSON(t, oldCat)

	newCat := refPackTestCatalog()
	newCat.Version = "0.2.0-diff"
	// alpha is promoted to active WITH reviewer and sources (legal), and
	// its price changes; zeta's price changes too (so both changed entries
	// must appear, alpha first by canonical order); a third model is added.
	alpha := &newCat.Models[1] // non-canonical position on purpose
	alpha.Status = RefStatusActive
	alpha.Reviewer = "diff-reviewer"
	alpha.Sources = []RefSource{{Kind: RefSourceInternalEvidence, Ref: "ev-diff-1", VerifiedAt: "2026-11-02"}}
	amt := 3.5
	alpha.Rates[0].Amount = &amt
	zeta := &newCat.Models[0]
	amtZ := 8.0
	zeta.Rates[1].Amount = &amtZ // input axis of zeta (non-canonical slice position)
	newCat.Models = append(newCat.Models, RefModel{
		Provider: "bprov", Model: "beta-model",
		Currency: "USD", Status: RefStatusDraft,
		EffectiveFrom: "2026-11-01", VerifiedAt: "2026-11-02",
		Rates:    []RefRate{{Axis: AxisInput, Unit: RefUnitPer1MTokens, Amount: ptrFloat(1.0)}},
		Reviewer: "fixture-reviewer",
	})
	newJSON := sealedCatalogJSON(t, newCat)

	first, err := RefDiff(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("RefDiff: %v", err)
	}
	second, err := RefDiff(oldJSON, newJSON)
	if err != nil {
		t.Fatalf("RefDiff (second render): %v", err)
	}
	if first != second {
		t.Fatalf("diff output is not deterministic:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}

	// Canonical order: changed/added entries must appear in canonical
	// identity order — aprov/alpha, bprov/beta, zprov/zeta — even though
	// both fixtures declare zeta first.
	ia, ib, iz := strings.Index(first, "alpha-model"), strings.Index(first, "beta-model"), strings.Index(first, "zeta-model")
	if ia < 0 || ib < 0 || iz < 0 || ia >= ib || ib >= iz {
		t.Fatalf("diff must list entries in canonical order (alpha < beta < zeta), got indices (%d,%d,%d):\n%s", ia, ib, iz, first)
	}

	t.Run("promotion without reviewer refused", func(t *testing.T) {
		bad := refPackTestCatalog()
		bad.Version = "0.2.0-bad"
		a := &bad.Models[1]
		a.Status = RefStatusActive
		a.Reviewer = "" // promotion without a reviewer
		a.Sources = []RefSource{{Kind: RefSourceInternalEvidence, Ref: "ev-diff-2", VerifiedAt: "2026-11-02"}}
		badJSON := sealedCatalogJSON(t, bad)
		_, err := RefDiff(oldJSON, badJSON)
		if err == nil {
			t.Fatalf("diff blessed a draft→active promotion without a reviewer")
		}
		if !strings.Contains(err.Error(), "alpha-model") {
			t.Fatalf("refusal must name the promoted entry, got: %v", err)
		}
	})

	t.Run("promotion without sources refused", func(t *testing.T) {
		bad := refPackTestCatalog()
		bad.Version = "0.2.0-bad"
		a := &bad.Models[1]
		a.Status = RefStatusActive
		a.Reviewer = "diff-reviewer"
		a.Sources = nil // schema-valid only if verified_at empty; force the refusal path
		a.VerifiedAt = ""
		badJSON := sealedCatalogJSON(t, bad)
		if _, err := RefDiff(oldJSON, badJSON); err == nil {
			t.Fatalf("diff accepted a draft→active promotion without primary sources")
		}
	})

	t.Run("identical snapshots render a stable no-op diff", func(t *testing.T) {
		same := sealedCatalogJSON(t, refPackTestCatalog())
		out1, err := RefDiff(same, same)
		if err != nil {
			t.Fatalf("RefDiff(identity): %v", err)
		}
		out2, err := RefDiff(same, same)
		if err != nil {
			t.Fatalf("RefDiff(identity, second): %v", err)
		}
		if out1 != out2 {
			t.Fatalf("identity diff is not deterministic")
		}
		if !strings.Contains(out1, "changed=0") {
			t.Fatalf("identity diff must report no changes, got:\n%s", out1)
		}
	})
}

func ptrFloat(f float64) *float64 { return &f }

// committedRefPackRel is the repo-root-relative location of the pinned
// reference pack (CORE-REF-03). The committed bytes ARE the pin.
const committedRefPackRel = "pkg/pricing/snapshots/reference-pack-v1.json"

// genesisCatalogRel is the CORE-REF-02 genesis catalog whose body the pack
// lifts verbatim.
const genesisCatalogRel = "pkg/pricing/catalogs/reference-catalog-v1.json"

// genesisCatalogDigest is the REF-02 review-recorded genesis digest
// (artifacts/internal-delivery-program/CORE-REF/core-ref02-20261102.md). Hardcoded on
// purpose: the pin must not move silently.
const genesisCatalogDigest = "eeb4d7063d48b8bf7b5d4f4374278259cdff856792755f63d0a92c21f2f651c5"

// TestBundledRefSnapshotPins pins the committed snapshot: it loads through
// the full fail-closed checks, its catalog digest is exactly the REF-02
// genesis digest, and its embedded body is byte-identical to the committed
// genesis catalog (lifted verbatim, not re-encoded). The whole pkg/pricing
// suite must also pass offline; GOPROXY=off evidence is recorded in the
// delivery record (the suite itself needs no network — no new dependencies).
func TestBundledRefSnapshotPins(t *testing.T) {
	packBytes, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(committedRefPackRel)))
	if err != nil {
		t.Fatalf("committed reference pack missing (%s): %v", committedRefPackRel, err)
	}
	pack, cat, err := LoadRefPack(packBytes)
	if err != nil {
		t.Fatalf("committed reference pack must pass all loader checks: %v", err)
	}
	if cat.Digest != genesisCatalogDigest {
		t.Fatalf("snapshot pin moved: catalog digest is %s, want the REF-02 genesis %s", cat.Digest, genesisCatalogDigest)
	}

	// Body must be the genesis bytes verbatim (canonical form), not a
	// re-encoding that could drift from the reviewed artifact.
	genesisRaw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(genesisCatalogRel)))
	if err != nil {
		t.Fatalf("read genesis catalog: %v", err)
	}
	var genesis Catalog
	if err := json.Unmarshal(genesisRaw, &genesis); err != nil {
		t.Fatalf("parse genesis catalog: %v", err)
	}
	d, err := CatalogDigest(genesis)
	if err != nil {
		t.Fatalf("digest genesis: %v", err)
	}
	if d != genesisCatalogDigest {
		t.Fatalf("committed genesis catalog digests to %s, want %s", d, genesisCatalogDigest)
	}
	n := canonicalizeCatalog(genesis)
	n.Digest = genesis.Digest
	canon, err := json.Marshal(n)
	if err != nil {
		t.Fatalf("canonical genesis: %v", err)
	}
	if !bytes.Equal(canon, []byte(pack.Catalog)) {
		t.Fatalf("pack catalog body is not the genesis bytes verbatim (len %d vs %d)", len(pack.Catalog), len(canon))
	}
}

// TestDefaultTargetsNeverFetch pins the no-fetch default: no Makefile target outside
// the pricing family may depend on pricing-refresh or run the LiteLLM import,
// and the guarded default targets (build/test/quality-*) must not touch the
// network source at all. The optional import path must keep recording the
// upstream provenance verbatim and keep the notice chain alive.
func TestDefaultTargetsNeverFetch(t *testing.T) {
	mf, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}

	// Walk the target graph: a rule line names one or more targets (split
	// on whitespace); its body is every tab-prefixed line until the next
	// rule. Variable assignments and .PHONY metadata are not rules.
	type target struct{ name, prerequisites, body string }
	var targets []target
	var cur []*target
	for _, line := range strings.Split(string(mf), "\n") {
		if strings.HasPrefix(line, "\t") { // recipe line
			for _, c := range cur {
				c.body += line + "\n"
			}
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 || strings.ContainsAny(line[:idx], "$=") || strings.HasPrefix(line[idx:], ":=") {
			continue // variable assignment / blank — not a rule
		}
		names := strings.Fields(line[:idx])
		if len(names) == 0 || names[0] == ".PHONY" {
			continue // .PHONY is metadata, not a rule; its names must not satisfy the existence pin
		}
		first := len(targets)
		prerequisites := strings.TrimSpace(strings.SplitN(line[idx+1:], "#", 2)[0])
		for _, n := range names {
			targets = append(targets, target{name: n, prerequisites: prerequisites})
		}
		cur = cur[:0]
		for i := first; i < len(targets); i++ {
			cur = append(cur, &targets[i])
		}
	}

	pricingFamily := map[string]bool{"pricing-refresh": true, "pricing-pack": true, "pricing-verify": true}
	noFetchMarkers := []string{"pricing-refresh", "import-litellm", "raw.githubusercontent.com/BerriAI"}
	for _, tg := range targets {
		if pricingFamily[tg.name] || tg.name == "help" {
			continue // the optional refresh path itself, offline targets, and help text
		}
		for _, marker := range noFetchMarkers {
			if strings.Contains(tg.prerequisites+"\n"+tg.body, marker) {
				t.Errorf("Makefile target %q references %q: the fetch path must stay an explicit pricing-family target", tg.name, marker)
			}
		}
	}
	for _, guarded := range []string{"build", "test", "test-short", "quality-fast", "quality-static", "quality-tests", "quality-full", "quality-changed"} {
		found := false
		for _, tg := range targets {
			if tg.name == guarded {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("guarded target %q missing from Makefile; the pin must track the default loop", guarded)
		}
	}

	// The optional import path must record upstream provenance verbatim
	// (never re-labeled as Yabanin data — audit REF-03: renaming the source
	// does not replace the data).
	lit := `{"probe-model":{"mode":"chat","litellm_provider":"openai","input_cost_per_token":0.000001,` +
		`"output_cost_per_token":0.000002,"cache_creation_input_token_cost":0.0000015,` +
		`"cache_read_input_token_cost":0.0000005}}`
	upstream := "github.com/BerriAI/litellm@61a73c59b049a8cd6c559168d7f3a2557a1a8cf7/model_prices_and_context_window.json"
	pf, stats, err := ImportLiteLLM(strings.NewReader(lit), upstream, "2026-09-30")
	if err != nil {
		t.Fatalf("ImportLiteLLM: %v", err)
	}
	if stats.Imported != 1 {
		t.Fatalf("fixture import classified %d models, want 1 (stats: %+v)", stats.Imported, stats)
	}
	if pf.Source != upstream {
		t.Fatalf("import must keep the upstream provenance verbatim, got %q", pf.Source)
	}
	if !strings.Contains(pf.Source, "BerriAI/litellm@") || strings.Contains(strings.ToLower(pf.Source), "yabanin") {
		t.Fatalf("imported snapshot must stay attributed to its upstream source, got %q", pf.Source)
	}

	// Historical attribution remains even though no upstream pricing dataset ships.
	noticePath := filepath.Join(repoRoot(t), "pkg", "pricing", "NOTICE-litellm.txt")
	info, err := os.Lstat(noticePath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("retained NOTICE must be a regular file: %v", err)
	}
	// #nosec G304 -- fixed repository-owned NOTICE path, checked regular above; no operator input.
	notice, err := os.ReadFile(noticePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"MIT License", "Berri AI", "Permission is hereby granted"} {
		if !bytes.Contains(notice, []byte(marker)) {
			t.Fatalf("retained NOTICE lost attribution/grant marker %q", marker)
		}
	}
	refreshFound := false
	for _, tg := range targets {
		if tg.name == "pricing-refresh" {
			refreshFound = true
			if tg.prerequisites != "" {
				t.Fatalf("pricing-refresh refusal must not run prerequisites: %s", tg.prerequisites)
			}
			assertPricingRefreshRefusal(t, tg.body, notice)
		}
	}
	if !refreshFound {
		t.Fatal("explicit pricing-refresh refusal target missing")
	}
}

// Execute the actual extracted recipe without unrelated Makefile parse-time
// commands. PATH sentinels detect known fetch/import tools; this is not a
// general-purpose network sandbox.
func assertPricingRefreshRefusal(t *testing.T, recipe string, notice []byte) {
	t.Helper()
	makePath, err := exec.LookPath("make")
	if err != nil {
		t.Fatal(err)
	}
	makePath, err = filepath.Abs(makePath)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	pricingDir := filepath.Join(dir, "pkg", "pricing")
	for _, path := range []string{bin, pricingDir} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	tripwire := filepath.Join(dir, "unexpected-tool.log")
	for _, tool := range []string{"curl", "wget", "go", "git", "python", "python3", "node", "yb"} {
		// #nosec G306 -- owner-only executable sentinels in t.TempDir must run to detect tool invocation.
		if err := os.WriteFile(filepath.Join(bin, tool), []byte("#!/bin/sh\nprintf '%s\\n' \"$0\" >> \"$TRIPWIRE_LOG\"\nexit 97\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	noticePath := filepath.Join(pricingDir, "NOTICE-litellm.txt")
	// #nosec G703 -- t.TempDir plus fixed literal components; no user-controlled path or symlink.
	if err := os.WriteFile(noticePath, notice, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte(".PHONY: pricing-refresh\npricing-refresh:\n"+recipe), 0o600); err != nil {
		t.Fatal(err)
	}
	assertAbsent := func(path string) {
		t.Helper()
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("excluded data/tool output exists or cannot be checked: %s: %v", path, err)
		}
	}
	for _, name := range []string{"bundled.json", "bundled-units.json"} {
		assertAbsent(filepath.Join(pricingDir, name))
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- absolute LookPath("make") result; fixed arguments, bounded context, isolated fixture and environment.
	cmd := exec.CommandContext(ctx, makePath, "--no-print-directory", "-f", "Makefile", "pricing-refresh")
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + bin, "LC_ALL=C", "TRIPWIRE_LOG=" + tripwire}
	output, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("pricing-refresh must explicitly refuse with exit 2: %v\n%s", err, output)
	}
	for _, marker := range []string{"Bundled LiteLLM price refresh was removed", "--in", "--source", "docs/compat/litellm-migration.md"} {
		if !bytes.Contains(output, []byte(marker)) {
			t.Errorf("refresh refusal lacks operator guidance %q: %s", marker, output)
		}
	}
	assertAbsent(tripwire)
	for _, name := range []string{"bundled.json", "bundled-units.json"} {
		assertAbsent(filepath.Join(pricingDir, name))
	}
	info, err := os.Lstat(noticePath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("refresh refusal replaced retained attribution: %v", err)
	}
	// #nosec G304 -- fixed t.TempDir NOTICE path, checked regular above; verifies exact retained bytes.
	after, err := os.ReadFile(noticePath)
	if err != nil || !bytes.Equal(notice, after) {
		t.Fatalf("refresh refusal modified retained attribution: %v", err)
	}
}
