package catalogs

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// TestNebiusBridgeFromCommittedRecord pins the bridge output over the
// committed verified record: 3 active verified-primary arms + 2 retired
// avoid entries, deterministic order, dated evidence everywhere.
func TestNebiusBridgeFromCommittedRecord(t *testing.T) {
	record := readCorpusFile(t, NebiusRecordPath)
	entries, err := NebiusEntries(record)
	if err != nil {
		t.Fatalf("NebiusEntries: %v", err)
	}
	if len(entries) != 5 {
		t.Fatalf("entries = %d, want 5 (3 arms + 2 avoids)", len(entries))
	}

	// Deterministic order: two bridge runs agree exactly.
	again, err := NebiusEntries(record)
	if err != nil {
		t.Fatalf("NebiusEntries (2nd): %v", err)
	}
	if !reflect.DeepEqual(entries, again) {
		t.Fatal("bridge output must be deterministic (map iteration must not leak into ordering)")
	}

	byModel := make(map[string]pricing.RefModel, len(entries))
	for _, m := range entries {
		byModel[m.Model] = m
	}

	// G1 anchor arm.
	g1, ok := byModel["zai-org/GLM-5.2"]
	if !ok {
		t.Fatal("G1 arm missing")
	}
	if g1.Status != pricing.RefStatusActive || g1.Reviewer != NebiusEntryReviewer {
		t.Fatalf("G1 = %s/%s, want active/%s", g1.Status, g1.Reviewer, NebiusEntryReviewer)
	}
	if g1.EffectiveFrom != "2026-06-01" || g1.VerifiedAt != "2026-09-08" {
		t.Fatalf("G1 window/verification = %s/@%s, want 2026-06-01/@2026-09-08", g1.EffectiveFrom, g1.VerifiedAt)
	}
	if in, priced := pricing.RateAmount(g1, pricing.AxisInput); !priced || in != 1.4 {
		t.Fatalf("G1 input = %v priced=%v, want 1.4", in, priced)
	}
	if out, priced := pricing.RateAmount(g1, pricing.AxisOutput); !priced || out != 4.4 {
		t.Fatalf("G1 output = %v priced=%v, want 4.4", out, priced)
	}
	if len(g1.Aliases) != 1 || g1.Aliases[0] != "GLM-5.2" {
		t.Fatalf("G1 aliases = %v, want [GLM-5.2] (billing name)", g1.Aliases)
	}

	// G2 cheap candidate, same family.
	g2, ok := byModel["zai-org/GLM-5.3-Flash"]
	if !ok {
		t.Fatal("G2 arm missing")
	}
	if g2.EffectiveFrom != "2026-08-01" {
		t.Fatalf("G2 effective_from = %q, want 2026-08-01", g2.EffectiveFrom)
	}
	if in, priced := pricing.RateAmount(g2, pricing.AxisInput); !priced || in != 0.15 {
		t.Fatalf("G2 input = %v priced=%v, want 0.15", in, priced)
	}
	if out, priced := pricing.RateAmount(g2, pricing.AxisOutput); !priced || out != 0.5 {
		t.Fatalf("G2 output = %v priced=%v, want 0.5", out, priced)
	}
	if len(g2.Aliases) != 1 || g2.Aliases[0] != "GLM-5.3 Flash" {
		t.Fatalf("G2 aliases = %v, want [GLM-5.3 Flash]", g2.Aliases)
	}

	// G2_ALT cross-family alternative; billing line lacks the -0731 suffix.
	alt, ok := byModel["deepseek-ai/DeepSeek-V4-Flash-0731"]
	if !ok {
		t.Fatal("G2_ALT arm missing")
	}
	if len(alt.Aliases) != 1 || alt.Aliases[0] != "DeepSeek-V4-Flash" {
		t.Fatalf("G2_ALT aliases = %v, want [DeepSeek-V4-Flash] (billed string without suffix)", alt.Aliases)
	}
	caveat := false
	for _, s := range alt.Sources {
		if strings.Contains(s.Note, "billing-name caveat") {
			caveat = true
		}
	}
	if !caveat {
		t.Fatal("G2_ALT must carry the billing-name caveat in its source note")
	}

	// All arms: USD, per-1M-token units, dated evidence per axis, verified
	// source record naming the in-repo evidence path.
	for name, m := range byModel {
		if m.Status != pricing.RefStatusActive {
			continue
		}
		if m.Currency != "USD" {
			t.Fatalf("%s: currency %q, want USD", name, m.Currency)
		}
		for _, r := range m.Rates {
			if r.Unit != pricing.RefUnitPer1MTokens {
				t.Fatalf("%s axis %s unit = %q, want %q", name, r.Axis, r.Unit, pricing.RefUnitPer1MTokens)
			}
			if len(r.Evidence) != 1 || r.Evidence[0].Ref != NebiusEvidencePrefix+"2026-09-08" {
				t.Fatalf("%s axis %s evidence = %+v, want one %s2026-09-08 observation", name, r.Axis, r.Evidence, NebiusEvidencePrefix)
			}
		}
		srcOK := false
		for _, s := range m.Sources {
			if s.Kind == pricing.RefSourceInternalEvidence &&
				strings.HasPrefix(s.Ref, NebiusEvidencePrefix) &&
				strings.Contains(s.Note, NebiusRecordPath) {
				srcOK = true
			}
		}
		if !srcOK {
			t.Fatalf("%s must cite the internal evidence record %s", name, NebiusRecordPath)
		}
	}

	// Avoid list: retired deprecations with the stated window, no rates.
	avoid1, ok := byModel["meta-llama/Llama-3.3-70B-Instruct"]
	if !ok {
		t.Fatal("avoid entry meta-llama/Llama-3.3-70B-Instruct missing")
	}
	avoid2, ok := byModel["deepseek-ai/DeepSeek-V4-Flash"]
	if !ok {
		t.Fatal("avoid entry deepseek-ai/DeepSeek-V4-Flash missing")
	}
	for name, m := range map[string]pricing.RefModel{"avoid1": avoid1, "avoid2": avoid2} {
		if m.Status != pricing.RefStatusRetired {
			t.Fatalf("%s status = %q, want retired", name, m.Status)
		}
		if len(m.Rates) != 0 {
			t.Fatalf("%s must carry no rates, got %d", name, len(m.Rates))
		}
		if m.EffectiveTo != "2026-08-31" {
			t.Fatalf("%s effective_to = %q, want 2026-08-31 (stated deprecation date)", name, m.EffectiveTo)
		}
	}
}

// mutateRecord round-trips the record through a map, applies fn, and
// re-marshals: targeted field mutations for refusal tests.
func mutateRecord(t *testing.T, record []byte, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(record, &m); err != nil {
		t.Fatalf("unmarshal record: %v", err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal record: %v", err)
	}
	return out
}

// TestNebiusBridgeRefusals pins the fail-closed refusals: the bridge must
// never smuggle unverified or not-actually-free data into the catalog.
func TestNebiusBridgeRefusals(t *testing.T) {
	record := readCorpusFile(t, NebiusRecordPath)

	cases := []struct {
		name    string
		mutate  func(m map[string]any)
		wantErr string
	}{
		{
			name: "unverified status",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G1"].(map[string]any)
				arm["prices_status"] = "TO_VERIFY_CONSOLE"
			},
			wantErr: "refusing to bridge as verified",
		},
		{
			name: "missing status",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G1"].(map[string]any)
				delete(arm, "prices_status")
			},
			wantErr: "refusing to bridge as verified",
		},
		{
			name: "zero price",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G2"].(map[string]any)
				arm["prices_usd_per_1m"].(map[string]any)["input"] = 0
			},
			wantErr: "not a positive verified amount",
		},
		{
			name: "negative price",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G2"].(map[string]any)
				arm["prices_usd_per_1m"].(map[string]any)["output"] = -0.5
			},
			wantErr: "not a positive verified amount",
		},
		{
			name: "missing prices",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G1"].(map[string]any)
				delete(arm, "prices_usd_per_1m")
			},
			wantErr: "refusing to bridge an unpriced arm",
		},
		{
			name: "missing effective_from",
			mutate: func(m map[string]any) {
				arm := m["arms"].(map[string]any)["G1"].(map[string]any)
				delete(arm, "prices_effective_from")
			},
			wantErr: "prices_effective_from is required",
		},
		{
			name: "unsupported record schema",
			mutate: func(m map[string]any) {
				m["schema_version"] = 2
			},
			wantErr: "unsupported schema_version",
		},
		{
			name: "missing evidence attribution",
			mutate: func(m map[string]any) {
				delete(m, "prices_source")
			},
			wantErr: "prices_source is required",
		},
		{
			name: "missing provider",
			mutate: func(m map[string]any) {
				delete(m, "provider")
			},
			wantErr: "provider is required",
		},
		{
			name: "avoid without reason",
			mutate: func(m map[string]any) {
				av := m["avoid"].([]any)[0].(map[string]any)
				delete(av, "reason")
			},
			wantErr: "reason is required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NebiusEntries(mutateRecord(t, record, tc.mutate))
			if err == nil {
				t.Fatalf("expected refusal (%s), got success", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}
