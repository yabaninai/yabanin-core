package guardhooks

// N02-P08 T04/T07/T09 behavioral pins:
//
//   - T04 offline parity: the whole free/BYO pack cycle (decode, verify,
//     compile, stage, activate, enforce, rollback) is local file+CPU work
//     with zero network dependencies, and the only egress-capable detector
//     kind degrades LOUDLY when offline (never a silent allow).
//   - T04 rollback stability: the NF-1 two-slot chain stays real across a
//     FAILED rollback (CAS conflict) — state unchanged, retry converges.
//   - T07 boundary corpus: empty pack dir, zero detectors, duplicate rule
//     ids (same and cross-pack), unicode patterns, the 64/256/1 MiB/4 MiB
//     caps at both boundaries, and the 10 000-finding cap with its
//     truncation metric driven through a real pack regex detector.
//   - T09 compatibility matrix: schema_version × runtime_api — exactly one
//     supported cell; every unsupported combination is a loud, explicit
//     error at decode (before any file work) and never stages.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
)

// p8finPack writes detector.json under root and returns the manifest bytes
// declaring it (unsigned local pack).
func p8finPack(t *testing.T, root string, detectorsJSON []byte, packID, version string) []byte {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "detector.json"), detectorsJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(detectorsJSON)
	manifest, err := json.Marshal(PackManifest{
		SchemaVersion: GuardPackManifestVersion,
		PackID:        packID, PackVersion: version, RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

// TestPackOpsOfflineParityFullCycle pins T04 offline parity: the free/BYO
// cycle — decode, digest-verify, regex compile, stage, shadow scan, activate,
// enforce, rollback — runs entirely on local files with no server, no key
// material and no egress, and pack detectors work over unicode content with
// correct byte offsets.
func TestPackOpsOfflineParityFullCycle(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "uni")
	// Unicode patterns (T07 corpus): Cyrillic and Japanese rules in one pack.
	detectorsJSON := []byte(`{"detectors":[` +
		`{"rule_id":"ru-пароль","rule_version":"1","category":"secret","pattern":"ПАРОЛЬ_[А-Я]+"},` +
		`{"rule_id":"jp-秘密","rule_version":"1","category":"secret","pattern":"パスワード"}]}`)
	manifest := p8finPack(t, root, detectorsJSON, "user.uni", "3")

	// No verifier configured: the unsigned local pack loads (free cycle).
	verified, detectors, err := LoadDetectorPackWithVerifier(root, manifest, nil)
	if err != nil {
		t.Fatalf("offline load failed: %v", err)
	}
	if verified.Digest == "" || len(detectors) != 2 {
		t.Fatalf("verified = %q, %d detectors", verified.Digest, len(detectors))
	}

	// Unicode detection with byte offsets that slice the exact substrings.
	evaluator, err := NewEvaluator(detectors...)
	if err != nil {
		t.Fatal(err)
	}
	text := "заметка: ПАРОЛЬ_ТЕСТ рядом パスワード123"
	evaluation, err := evaluator.Evaluate(Invocation{Context: ctx, Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: text})
	if err != nil {
		t.Fatal(err)
	}
	if len(evaluation.Findings) != 2 {
		t.Fatalf("findings = %d, want 2 (%#v)", len(evaluation.Findings), evaluation.Findings)
	}
	spans := make([]string, 0, len(evaluation.Findings))
	for _, f := range evaluation.Findings {
		spans = append(spans, text[f.Start:f.End])
	}
	for _, want := range []string{"ПАРОЛЬ_ТЕСТ", "パスワード"} {
		found := false
		for _, got := range spans {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("unicode finding %q not among byte-offset spans %q", want, spans)
		}
	}

	// The full lifecycle chain on a local CAS — still zero egress.
	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: root, Manifest: manifest}}); err != nil {
		t.Fatal(err)
	}
	if hits := lifecycle.ShadowHook().Scan(text); len(hits) == 0 {
		t.Fatal("shadow scan found nothing")
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if cas.from != BuiltinChainVersion || cas.to != "user.uni@3" {
		t.Fatalf("activate CAS = %q -> %q", cas.from, cas.to)
	}
	if _, _, err := lifecycle.ActiveHook().Apply(text); !errors.Is(err, ErrDenied) {
		t.Fatalf("activated pack must enforce offline: %v", err)
	}
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := lifecycle.ActiveHook().Apply(text); err != nil {
		t.Fatalf("rollback must restore the built-in chain (unicode text is not a built-in finding): %v", err)
	}
}

// TestPackHTTPDetectorOfflineFailsLoud pins the offline boundary for the only
// egress-capable detector kind: an unreachable endpoint is an explicit error,
// mapped by FailureOutcome to deny+blocked (enforce) and audit-only+forward
// (shadow) — never a silent allow.
func TestPackHTTPDetectorOfflineFailsLoud(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint, client := server.URL, server.Client()
	server.Close() // the endpoint is now offline (connection refused)

	detector, err := NewHTTPDetector(HTTPDetectorConfig{
		Identity: RuleVersion{PackID: "user.remote", PackVersion: "1", RuleID: "r", RuleVersion: "1"},
		Endpoint: endpoint, Hosts: []string{"127.0.0.1"}, Client: client,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = detector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"})
	if err == nil {
		t.Fatal("offline remote detector must fail loudly")
	}
	if verdict, blocked := FailureOutcome(FailureModeEnforce, err); verdict != VerdictDeny || !blocked {
		t.Fatalf("enforce outcome = (%s, %v), want (deny, true)", verdict, blocked)
	}
	if verdict, blocked := FailureOutcome(FailureModeShadow, err); verdict != VerdictAuditOnly || blocked {
		t.Fatalf("shadow outcome = (%s, %v), want (audit-only, false)", verdict, blocked)
	}
}

// TestPackLifecycleRollbackSurvivesCASConflict pins T04 rollback stability
// beyond NF-1: a rollback whose durable CAS fails (store unavailable) leaves
// the two-slot history and enforcement EXACTLY as they were; after the store
// heals, the retry converges and the NF-1 chain (real second rollback) still
// holds.
func TestPackLifecycleRollbackSurvivesCASConflict(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()
	rootA := filepath.Join(base, "alpha")
	manifestA := secondRollbackPack(t, rootA, "user.alpha", "ARB_NF1_[A-Z]+")
	rootB := filepath.Join(base, "beta")
	manifestB := secondRollbackPack(t, rootB, "user.beta", "BRB_NF1_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}

	// Interrupted rollback: the durable CAS fails BEFORE any state swap.
	cas.err = errors.New("durable store unavailable")
	if err := lifecycle.Rollback(ctx); err == nil {
		t.Fatal("rollback must surface the CAS failure")
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "BRB", "ARB", "BRB")
	if got := lifecycle.StagedVersion(); got != "" {
		t.Fatalf("failed rollback must not resurrect a candidate, staged %q", got)
	}

	// Retry after the store heals: same transition, and the two-slot chain
	// stays real in both directions (NF-1 semantics preserved).
	cas.err = nil
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("rollback retry: %v", err)
	}
	if cas.from != "user.beta@1" || cas.to != "user.alpha@1" {
		t.Fatalf("retried rollback CAS = %q -> %q", cas.from, cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "ARB", "ARB", "BRB")
	if err := lifecycle.Rollback(ctx); err != nil {
		t.Fatalf("second rollback after the interrupted attempt: %v", err)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "BRB", "ARB", "BRB")
}

// TestPackActivateDoubleActivationNoSideEffects pins the no-double-activation
// contract at the lifecycle level: a second Activate without a fresh candidate
// is refused with no extra CAS write, and a failed (CAS-error) activation
// keeps the candidate staged so the operator retry converges to exactly one
// durable transition.
func TestPackActivateDoubleActivationNoSideEffects(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "alpha")
	manifest := secondRollbackPack(t, root, "user.alpha", "ADBL_NF1_[A-Z]+")

	cas := &lifecycleCAS{}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, cas)
	if _, err := lifecycle.StageSources([]PackSource{{Root: root, Manifest: manifest}}); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.Activate(ctx); err == nil || !strings.Contains(err.Error(), "no staged pack") {
		t.Fatalf("second activate without staging must be refused, got %v", err)
	}
	if cas.from != BuiltinChainVersion || cas.to != "user.alpha@1" {
		t.Fatalf("CAS log = %q -> %q, want exactly one transition", cas.from, cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "ADBL", "ADBL")

	// Interrupted activation (CAS error): nothing swaps, candidate preserved.
	rootB := filepath.Join(t.TempDir(), "beta")
	manifestB := secondRollbackPack(t, rootB, "user.beta", "BDBL_NF1_[A-Z]+")
	if _, err := lifecycle.StageSources([]PackSource{{Root: rootB, Manifest: manifestB}}); err != nil {
		t.Fatal(err)
	}
	cas.err = errors.New("CAS unavailable")
	if err := lifecycle.Activate(ctx); err == nil {
		t.Fatal("CAS failure must surface")
	}
	if got := lifecycle.StagedVersion(); got != "user.beta@1" {
		t.Fatalf("interrupted activation must keep the candidate staged, got %q", got)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "ADBL", "ADBL", "BDBL")
	// Retry converges: exactly one more durable transition.
	cas.err = nil
	if err := lifecycle.Activate(ctx); err != nil {
		t.Fatalf("activation retry: %v", err)
	}
	if cas.from != "user.alpha@1" || cas.to != "user.beta@1" {
		t.Fatalf("retry CAS = %q -> %q", cas.from, cas.to)
	}
	assertSecondRollbackEnforcement(t, lifecycle.ActiveHook(), "BDBL", "ADBL", "BDBL")
}

// TestPackBoundaryCorpus is the T07 lifecycle boundary corpus. Every edge is
// a loud rejection (or an exact at-limit acceptance) — nothing degrades to a
// partial load or a silent skip.
func TestPackBoundaryCorpus(t *testing.T) {
	ctx := context.Background()
	t.Run("empty pack dir", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "empty")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		manifest := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "user.empty", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}}}
		data, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := LoadDetectorPack(root, data); err == nil {
			t.Fatal("an empty pack directory must be a loud load failure")
		}
	})
	t.Run("zero detectors", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "zero")
		manifest := p8finPack(t, root, []byte(`{"detectors":[]}`), "user.zero", "1")
		lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, &lifecycleCAS{})
		if _, err := lifecycle.StageSources([]PackSource{{Root: root, Manifest: manifest}}); err == nil || !strings.Contains(err.Error(), "no detectors") {
			t.Fatalf("zero-detector pack must be refused with an explicit error, got %v", err)
		}
		if lifecycle.ShadowHook() != nil {
			t.Fatal("a refused pack must not publish a shadow hook")
		}
		if err := lifecycle.Activate(ctx); err == nil {
			t.Fatal("nothing may be activatable after a refused stage")
		}
	})
	t.Run("duplicate rule ids", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "dup")
		same := []byte(`{"detectors":[` +
			`{"rule_id":"r0","rule_version":"1","category":"secret","pattern":"DUP_A_[A-Z]+"},` +
			`{"rule_id":"r0","rule_version":"1","category":"secret","pattern":"DUP_B_[A-Z]+"}]}`)
		if _, _, err := LoadDetectorPack(root, p8finPack(t, root, same, "user.dup", "1")); err == nil || !strings.Contains(err.Error(), "duplicate detector") {
			t.Fatalf("same rule_id+rule_version must be a loud duplicate error, got %v", err)
		}
		// Distinct rule_version under the same rule_id is a distinct identity:
		// the documented contract keeps both detectors.
		versions := []byte(`{"detectors":[` +
			`{"rule_id":"r0","rule_version":"1","category":"secret","pattern":"DUPV_ONE_[A-Z]+"},` +
			`{"rule_id":"r0","rule_version":"2","category":"secret","pattern":"DUPV_TWO_[A-Z]+"}]}`)
		_, detectors, err := LoadDetectorPack(root, p8finPack(t, root, versions, "user.dup", "1"))
		if err != nil || len(detectors) != 2 {
			t.Fatalf("distinct rule versions must coexist: %v (%d)", err, len(detectors))
		}
	})
	t.Run("duplicate rule ids across packs", func(t *testing.T) {
		base := t.TempDir()
		rootA := filepath.Join(base, "a")
		manifestA := p8finPack(t, rootA, []byte(`{"detectors":[{"rule_id":"shared","rule_version":"1","category":"secret","pattern":"XSHARE_[A-Z]+"}]}`), "user.same", "1")
		rootB := filepath.Join(base, "b")
		manifestB := p8finPack(t, rootB, []byte(`{"detectors":[{"rule_id":"shared","rule_version":"1","category":"secret","pattern":"YSHARE_[A-Z]+"}]}`), "user.same", "1")
		lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, &lifecycleCAS{})
		_, err := lifecycle.StageSources([]PackSource{{Root: rootA, Manifest: manifestA}, {Root: rootB, Manifest: manifestB}})
		if err == nil || !strings.Contains(err.Error(), "duplicate detector") {
			t.Fatalf("colliding identities across sources must fail the whole candidate loudly, got %v", err)
		}
		if lifecycle.ShadowHook() != nil {
			t.Fatal("a failed multi-pack stage must not publish a shadow hook")
		}
	})
	t.Run("unicode patterns", func(t *testing.T) {
		// Covered end-to-end by TestPackOpsOfflineParityFullCycle; this cell
		// pins the corpus edge itself: an emoji/class boundary pattern.
		root := filepath.Join(t.TempDir(), "emoji")
		manifest := p8finPack(t, root, []byte(`{"detectors":[{"rule_id":"emoji","rule_version":"1","category":"secret","pattern":"🔒_[А-Я]+"}]}`), "user.emoji", "1")
		_, detectors, err := LoadDetectorPack(root, manifest)
		if err != nil || len(detectors) != 1 {
			t.Fatalf("unicode pattern must compile: %v", err)
		}
		text := " leak 🔒_СЕКРЕТ end"
		evaluation, err := mustEvaluator(t, detectors...).Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: text})
		if err != nil || len(evaluation.Findings) != 1 || text[evaluation.Findings[0].Start:evaluation.Findings[0].End] != "🔒_СЕКРЕТ" {
			t.Fatalf("emoji+Cyrillic span = %#v, %v", evaluation.Findings, err)
		}
	})
	t.Run("manifest cap 1MiB at both boundaries", func(t *testing.T) {
		prefix := `{"schema_version":"guardpacks.v1","pack_id":"`
		suffix := `","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"detector.json","sha256":"` + strings.Repeat("0", 64) + `"}]}`
		padLen := MaxPackManifestBytes - len(prefix) - len(suffix)
		if padLen <= 0 {
			t.Fatalf("fixture geometry broken: pad %d", padLen)
		}
		exact := []byte(prefix + strings.Repeat("a", padLen) + suffix)
		if len(exact) != MaxPackManifestBytes {
			t.Fatalf("fixture length %d, want exactly %d", len(exact), MaxPackManifestBytes)
		}
		if _, err := DecodePackManifest(exact); err != nil {
			t.Fatalf("a manifest exactly at the 1 MiB cap must decode: %v", err)
		}
		_, err := DecodePackManifest([]byte(prefix + strings.Repeat("a", padLen+1) + suffix))
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("one byte over the cap must be rejected, got %v", err)
		}
	})
	t.Run("detector file cap 4MiB at both boundaries", func(t *testing.T) {
		spec := []byte(`{"detectors":[{"rule_id":"big","rule_version":"1","category":"secret","pattern":"BIG4M_[A-Z]+"}]}`)
		pad := MaxDetectorFileBytes - len(spec)
		if pad <= 0 {
			t.Fatalf("fixture geometry broken: pad %d", pad)
		}
		root := filepath.Join(t.TempDir(), "big")
		manifest := p8finPack(t, root, append(append([]byte(nil), spec...), []byte(strings.Repeat(" ", pad))...), "user.big", "1")
		_, detectors, err := LoadDetectorPack(root, manifest)
		if err != nil || len(detectors) != 1 {
			t.Fatalf("a detector.json exactly at the 4 MiB cap must load: %v", err)
		}
		if _, _, applyErr := NewWithEvaluator(ModeDeny, mustEvaluator(t, detectors...)).Apply("BIG4M_VALUE"); !errors.Is(applyErr, ErrDenied) {
			t.Fatalf("at-limit pack must enforce: %v", applyErr)
		}
		// One byte over: rejected before decoding.
		overRoot := filepath.Join(t.TempDir(), "over")
		manifest = p8finPack(t, overRoot, append(append([]byte(nil), spec...), []byte(strings.Repeat(" ", pad+1))...), "user.big", "1")
		if _, _, err := LoadDetectorPack(overRoot, manifest); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("one byte over the 4 MiB cap must be rejected, got %v", err)
		}
	})
	t.Run("detector cap 256 at the boundary", func(t *testing.T) {
		specs := make([]map[string]string, MaxDetectorsPerPack)
		probe := make([]string, MaxDetectorsPerPack)
		for i := range specs {
			specs[i] = map[string]string{
				"rule_id": "r" + strconv.Itoa(i), "rule_version": "1",
				"category": "secret", "pattern": fmt.Sprintf("R%d_BND256_[A-Z]+", i),
			}
			probe[i] = fmt.Sprintf("R%d_BND256_VALUE", i)
		}
		content, err := json.Marshal(map[string]any{"detectors": specs})
		if err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(t.TempDir(), "cap256")
		manifest := p8finPack(t, root, content, "user.cap256", "1")
		_, detectors, err := LoadDetectorPack(root, manifest)
		if err != nil || len(detectors) != MaxDetectorsPerPack {
			t.Fatalf("a pack exactly at the %d-detector cap must load: %v (%d)", MaxDetectorsPerPack, err, len(detectors))
		}
		evaluation, err := mustEvaluator(t, detectors...).Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: strings.Join(probe, " ")})
		if err != nil {
			t.Fatal(err)
		}
		if len(evaluation.Findings) != MaxDetectorsPerPack {
			t.Fatalf("all %d at-limit detectors must enforce, got %d findings", MaxDetectorsPerPack, len(evaluation.Findings))
		}
	})
	t.Run("findings cap 10000 with truncation metric through a pack regex", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "bulk")
		manifest := p8finPack(t, root, []byte(`{"detectors":[{"rule_id":"bulk","rule_version":"1","category":"secret","pattern":"x"}]}`), "user.bulk", "1")
		_, detectors, err := LoadDetectorPack(root, manifest)
		if err != nil || len(detectors) != 1 {
			t.Fatalf("bulk pack load: %v", err)
		}
		evaluator, err := NewEvaluator(detectors...)
		if err != nil {
			t.Fatal(err)
		}
		before := testutil.ToFloat64(metrics.GuardFindingsTruncatedTotal)
		result, err := evaluator.Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: strings.Repeat("x", MaxFindingsPerDetection+1)})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(result.Findings); got != MaxFindingsPerDetection {
			t.Fatalf("pack regex findings = %d, want capped at %d", got, MaxFindingsPerDetection)
		}
		if delta := testutil.ToFloat64(metrics.GuardFindingsTruncatedTotal) - before; delta != 1 {
			t.Fatalf("truncation metric delta = %v, want 1", delta)
		}
	})
}

func mustEvaluator(t *testing.T, detectors ...VersionedDetector) *Evaluator {
	t.Helper()
	evaluator, err := NewEvaluator(detectors...)
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

// TestPackManifestCompatMatrix pins T09: exactly one supported
// schema_version × runtime_api cell; every old/new/unknown combination is a
// loud, specific decode error before any file is opened, and an incompatible
// pack never stages (nothing to activate).
func TestPackManifestCompatMatrix(t *testing.T) {
	schemaCells := []string{GuardPackManifestVersion, "guardpacks.v0", "guardpacks.v2", "", "guardpacks.v9-future"}
	runtimeCells := []string{RuntimeVersion, "guardrails.v0", "guardrails.v2", "", "guardrails.v999"}
	for _, schema := range schemaCells {
		for _, runtimeAPI := range runtimeCells {
			name := fmt.Sprintf("schema=%q runtime=%q", schema, runtimeAPI)
			t.Run(name, func(t *testing.T) {
				data, err := json.Marshal(PackManifest{
					SchemaVersion: schema, PackID: "user.compat", PackVersion: "1", RuntimeAPI: runtimeAPI,
					Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}},
				})
				if err != nil {
					t.Fatal(err)
				}
				_, err = DecodePackManifestWithVerifier(data, nil)
				supported := schema == GuardPackManifestVersion && runtimeAPI == RuntimeVersion
				if supported && err != nil {
					t.Fatalf("the single supported cell must decode: %v", err)
				}
				if !supported && err == nil {
					t.Fatal("unsupported cell must be rejected loudly")
				}
				if !supported {
					if schema != GuardPackManifestVersion && !strings.Contains(err.Error(), "incompatible schema version") {
						t.Fatalf("schema rejection must name the cause: %v", err)
					}
					if schema == GuardPackManifestVersion && !strings.Contains(err.Error(), "incompatible runtime API") {
						t.Fatalf("runtime rejection must name the cause: %v", err)
					}
				}
			})
		}
	}

	// End to end: an incompatible pack with perfectly valid files is refused
	// by the loader and never becomes a staged candidate.
	root := filepath.Join(t.TempDir(), "incompat")
	goodJSON := []byte(`{"detectors":[{"rule_id":"r","rule_version":"1","category":"secret","pattern":"INCOMPAT_[A-Z]+"}]}`)
	sum := sha256.Sum256(goodJSON)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "detector.json"), goodJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	incompatible, err := json.Marshal(PackManifest{
		SchemaVersion: GuardPackManifestVersion, PackID: "user.incompat", PackVersion: "1", RuntimeAPI: "guardrails.v2",
		Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDetectorPack(root, incompatible); err == nil || !strings.Contains(err.Error(), "incompatible runtime API") {
		t.Fatalf("loader must refuse the incompatible runtime loudly, got %v", err)
	}
	lifecycle := NewPackLifecycle(BuiltinChainVersion, ModeDeny, &lifecycleCAS{})
	if _, err := lifecycle.StageSources([]PackSource{{Root: root, Manifest: incompatible}}); err == nil {
		t.Fatal("an incompatible pack must never stage")
	}
	if lifecycle.ShadowHook() != nil {
		t.Fatal("an incompatible pack must not publish a shadow hook")
	}
	if err := lifecycle.Activate(context.Background()); err == nil {
		t.Fatal("an incompatible pack must leave nothing activatable")
	}
}
