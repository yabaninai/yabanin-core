package guardhooks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/reireirei/yabanin/pkg/metrics"
)

func TestDecodeAndVerifyPackOffline(t *testing.T) {
	root := t.TempDir()
	content := []byte("user detector payload")
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifestBytes, err := json.Marshal(PackManifest{
		SchemaVersion: GuardPackManifestVersion,
		PackID:        "custom.rules", PackVersion: "1.0.0", RuntimeAPI: RuntimeVersion,
		Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := DecodePackManifest(manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyPack(root, manifest)
	if err != nil || verified.Digest == "" {
		t.Fatalf("VerifyPack() = %#v, %v", verified, err)
	}
	if err := os.WriteFile(filepath.Join(root, "detector.json"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPack(root, manifest); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("expected hash mismatch, got %v", err)
	}
}

func TestPackLoadRejectsOversizedInputs(t *testing.T) {
	if _, err := DecodePackManifest(bytes.Repeat([]byte("x"), MaxPackManifestBytes+1)); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized manifest error=%v", err)
	}
	root := t.TempDir()
	content := bytes.Repeat([]byte(" "), MaxDetectorFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "oversized", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}}}
	if _, err := VerifyPack(root, manifest); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized detector verification error=%v", err)
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDetectorPack(root, manifestBytes); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized detector load error=%v", err)
	}
}

func TestEvaluatorCapsFindingsPerDetection(t *testing.T) {
	detector := bulkTestDetector{findings: make([]Finding, MaxFindingsPerDetection+1)}
	for i := range detector.findings {
		detector.findings[i] = Finding{Category: CatSecret, Start: 0, End: 1}
	}
	evaluator, err := NewEvaluator(detector)
	if err != nil {
		t.Fatal(err)
	}
	before := testutil.ToFloat64(metrics.GuardFindingsTruncatedTotal)
	result, err := evaluator.Evaluate(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.Findings); got != MaxFindingsPerDetection {
		t.Fatalf("findings=%d, want capped at %d", got, MaxFindingsPerDetection)
	}
	if delta := testutil.ToFloat64(metrics.GuardFindingsTruncatedTotal) - before; delta != 1 {
		t.Fatalf("guard_findings_truncated_total delta = %v, want 1", delta)
	}
}

type bulkTestDetector struct{ findings []Finding }

func (bulkTestDetector) Identity() RuleVersion {
	return RuleVersion{PackID: "test", PackVersion: "1", RuleID: "bulk", RuleVersion: "1"}
}
func (d bulkTestDetector) Detect(Invocation) ([]Finding, error) { return d.findings, nil }

func TestDecodePackManifestRejectsBadAndIncompatibleManifests(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":"wrong","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"unsupported","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"../escape","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","unknown":true,"files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"bad"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"},{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]}`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"},{"path":"y","sha256":"` + strings.Repeat("0", 64) + `"}]`,
		`{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[]}`,
	} {
		if _, err := DecodePackManifest([]byte(input)); err == nil {
			t.Fatalf("expected manifest rejection for %s", input)
		}
	}
}

func TestDecodePackManifestSignaturePolicy(t *testing.T) {
	base := `"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]`
	unsigned, err := DecodePackManifest([]byte("{" + base + "}"))
	if err != nil || unsigned.Signature != nil {
		t.Fatalf("unsigned local pack should load: %#v, %v", unsigned, err)
	}
	signed := `{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}],"signature":{"key_id":"bogus","algorithm":"bogus","value":"garbage"}}`
	if _, err := DecodePackManifest([]byte(signed)); err == nil || !strings.Contains(err.Error(), "signature declared but no verifier configured") {
		t.Fatalf("signed manifest without verifier must fail explicitly: %v", err)
	}
}

func TestVerifyPackRejectsMissingAndEscapingFiles(t *testing.T) {
	root := t.TempDir()
	valid := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "missing", SHA256: strings.Repeat("0", 64)}}}
	if _, err := VerifyPack(root, valid); err == nil || !strings.Contains(err.Error(), "file") {
		t.Fatalf("expected missing file error, got %v", err)
	}
	if _, err := VerifyPack(root, PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "../outside", SHA256: strings.Repeat("0", 64)}}}); err == nil {
		t.Fatal("expected traversal path rejection")
	}
	if _, err := VerifyPack(filepath.Join(root, "missing-root"), valid); err == nil {
		t.Fatal("expected invalid root error")
	}
}

func TestVerifyPackRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	sum := sha256.Sum256([]byte("x"))
	manifest := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "link", SHA256: hex.EncodeToString(sum[:])}}}
	if _, err := VerifyPack(root, manifest); err == nil || !strings.Contains(err.Error(), "escapes pack root") {
		t.Fatalf("expected symlink escape rejection, got %v", err)
	}
}

// TestDecodePackManifestRejectsTooManyFiles pins the file-count cap: a
// manifest at the limit still decodes, one more entry is rejected cheaply at
// decode time instead of costing one open+hash per entry during verification.
func TestDecodePackManifestRejectsTooManyFiles(t *testing.T) {
	build := func(n int) []byte {
		files := make([]PackFile, n)
		for i := range files {
			files[i] = PackFile{Path: "d" + strconv.Itoa(i) + "/file", SHA256: strings.Repeat("0", 64)}
		}
		data, err := json.Marshal(PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: files})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if _, err := DecodePackManifest(build(MaxPackManifestFiles)); err != nil {
		t.Fatalf("manifest at the file limit must decode: %v", err)
	}
	_, err := DecodePackManifest(build(MaxPackManifestFiles + 1))
	if err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("expected file-count limit rejection, got %v", err)
	}
}

// TestLoadDetectorPackRejectsMultiFileManifestBeforeVerification pins the
// pack-shape check running before VerifyPack: a multi-file manifest is
// rejected by shape even when the extra file does not exist on disk, so
// hostile manifests cannot spend verification work.
func TestLoadDetectorPackRejectsMultiFileManifestBeforeVerification(t *testing.T) {
	root := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"r","rule_version":"1","category":"secret","pattern":"MULTI_FILE_[A-Z]+"}]}`)
	if err := os.WriteFile(filepath.Join(root, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	manifest := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{
		{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])},
		// extra.bin does not exist; if the shape check ran after VerifyPack,
		// the missing-file error would surface instead.
		{Path: "extra.bin", SHA256: strings.Repeat("0", 64)},
	}}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadDetectorPack(root, data); err == nil || !strings.Contains(err.Error(), "exactly one detector.json") {
		t.Fatalf("expected shape rejection before verification, got %v", err)
	}
}
