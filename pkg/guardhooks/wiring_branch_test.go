package guardhooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNilLifecycleStageReportsError pins the nil-receiver guards of the
// multi-pack staging entry point: a nil lifecycle is an explicit error, and
// stagedVersion on nil or never-staged lifecycles is the empty version, never
// a panic.
func TestNilLifecycleStageReportsError(t *testing.T) {
	var nilLifecycle *PackLifecycle
	if _, err := nilLifecycle.StageSources(nil); err == nil || !strings.Contains(err.Error(), "nil lifecycle") {
		t.Fatalf("nil lifecycle stage must fail explicitly, got %v", err)
	}
	if got := nilLifecycle.stagedVersion(); got != "" {
		t.Fatalf("nil lifecycle stagedVersion = %q, want empty", got)
	}
	fresh := NewPackLifecycle("1", ModeDeny, &lifecycleCAS{})
	if got := fresh.stagedVersion(); got != "" {
		t.Fatalf("unstaged lifecycle stagedVersion = %q, want empty", got)
	}
}

// TestRollbackRequiresPolicyAndFailsClosedOnCAS pins the rollback contract:
// a lifecycle without a policy CAS refuses to roll back, and a failing CAS
// leaves the active pack enforcing (fail closed, no partial state).
func TestRollbackRequiresPolicyAndFailsClosedOnCAS(t *testing.T) {
	root, manifest := writeLifecyclePack(t)

	noPolicy := NewPackLifecycle("1", ModeDeny, nil)
	if _, err := noPolicy.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	if err := noPolicy.Activate(context.Background()); err == nil || !strings.Contains(err.Error(), "policy CAS API is not configured") {
		t.Fatalf("activate without policy CAS must refuse, got %v", err)
	}
	if err := noPolicy.Rollback(context.Background()); err == nil {
		t.Fatal("rollback without an active pack must refuse")
	}

	cas := &lifecycleCAS{err: errors.New("cas unavailable")}
	lifecycle := NewPackLifecycle("1", ModeDeny, cas)
	if _, err := lifecycle.Stage(root, manifest); err != nil {
		t.Fatal(err)
	}
	cas.err = nil
	if err := lifecycle.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	cas.err = errors.New("cas unavailable")
	if _, hits, err := lifecycle.ActiveHook().Apply("PACK_SECRET_VALUE"); err != ErrDenied {
		t.Fatalf("active pack must keep enforcing before rollback: %#v, %v", hits, err)
	}
	err := lifecycle.Rollback(context.Background())
	if err == nil || !strings.Contains(err.Error(), "policy CAS") {
		t.Fatalf("rollback with failing CAS must fail explicitly, got %v", err)
	}
	if _, hits, err := lifecycle.ActiveHook().Apply("PACK_SECRET_VALUE"); err != ErrDenied {
		t.Fatalf("failed rollback must leave the active pack enforcing: %#v, %v", hits, err)
	}
}

// TestDecodePackManifestSignatureVerifierPaths covers both verifier outcomes
// for a declared signature: a verifying verifier accepts the manifest, and a
// failing verifier rejects it with the explicit verification error.
func TestDecodePackManifestSignatureVerifierPaths(t *testing.T) {
	base := `{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}],"signature":{"version":"guardpack-sig.v1","key_id":"k","algorithm":"ed25519","value":"c2ln"}}`

	accepting := okVerifier{}
	if _, err := DecodePackManifestWithVerifier([]byte(base), accepting); err != nil {
		t.Fatalf("verifier-accepted signature must load, got %v", err)
	}

	rejecting := errVerifier{err: errors.New("untrusted key")}
	if _, err := DecodePackManifestWithVerifier([]byte(base), rejecting); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("failing verifier must reject the manifest, got %v", err)
	}
}

type okVerifier struct{}

func (okVerifier) Verify(PackManifest, []byte) error { return nil }

type errVerifier struct{ err error }

func (v errVerifier) Verify(PackManifest, []byte) error { return v.err }

// TestDecodePackManifestRejectsTrailingData pins the strict single-document
// manifest contract: trailing JSON after the manifest object is rejected
// instead of silently ignored.
func TestDecodePackManifestRejectsTrailingData(t *testing.T) {
	manifest := `{"schema_version":"guardpacks.v1","pack_id":"p","pack_version":"1","runtime_api":"guardrails.v1","files":[{"path":"x","sha256":"` + strings.Repeat("0", 64) + `"}]} {"trailing":true}`
	if _, err := DecodePackManifest([]byte(manifest)); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("trailing JSON must be rejected, got %v", err)
	}
}

// TestVerifyPackRejectsInvalidOversizedAndDuplicateManifests covers the
// verification entry checks directly: an incompatible manifest, an encoded
// manifest beyond the size cap, duplicate file entries, and non-canonical
// relative paths are all rejected before any file is opened.
func TestVerifyPackRejectsInvalidOversizedAndDuplicateManifests(t *testing.T) {
	if _, err := VerifyPack(t.TempDir(), PackManifest{}); err == nil || !strings.Contains(err.Error(), "invalid or incompatible") {
		t.Fatalf("empty manifest must be rejected, got %v", err)
	}
	oversized := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: strings.Repeat("p", MaxPackManifestBytes), PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}}}
	if _, err := VerifyPack(t.TempDir(), oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized manifest must be rejected, got %v", err)
	}
	existing := t.TempDir()
	content := []byte(`{"detectors":[{"rule_id":"dup","rule_version":"1","category":"secret","pattern":"DUP_[A-Z]+"}]}`)
	if err := os.WriteFile(filepath.Join(existing, "detector.json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	dupFile := PackFile{Path: "detector.json", SHA256: hex.EncodeToString(sum[:])}
	duplicated := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{dupFile, dupFile}}
	if _, err := VerifyPack(existing, duplicated); err == nil || !strings.Contains(err.Error(), "duplicate file") {
		t.Fatalf("duplicate files must be rejected, got %v", err)
	}
	nonCanonical := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "./detector.json", SHA256: strings.Repeat("0", 64)}}}
	if _, err := VerifyPack(t.TempDir(), nonCanonical); err == nil || !strings.Contains(err.Error(), "invalid relative path") {
		t.Fatalf("non-canonical path must be rejected, got %v", err)
	}
}

// TestVerifyPackReportsFileReadFailure pins the read-failure branch: a
// declared detector.json that cannot be read (here: a directory) fails
// verification instead of hashing empty content.
func TestVerifyPackReportsFileReadFailure(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "detector.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := PackManifest{SchemaVersion: GuardPackManifestVersion, PackID: "p", PackVersion: "1", RuntimeAPI: RuntimeVersion, Files: []PackFile{{Path: "detector.json", SHA256: strings.Repeat("0", 64)}}}
	if _, err := VerifyPack(root, manifest); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("unreadable detector.json must fail verification, got %v", err)
	}
}

// TestHTTPDetectorIdentityAndTransportFailures covers the adapter identity
// accessor and the transport failure modes: oversized input, unreachable
// endpoint, and a non-200 response are explicit errors, never empty findings.
func TestHTTPDetectorIdentityAndTransportFailures(t *testing.T) {
	identity := RuleVersion{PackID: "user.pack", PackVersion: "1", RuleID: "remote", RuleVersion: "1"}

	failing := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	failingDetector, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: failing.URL, Hosts: []string{"127.0.0.1"}, Client: failing.Client(), MaxBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	if got := failingDetector.Identity(); got != identity {
		t.Fatalf("Identity() = %#v, want %#v", got, identity)
	}
	if _, err := failingDetector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: strings.Repeat("x", 65)}); err == nil || !strings.Contains(err.Error(), "input exceeds") {
		t.Fatalf("oversized input must be rejected locally, got %v", err)
	}
	if _, err := failingDetector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil || !strings.Contains(err.Error(), "unexpected status 500") {
		t.Fatalf("non-200 response must be an error, got %v", err)
	}

	closed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	closedDetector, err := NewHTTPDetector(HTTPDetectorConfig{Identity: identity, Endpoint: closed.URL, Hosts: []string{"127.0.0.1"}, Client: closed.Client(), MaxBytes: 64})
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	if _, err := closedDetector.Detect(Invocation{Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: "x"}); err == nil || !strings.Contains(err.Error(), "request failed") {
		t.Fatalf("unreachable endpoint must be an error, got %v", err)
	}
}

// TestCmpStringOrdering pins the three-way comparison used to order
// versioned detectors: less, greater, and equal are all distinguished.
func TestCmpStringOrdering(t *testing.T) {
	if got := cmpString("a", "b"); got != -1 {
		t.Fatalf("cmpString(a,b) = %d, want -1", got)
	}
	if got := cmpString("b", "a"); got != 1 {
		t.Fatalf("cmpString(b,a) = %d, want 1", got)
	}
	if got := cmpString("a", "a"); got != 0 {
		t.Fatalf("cmpString(a,a) = %d, want 0", got)
	}
}
