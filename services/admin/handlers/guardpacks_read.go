package handlers

// N02-P08 (T02/T06): the read + dry-run half of the admin guard detector-pack
// surface, so the dashboard can drive the edit→validate→simulate→activate→
// runtime→audit chain through the API:
//
//	GET  /api/guard-packs         — the on-disk pack inventory (one row per
//	                                <packDir> entry: manifest identity or the
//	                                reason it is not loadable) plus the durable
//	                                active/previous versions.
//	GET  /api/guard-packs/status  — the honest runtime read: the durable
//	                                requested state, the staged (not yet
//	                                activated) candidate, and whether the
//	                                durable active version still LOADS from
//	                                disk. Loadability is the same verification
//	                                every replica's runtime adoption performs;
//	                                a load failure here is exactly the state
//	                                that keeps replicas on their last known-good
//	                                hook and increments
//	                                gateway_guard_pack_watch_failures_total.
//	POST /api/guard-packs/validate — dry-run the full loader (SHA-256 file
//	                                verification + detector compile) without
//	                                staging anything. Parity with the activate
//	                                path's Stage step, minus the mutation.
//	POST /api/guard-packs/simulate — detect-only dry run: load the pack, run
//	                                the combined built-in + pack evaluator
//	                                over the caller's sample (audit-only
//	                                semantics — findings only, no action,
//	                                no state change).
//
// Honesty contract (N02-P08-T06): this surface never fabricates runtime
// telemetry. The durable row is the REQUESTED version; the per-replica
// APPLIED version and the watch-failure counter live in the gateway process
// (its /metrics and adoption logs) and are not restated here — the status
// endpoint reports the durable state plus the load check instead, so the
// failure-relevant condition is observable without inventing a count or an
// applied version this process cannot know.
//
// All four routes ride the same root-only group as activate/rollback
// (mountGuard → mountRootAdmin): they expose the operator-configured pack
// root and run loader work over it. Read-only routes are not journaled;
// validate/simulate mutate nothing (no durable write, no lifecycle state,
// no production policy change — the N02-P08 feedback invariant).

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

// guardPackSimulateBodyLimit caps the simulate JSON body: two short identity
// strings plus the sample text the operator wants scanned. 128 KiB bounds the
// regex work per request (the 4 KiB mutation cap would make the sample
// useless) while staying far below the per-detector file limits.
const guardPackSimulateBodyLimit = 128 * 1024

// maxSimulateFindings caps the findings ARRAY in the simulate response. The
// evaluator itself retains up to MaxFindingsPerDetection findings per
// detector; echoing all of them to a browser is wasted payload, so the
// response carries the total and a truncated flag instead.
const maxSimulateFindings = 100

// guardPackListRow is one on-disk pack directory. A directory whose manifest
// cannot be read or decoded is listed WITH its error (the operator must see
// the broken pack, not have it silently disappear from the inventory).
type guardPackListRow struct {
	// Dir is the on-disk directory name (always present, even for a row
	// whose manifest does not declare a usable identity).
	Dir string `json:"dir"`
	// PackID/PackVersion come from the decoded manifest; empty on an error row.
	PackID      string `json:"pack_id,omitempty"`
	PackVersion string `json:"pack_version,omitempty"`
	// Files is the manifest's declared file count (the supported pack shape
	// is exactly one detector.json).
	Files int `json:"files,omitempty"`
	// SignatureDeclared reports a manifest signature envelope. A declared
	// signature fails closed without a configured verifier (pack.go), so the
	// UI must distinguish "unsigned local pack (free cycle)" from "declared
	// signature" instead of hiding the field.
	SignatureDeclared bool `json:"signature_declared,omitempty"`
	// Coverage is the manifest's declared scenario
	// coverage (one row per detector rule: rule_id, ev_ids, evidence_test).
	// ABSENT — never null — when the pack declares none: absence means
	// "coverage unknown", not "full coverage". It rides the same root-only
	// permission as the whole endpoint (no separate grant), and a pack
	// whose coverage block fails decode validation is listed as an error
	// row instead of a partial claim.
	Coverage []guardhooks.CoverageEntry `json:"coverage,omitempty"`
	// Error is the reason the directory is not loadable (empty = healthy).
	Error string `json:"error,omitempty"`
}

type guardPackListResponse struct {
	Packs []guardPackListRow `json:"packs"`
	// ActiveVersion/PreviousVersion are the durable requested versions
	// ("" = the built-in chain; the gateway watches this row).
	ActiveVersion   string `json:"active_version"`
	PreviousVersion string `json:"previous_version"`
}

// handleList serves GET /api/guard-packs: the pack inventory plus the durable
// state the activation marks hang off. A policy read failure is a 500 — the
// inventory without the durable state would invite activating against a
// stale view.
func (g *GuardPackHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if g.unwired(w) {
		return
	}
	if g.packDir == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "guard pack directory not configured"})
		return
	}
	if g.policy == nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard policy store failed"})
		return
	}
	state, err := g.policy.ActiveGuardPackState(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard policy store failed"})
		return
	}
	entries, err := os.ReadDir(g.packDir)
	if err != nil {
		// The configured root is unreadable: that is an operator-visible
		// environment fault, not an empty inventory.
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard pack directory is not readable"})
		return
	}
	packs := make([]guardPackListRow, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		packs = append(packs, inventoryPackDir(filepath.Join(g.packDir, entry.Name()), entry.Name(), g.verifier))
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Dir < packs[j].Dir })
	writeJSON(w, http.StatusOK, guardPackListResponse{
		Packs:           packs,
		ActiveVersion:   state.ActiveVersion,
		PreviousVersion: state.PreviousVersion,
	})
}

// inventoryPackDir reads <dir>/manifest.json and reports either the declared
// identity or the reason the pack is not loadable (never hides a directory).
// The manifest is decoded under the surface's verifier: with one configured,
// a correctly signed pack lists as healthy; without one, a declared
// signature is reported as the reason the pack is not loadable.
func inventoryPackDir(root, name string, verifier guardhooks.SignatureVerifier) guardPackListRow {
	manifest, err := readPackFileBounded(filepath.Join(root, "manifest.json"), guardhooks.MaxPackManifestBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return guardPackListRow{Dir: name, Error: "manifest.json not found"}
		}
		return guardPackListRow{Dir: name, Error: "manifest.json is not readable"}
	}
	decoded, err := guardhooks.DecodePackManifestWithVerifier(manifest, verifier)
	if err != nil {
		return guardPackListRow{Dir: name, Error: "manifest is not loadable: " + err.Error()}
	}
	return guardPackListRow{
		Dir:               name,
		PackID:            decoded.PackID,
		PackVersion:       decoded.PackVersion,
		Files:             len(decoded.Files),
		SignatureDeclared: decoded.Signature != nil,
		// Additive surfacing: the declaration the decoded
		// manifest carries, verbatim — nil (key omitted) when the pack
		// declares none.
		Coverage: decoded.Coverage,
	}
}

// guardPackRuntimeStatus is the loadability half of the status endpoint.
type guardPackRuntimeStatus struct {
	// ActivePackLoadable: every pack the durable active version names passes
	// the same load (manifest decode + SHA-256 verification + detector
	// compile) the runtime materialization performs. The built-in chain
	// ("core"/empty) is always loadable.
	ActivePackLoadable bool `json:"active_pack_loadable"`
	// LoadError carries the first failure reason (empty when loadable).
	LoadError string `json:"load_error,omitempty"`
	// Check names what was verified, so the UI can quote it honestly.
	Check string `json:"check"`
}

type guardPackStatusResponse struct {
	// Durable requested state (the coordination point every replica watches).
	ActiveVersion   string `json:"active_version"`
	PreviousVersion string `json:"previous_version"`
	UpdatedBy       string `json:"updated_by,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
	// StagedVersion is this admin process's verified-but-not-activated
	// candidate ("" when nothing is staged). It is process-local state —
	// other replicas keep their own.
	StagedVersion string `json:"staged_version"`
	// Runtime is the honest runtime read (see the file comment: no applied
	// version and no failure counter are fabricated here).
	Runtime guardPackRuntimeStatus `json:"runtime"`
}

// handleStatus serves GET /api/guard-packs/status.
func (g *GuardPackHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	if g.unwired(w) {
		return
	}
	if g.packDir == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "guard pack directory not configured"})
		return
	}
	if g.policy == nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard policy store failed"})
		return
	}
	state, err := g.policy.ActiveGuardPackState(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard policy store failed"})
		return
	}
	loadable, loadErr := checkDurablePackLoadable(g.packDir, state.ActiveVersion, g.verifier)
	resp := guardPackStatusResponse{
		ActiveVersion:   state.ActiveVersion,
		PreviousVersion: state.PreviousVersion,
		StagedVersion:   g.lifecycle.StagedVersion(),
		Runtime: guardPackRuntimeStatus{
			ActivePackLoadable: loadable,
			LoadError:          loadErr,
			Check:              "durable active version loaded from the pack root (the same load the runtime materialization performs; a failure keeps replicas on the last known-good hook and counts in gateway_guard_pack_watch_failures_total)",
		},
	}
	if !state.UpdatedAt.IsZero() {
		resp.UpdatedAt = state.UpdatedAt.UTC().Format(time.RFC3339)
		resp.UpdatedBy = state.UpdatedBy
	}
	writeJSON(w, http.StatusOK, resp)
}

// checkDurablePackLoadable mirrors the runtime adoption's resolution
// (pkg/gateway resolveDurableGuardPackSources + LoadPackHookWithVerifier
// semantics): split the durable identity on ",", resolve each pack@version
// under the pack root, decode (under the surface's verifier) + fully load
// it. Read-only — nothing is staged or activated, and no lifecycle state is
// touched.
func checkDurablePackLoadable(packDir, identity string, verifier guardhooks.SignatureVerifier) (bool, string) {
	identity = strings.TrimSpace(identity)
	if identity == "" || identity == guardhooks.BuiltinChainVersion {
		return true, ""
	}
	seen := make(map[string]bool)
	for _, part := range strings.Split(identity, ",") {
		part = strings.TrimSpace(part)
		packID, version, ok := strings.Cut(part, "@")
		if !ok || packID == "" || version == "" || filepath.Base(packID) != packID || packID == "." || packID == ".." {
			return false, fmt.Sprintf("malformed durable guard pack identity %q", part)
		}
		if seen[packID] {
			continue
		}
		seen[packID] = true
		root := filepath.Join(packDir, packID)
		manifest, err := readPackFileBounded(filepath.Join(root, "manifest.json"), guardhooks.MaxPackManifestBytes)
		if err != nil {
			return false, fmt.Sprintf("read manifest for durable pack %q: %v", packID, err)
		}
		decoded, err := guardhooks.DecodePackManifestWithVerifier(manifest, verifier)
		if err != nil {
			return false, fmt.Sprintf("decode manifest for durable pack %q: %v", packID, err)
		}
		if decoded.PackID != packID || decoded.PackVersion != version {
			return false, fmt.Sprintf("durable pack %s@%s not found on disk (manifest declares %s@%s)", packID, version, decoded.PackID, decoded.PackVersion)
		}
		if _, _, err := guardhooks.LoadDetectorPackWithVerifier(root, manifest, verifier); err != nil {
			return false, fmt.Sprintf("load durable pack %s@%s: %v", packID, version, err)
		}
	}
	return true, ""
}

// guardPackSimulateBody is the simulate request: the pack identity plus the
// sample text. An empty sample is a legitimate dry run (honestly answers
// "no findings"); a missing detector pack is not (404/409 like activate).
type guardPackSimulateBody struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
	Sample  string `json:"sample"`
}

type guardPackFinding struct {
	Detector   string  `json:"detector"`
	Category   string  `json:"category"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

type guardPackSimulateResponse struct {
	Status        string             `json:"status"`
	PackID        string             `json:"pack_id"`
	PackVersion   string             `json:"pack_version"`
	Digest        string             `json:"digest"`
	TotalFindings int                `json:"total_findings"`
	Truncated     bool               `json:"truncated"`
	Findings      []guardPackFinding `json:"findings"`
	// Categories is the deduped category set at the SCAN confidence
	// threshold (Hook.Scan parity) — the categories the runtime would act
	// on, as opposed to the raw offset-level findings above which include
	// every detector match regardless of confidence.
	Categories []string `json:"categories"`
}

// handleSimulate serves POST /api/guard-packs/simulate: load the requested
// pack (full verification, no staging) and evaluate the sample through the
// combined built-in + pack evaluator — the detect-only half of the shadow
// semantics. Findings carry offsets and detector identity only.
func (g *GuardPackHandlers) handleSimulate(w http.ResponseWriter, r *http.Request) {
	if g.unwired(w) {
		return
	}
	var body guardPackSimulateBody
	if !decodeBodyWithLimit(w, r, guardPackSimulateBodyLimit, &body) {
		return
	}
	packID := strings.TrimSpace(body.PackID)
	version := strings.TrimSpace(body.Version)
	if !validGuardPackID(w, packID) || !validGuardPackVersion(w, version) {
		return
	}
	manifest, root, ok := g.loadPackManifest(w, packID, version)
	if !ok {
		return
	}
	verified, detectors, err := guardhooks.LoadDetectorPackWithVerifier(root, manifest, g.verifier)
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack failed verification: " + err.Error()})
		return
	}
	// The same combined evaluator a staged candidate runs with (built-ins
	// first, pack detectors after), so the preview matches what activation
	// would enforce.
	evaluator, err := guardhooks.NewExtendedEvaluator(detectors...)
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack failed simulation: " + err.Error()})
		return
	}
	evaluation, err := evaluator.Evaluate(guardhooks.Invocation{
		Context: r.Context(),
		Version: guardhooks.RuntimeVersion,
		Phase:   guardhooks.PhaseBefore,
		Kind:    guardhooks.ContentText,
		Text:    body.Sample,
	})
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack simulation failed: " + err.Error()})
		return
	}
	total := len(evaluation.Findings)
	truncated := total > maxSimulateFindings
	findings := make([]guardPackFinding, 0, min(total, maxSimulateFindings))
	for _, f := range evaluation.Findings {
		if len(findings) == maxSimulateFindings {
			break
		}
		findings = append(findings, guardPackFinding{
			Detector:   f.Detector,
			Category:   string(f.Category),
			Start:      f.Start,
			End:        f.End,
			Confidence: f.Confidence,
		})
	}
	// Scan-parity categories: the audit-only hook applies the same
	// confidence threshold and checksum validations as the enforcing chain,
	// so the preview names exactly the categories the runtime would act on.
	var categories []string
	for _, hit := range guardhooks.NewWithEvaluator(guardhooks.ModeLog, evaluator).Scan(body.Sample) {
		categories = append(categories, string(hit.Category))
	}
	writeJSON(w, http.StatusOK, guardPackSimulateResponse{
		Status:        "simulated",
		PackID:        verified.Manifest.PackID,
		PackVersion:   verified.Manifest.PackVersion,
		Digest:        verified.Digest,
		TotalFindings: total,
		Truncated:     truncated,
		Findings:      findings,
		Categories:    categories,
	})
}

type guardPackValidateResponse struct {
	Status      string `json:"status"`
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	Digest      string `json:"digest"`
	Detectors   int    `json:"detectors"`
}

// handleValidate serves POST /api/guard-packs/validate: the activate path's
// verification step as a dry run — manifest decode, SHA-256 file checks and
// detector compile, with NO staging and NO durable write. Same 404/409
// semantics as activate (unknown identity is 404, a present-but-broken pack
// is 409), so the UI preview cannot pass where activation would fail.
func (g *GuardPackHandlers) handleValidate(w http.ResponseWriter, r *http.Request) {
	if g.unwired(w) {
		return
	}
	var body guardPackActivateBody
	if !decodeGuardPackBody(w, r, &body) {
		return
	}
	packID := strings.TrimSpace(body.PackID)
	version := strings.TrimSpace(body.Version)
	if !validGuardPackID(w, packID) || !validGuardPackVersion(w, version) {
		return
	}
	manifest, root, ok := g.loadPackManifest(w, packID, version)
	if !ok {
		return
	}
	verified, detectors, err := guardhooks.LoadDetectorPackWithVerifier(root, manifest, g.verifier)
	if err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack failed verification: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, guardPackValidateResponse{
		Status:      "valid",
		PackID:      verified.Manifest.PackID,
		PackVersion: verified.Manifest.PackVersion,
		Digest:      verified.Digest,
		Detectors:   len(detectors),
	})
}

// readPackFileBounded reads at most limit+1 bytes so a hostile file cannot
// spend unbounded memory before the manifest size check runs (readBoundedFile
// parity without the HTTP writes).
func readPackFileBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- the path is <operator-configured root>/<validated single-component pack id>/manifest.json
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) > limit {
		return nil, fmt.Errorf("manifest exceeds %d-byte limit", limit)
	}
	return data, nil
}

// decodeBodyWithLimit is decodeGuardPackBody with an explicit cap (the
// simulate sample needs more than the 4 KiB mutation bound).
func decodeBodyWithLimit(w http.ResponseWriter, r *http.Request, limit int64, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "invalid request body"})
		return false
	}
	return true
}
