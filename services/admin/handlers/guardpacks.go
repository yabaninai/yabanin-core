package handlers

// N02-P04/P08: admin HTTP surface for the guard detector-pack lifecycle.
//
// The guard lifecycle (pkg/guardhooks.PackLifecycle) keeps a verified
// candidate separate from the active evaluator; activation publishes the
// candidate only after the policy CAS succeeds. This file routes two root-only
// mutations onto that lifecycle:
//
//	POST /api/guard-packs/activate  — stage + activate one on-disk pack by
//	                                  id + version (canary_rollouts.go pattern:
//	                                  explicit activation step, never implicit)
//	POST /api/guard-packs/rollback  — restore the previous active version
//
// The CAS boundary is the durable policy store (pkg/policystore.GuardPolicyCAS,
// migration 0013 guard_pack_state): exactly one concurrent activation wins,
// every loser gets 409 together with the live durable state (writeConflict
// parity), and a store failure fails closed with 5xx while the pack state
// (durable row AND local lifecycle) stays unchanged. The gateway startup
// activates its env-configured packs through the SAME durable CAS
// (pkg/gateway guardpack_durable.go) and adopts the durable winner on a lost
// startup race, so API activations converge with gateway startups across
// replicas; the admin runner hydrates its lifecycle read-only from the same
// row.
//
// Pack discovery mirrors the gateway wiring: one pack per directory under the
// operator-configured pack root, <root>/<pack_id>/manifest.json + detector.json.
// Unsigned local packs load without any payment/licensing gate (N02-P08 free
// cycle). The pack-signature verifier the admin startup resolved from the
// shared env config applies to every manifest this surface decodes or loads:
// a correctly signed pack verifies, and a declared signature with NO
// verifier configured (or a bad one) fails closed exactly like the startup
// path.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// GuardPolicyStore is the narrow durable seam the guard-pack handlers need:
// the policy-version CAS (the same contract the lifecycle holds internally)
// plus the state read used to render conflict bodies with the LIVE durable
// state. *policystore.GuardPolicyCAS is the production implementation; tests
// use an in-memory equivalent.
type GuardPolicyStore interface {
	CompareAndSwap(ctx context.Context, from, to string) error
	ActiveGuardPackState(ctx context.Context) (policystore.GuardPackState, error)
}

// compile pin: the durable adapter satisfies the handler seam.
var _ GuardPolicyStore = (*policystore.GuardPolicyCAS)(nil)

// guardPackBodyLimit caps the JSON body (two short strings; a DoS bound, not
// a feature limit — canaryBodyLimit parity).
const guardPackBodyLimit = 4 * 1024

// maxGuardPackVersionLen bounds the requested version string; the manifest
// remains the source of truth, this only rejects absurd input early.
const maxGuardPackVersionLen = 128

// GuardPackHandlers serves the guard detector-pack lifecycle routes. The
// admin server wires it with SetGuardPackHandlers over the operator-configured
// pack root, the durable-CAS-bound lifecycle, the same durable CAS (for
// conflict-state reads) and the static pack-signature verifier resolved once
// at admin startup.
type GuardPackHandlers struct {
	// packDir is the operator-configured pack root (the same layout the
	// gateway startup wiring reads: <dir>/<pack_id>/manifest.json).
	packDir string
	// lifecycle is the durable-CAS-bound pack lifecycle this surface drives.
	lifecycle *guardhooks.PackLifecycle
	// policy is the durable CAS seam (kept for live conflict-state reads).
	policy GuardPolicyStore
	// verifier is the static pack-signature verifier applied to every
	// manifest this surface decodes or loads (nil = none configured:
	// unsigned packs load freely, declared signatures fail closed).
	verifier guardhooks.SignatureVerifier
	// audit is the AdminHandlers journal hook (nil = no journal in bare
	// test instances).
	audit func(r *http.Request, action, resource, details string)
}

// NewGuardPackHandlers builds the guard-pack handlers over the pack root, the
// lifecycle, the durable CAS seam and the pack-signature verifier (nil keeps
// the fail-closed no-verifier default). A nil lifecycle keeps the routes
// mounted but unwired: they answer 503 (canary_rollouts.go convention).
func NewGuardPackHandlers(packDir string, lifecycle *guardhooks.PackLifecycle, policy GuardPolicyStore, verifier guardhooks.SignatureVerifier) *GuardPackHandlers {
	return &GuardPackHandlers{packDir: packDir, lifecycle: lifecycle, policy: policy, verifier: verifier}
}

// SetGuardPackHandlers attaches the guard-pack lifecycle handlers to the
// admin router.
func (h *AdminHandlers) SetGuardPackHandlers(g *GuardPackHandlers) {
	h.guardPacks = g
	if g != nil {
		g.audit = h.auditLogAction
	}
}

// mountGuard registers the guard detector-pack lifecycle routes on the
// root-only CRUD group (router.go mountRootAdmin — MustBeRoot + orgscope,
// same chain as the other global operational mutations). Mounted
// unconditionally: nil handlers answer 503. The read/dry-run surface
// (guardpacks_read.go: list/status/validate/simulate) rides the same group.
func (h *AdminHandlers) mountGuard(r chi.Router) {
	r.Post("/api/guard-packs/activate", h.guardPacks.handleActivate)
	r.Post("/api/guard-packs/rollback", h.guardPacks.handleRollback)
	r.Get("/api/guard-packs", h.guardPacks.handleList)
	r.Get("/api/guard-packs/status", h.guardPacks.handleStatus)
	r.Post("/api/guard-packs/validate", h.guardPacks.handleValidate)
	r.Post("/api/guard-packs/simulate", h.guardPacks.handleSimulate)
}

// unwired reports whether the lifecycle is missing and, when it is, writes
// the 503. Nil-receiver safe.
func (g *GuardPackHandlers) unwired(w http.ResponseWriter) bool {
	if g == nil || g.lifecycle == nil {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "guard pack lifecycle not configured"})
		return true
	}
	return false
}

type guardPackActivateBody struct {
	PackID  string `json:"pack_id"`
	Version string `json:"version"`
}

// handleActivate serves POST /api/guard-packs/activate: verify and stage the
// requested on-disk pack, then publish it through the durable policy CAS.
// Failure at ANY step leaves the active pack untouched (fail-closed): a
// conflicted or failed activation never half-swaps the guard chain.
func (g *GuardPackHandlers) handleActivate(w http.ResponseWriter, r *http.Request) {
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
	// Stage verifies every declared file (SHA-256) and compiles the
	// detector chain before anything is published. A verification failure
	// is a 409, not a 500: the pack exists but cannot take over the active
	// state, and nothing changed.
	if _, err := g.lifecycle.Stage(root, manifest); err != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack failed verification: " + err.Error()})
		return
	}
	// Activate runs the durable policy CAS; only a winning CAS exposes the
	// staged hook as active (in-memory, no restart needed for consumers of
	// this lifecycle).
	if err := g.lifecycle.Activate(r.Context()); err != nil {
		g.writeLifecycleError(w, r, err)
		return
	}
	g.auditAction(r, "activate", "guard_pack", "pack="+packID+",version="+version)
	g.writeState(r.Context(), w, http.StatusOK, "activated")
}

// handleRollback serves POST /api/guard-packs/rollback: restore the previous
// active version through the same durable CAS. Rolling back without an
// active pack (or without a prior version) is a 409, never a silent no-op.
func (g *GuardPackHandlers) handleRollback(w http.ResponseWriter, r *http.Request) {
	if g.unwired(w) {
		return
	}
	if err := g.lifecycle.Rollback(r.Context()); err != nil {
		g.writeLifecycleError(w, r, err)
		return
	}
	g.auditAction(r, "rollback", "guard_pack", "restored previous active guard pack version")
	g.writeState(r.Context(), w, http.StatusOK, "rolled_back")
}

// loadPackManifest resolves <packDir>/<packID>/manifest.json and enforces the
// requested identity: the manifest must declare exactly the requested
// pack_id and pack_version, so a version that is not on disk is the same 404
// as a pack that is not (fail-closed; no partial identity is trusted).
func (g *GuardPackHandlers) loadPackManifest(w http.ResponseWriter, packID, version string) ([]byte, string, bool) {
	if g.packDir == "" {
		writeJSON(w, http.StatusServiceUnavailable, apiError{Error: "guard pack directory not configured"})
		return nil, "", false
	}
	root := filepath.Join(g.packDir, packID)
	manifestPath := filepath.Join(root, "manifest.json")
	manifest, ok := readBoundedFile(w, manifestPath, guardhooks.MaxPackManifestBytes)
	if !ok {
		return nil, "", false
	}
	// The manifest is decoded under this surface's verifier: a declared
	// signature verifies here exactly as it would at Stage below, and a
	// signed manifest with no verifier (or a bad one) fails closed.
	decoded, err := guardhooks.DecodePackManifestWithVerifier(manifest, g.verifier)
	if err != nil {
		// The pack directory exists but its manifest is broken, oversized
		// or declares a signature no verifier can check: fail closed.
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack manifest is not activatable: " + err.Error()})
		return nil, "", false
	}
	if decoded.PackID != packID {
		writeJSON(w, http.StatusNotFound, apiError{Error: "guard pack not found"})
		return nil, "", false
	}
	if decoded.PackVersion != version {
		writeJSON(w, http.StatusNotFound, apiError{Error: "guard pack version not found: " + packID + "@" + version})
		return nil, "", false
	}
	return manifest, root, true
}

// readBoundedFile reads at most limit+1 bytes so a hostile file cannot spend
// unbounded memory before the manifest size check runs. A read failure is a
// 404 (unknown pack); an over-limit file is a 409 (present, not activatable).
func readBoundedFile(w http.ResponseWriter, path string, limit int) ([]byte, bool) {
	file, err := os.Open(path) // #nosec G304 -- the path is <operator-configured root>/<validated single-component pack id>/manifest.json
	if err != nil {
		writeJSON(w, http.StatusNotFound, apiError{Error: "guard pack not found"})
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	closeErr := file.Close()
	if readErr != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack manifest is not readable"})
		return nil, false
	}
	if closeErr != nil {
		writeJSON(w, http.StatusConflict, apiError{Error: "guard pack manifest is not readable"})
		return nil, false
	}
	if len(data) > limit {
		writeJSON(w, http.StatusConflict, apiError{Error: fmt.Sprintf("guard pack manifest exceeds %d-byte limit", limit)})
		return nil, false
	}
	return data, true
}

// validGuardPackID applies the gateway wiring's pack-id grammar: a single
// clean path component, so the manifest path cannot escape the pack root.
func validGuardPackID(w http.ResponseWriter, packID string) bool {
	if packID == "" || len(packID) > 256 || filepath.Base(packID) != packID || packID == "." || packID == ".." {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "pack_id must be a single path component (1..256 characters)"})
		return false
	}
	return true
}

// validGuardPackVersion rejects empty/oversized request versions before any
// filesystem work (the manifest comparison remains the real gate).
func validGuardPackVersion(w http.ResponseWriter, version string) bool {
	if version == "" || len(version) > maxGuardPackVersionLen {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "version must be 1 to " + fmt.Sprint(maxGuardPackVersionLen) + " characters"})
		return false
	}
	return true
}

// writeLifecycleError maps lifecycle/CAS failures (fail-closed ordering):
// a durable CAS conflict is 409 with the LIVE store state (writeConflict
// parity — the operator rebases on the fresh state); "nothing staged/active"
// is 409; every other CAS failure is a store failure answered 500 with the
// pack state unchanged.
func (g *GuardPackHandlers) writeLifecycleError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, policystore.ErrGuardPackConflict) {
		current := map[string]any{}
		if g.policy != nil {
			if state, stateErr := g.policy.ActiveGuardPackState(r.Context()); stateErr == nil {
				current["active_version"] = state.ActiveVersion
				current["previous_version"] = state.PreviousVersion
			}
		}
		writeConflict(w, current)
		return
	}
	msg := err.Error()
	// "no staged/active pack" is the lifecycle refusing a stateless
	// mutation; a non-empty-version CAS rejection is the durable adapter
	// refusing a rollback with no prior version to restore. Both are
	// caller-visible state conflicts (409), not server failures.
	if strings.Contains(msg, "no staged pack") || strings.Contains(msg, "no active pack") || strings.Contains(msg, "requires non-empty") {
		writeJSON(w, http.StatusConflict, apiError{Error: msg})
		return
	}
	writeJSON(w, http.StatusInternalServerError, apiError{Error: "guard policy store failed; pack state unchanged"})
}

// writeState answers with the live durable activation record (best-effort:
// a failed read degrades to a status-only body — the mutation already
// committed through the CAS).
func (g *GuardPackHandlers) writeState(ctx context.Context, w http.ResponseWriter, code int, status string) {
	body := map[string]any{"status": status}
	if g.policy != nil {
		if state, err := g.policy.ActiveGuardPackState(ctx); err == nil {
			body["active_version"] = state.ActiveVersion
			body["previous_version"] = state.PreviousVersion
		}
	}
	writeJSON(w, code, body)
}

// auditAction journals a guard-pack mutation (nil-safe).
func (g *GuardPackHandlers) auditAction(r *http.Request, action, resource, details string) {
	if g == nil || g.audit == nil {
		return
	}
	g.audit(r, action, resource, details)
}

// decodeGuardPackBody reads the JSON body under the cap and rejects unknown
// fields (decodeCanaryBody parity).
func decodeGuardPackBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, guardPackBodyLimit))
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
