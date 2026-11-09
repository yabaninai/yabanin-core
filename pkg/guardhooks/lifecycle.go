package guardhooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// DetectorPackFile is the portable, declarative detector format accepted by
// the free-pack loader. Patterns use Go's linear-time RE2 syntax.
type DetectorPackFile struct {
	Detectors []RegexDetectorSpec `json:"detectors"`
}

// RegexDetectorSpec defines one detector in detector.json.
type RegexDetectorSpec struct {
	RuleID      string   `json:"rule_id"`
	RuleVersion string   `json:"rule_version"`
	Category    Category `json:"category"`
	Pattern     string   `json:"pattern"`
}

// PackSource binds a manifest to its on-disk pack directory.
type PackSource struct {
	Root     string
	Manifest []byte
}

type regexVersionedDetector struct {
	identity RuleVersion
	category Category
	pattern  *regexp.Regexp
}

func (d regexVersionedDetector) Identity() RuleVersion { return d.identity }
func (d regexVersionedDetector) Detect(in Invocation) ([]Finding, error) {
	text, err := in.Content()
	if err != nil {
		return nil, err
	}
	spans := d.pattern.FindAllStringIndex(text, MaxFindingsPerDetection+1)
	out := make([]Finding, 0, len(spans))
	for _, span := range spans {
		out = append(out, Finding{Category: d.category, Start: span[0], End: span[1], Confidence: 1, Detector: d.identity.PackID + ":" + d.identity.RuleID})
	}
	return out, nil
}

// MaxDetectorsPerPack bounds how many detectors one detector.json may
// declare. Every detector compiles a regex at load time and runs over every
// guarded request, so an unbounded list (a 4 MiB file can declare tens of
// thousands of patterns) would multiply per-request evaluation cost. 256
// detectors leave generous room for real packs while keeping the per-request
// worst case bounded.
const MaxDetectorsPerPack = 256

// LoadDetectorPack verifies the manifest and every file before compiling any
// detector. The supported pack has exactly one detector.json payload.
// Signatures fail closed: use LoadDetectorPackWithVerifier to check declared
// signatures against a configured verifier.
func LoadDetectorPack(root string, manifestBytes []byte) (VerifiedPack, []VersionedDetector, error) {
	return LoadDetectorPackWithVerifier(root, manifestBytes, nil)
}

// LoadDetectorPackWithVerifier is LoadDetectorPack with the explicit
// signature policy applied: a manifest declaring a signature is verified
// against the configured verifier (nil keeps the fail-closed default).
func LoadDetectorPackWithVerifier(root string, manifestBytes []byte, verifier SignatureVerifier) (VerifiedPack, []VersionedDetector, error) {
	manifest, err := DecodePackManifestWithVerifier(manifestBytes, verifier)
	if err != nil {
		return VerifiedPack{}, nil, err
	}
	// Reject unsupported pack shapes before any file is opened or hashed so a
	// manifest with many entries cannot spend verification work.
	if len(manifest.Files) != 1 || manifest.Files[0].Path != "detector.json" {
		return VerifiedPack{}, nil, errors.New("guard pack load: expected exactly one detector.json file")
	}
	// Resolve the pack root once and drive verification AND the detector.json
	// read through the same resolved directory (review F1): VerifyPack works
	// on the symlink-resolved tree, so a symlinked root must never be
	// verified at one location and read at another.
	rootReal, err := resolvePackRoot(root)
	if err != nil {
		return VerifiedPack{}, nil, err
	}
	verified, err := VerifyPack(rootReal, manifest)
	if err != nil {
		return VerifiedPack{}, nil, err
	}
	// The bytes below are what the evaluators compile — re-hash them against
	// the manifest (review F1 TOCTOU): content swapped between VerifyPack's
	// hash pass and this read fails closed instead of being staged.
	data, err := loadVerifiedDetectorFile(rootReal, manifest)
	if err != nil {
		return VerifiedPack{}, nil, err
	}
	var spec DetectorPackFile
	decoderErr := json.Unmarshal(data, &spec)
	if decoderErr != nil {
		return VerifiedPack{}, nil, fmt.Errorf("guard pack load: decode detector.json: %w", decoderErr)
	}
	if len(spec.Detectors) == 0 {
		return VerifiedPack{}, nil, errors.New("guard pack load: detector.json has no detectors")
	}
	if len(spec.Detectors) > MaxDetectorsPerPack {
		return VerifiedPack{}, nil, fmt.Errorf("guard pack load: %d detectors exceeds the %d-detector limit", len(spec.Detectors), MaxDetectorsPerPack)
	}
	detectors := make([]VersionedDetector, 0, len(spec.Detectors))
	ruleIDs := make(map[string]struct{}, len(spec.Detectors))
	for _, item := range spec.Detectors {
		if item.RuleID == "" || item.RuleVersion == "" || item.Category == "" || item.Pattern == "" {
			return VerifiedPack{}, nil, errors.New("guard pack load: detector rule_id, rule_version, category and pattern are required")
		}
		pattern, err := regexp.Compile(item.Pattern)
		if err != nil {
			return VerifiedPack{}, nil, fmt.Errorf("guard pack load: detector %q pattern: %w", item.RuleID, err)
		}
		ruleIDs[item.RuleID] = struct{}{}
		detectors = append(detectors, regexVersionedDetector{
			identity: RuleVersion{PackID: manifest.PackID, PackVersion: manifest.PackVersion, RuleID: item.RuleID, RuleVersion: item.RuleVersion},
			category: item.Category, pattern: pattern,
		})
	}
	// Coverage enforcement: this loader is the only point
	// where the manifest's coverage block and the pack's own detector rules
	// coexist, so the "unknown rule_id ⇒ pack invalid" rule lands here — a
	// coverage claim may never point at another pack's rules or at nothing.
	if err := ValidateCoverageAgainstRules(manifest.Coverage, ruleIDs); err != nil {
		return VerifiedPack{}, nil, err
	}
	if _, err := NewEvaluator(detectors...); err != nil {
		return VerifiedPack{}, nil, fmt.Errorf("guard pack load: %w", err)
	}
	return verified, detectors, nil
}

// resolvePackRoot resolves the operator-configured pack root to its real
// (symlink-free) absolute path, the same normalization VerifyPack applies —
// hoisted here so every load-side filesystem access addresses the exact
// directory that was verified.
func resolvePackRoot(root string) (string, error) {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("guard pack load: resolve pack root: %w", err)
	}
	rootReal, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("guard pack load: resolve pack root: %w", err)
	}
	return rootReal, nil
}

// loadVerifiedDetectorFile reads detector.json under the symlink-resolved
// pack root and re-hashes the loaded bytes against the manifest's declared
// digest. VerifyPack hashed an earlier read of the same path; the bytes this
// function returns are exactly what the evaluators will compile, so a file
// swapped between verification and load (the review-F1 race window) is
// rejected here fail-closed — nothing unverified is ever staged.
func loadVerifiedDetectorFile(rootReal string, manifest PackManifest) ([]byte, error) {
	path := filepath.Join(rootReal, "detector.json") // File name is fixed by the loader contract and checked against the manifest by the caller.
	file, err := os.Open(path)                       // #nosec G304 -- the only accepted relative path is the fixed detector.json under the verified pack root.
	if err != nil {
		return nil, fmt.Errorf("guard pack load: read detector.json: %w", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxDetectorFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, fmt.Errorf("guard pack load: read detector.json: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("guard pack load: close detector.json: %w", closeErr)
	}
	if len(data) > MaxDetectorFileBytes {
		return nil, fmt.Errorf("guard pack load: detector.json exceeds %d-byte limit", MaxDetectorFileBytes)
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), manifest.Files[0].SHA256) {
		return nil, errors.New("guard pack load: detector.json changed between verification and load (sha256 mismatch)")
	}
	return data, nil
}

// PolicyVersionCAS is the narrow public-policy API boundary used to activate
// and roll back a verified pack. Implementations must perform a CAS.
type PolicyVersionCAS interface {
	CompareAndSwap(context.Context, string, string) error
}

// BuiltinChainVersion is the durable version identity of the built-in hook
// chain: the lifecycle's usual starting point, and the previous version
// recorded when a pack is activated from (or rolled back to) the built-ins.
// A rollback to this identity legitimately restores the built-in chain —
// every other previous identity must have a loaded hook chain behind it, so
// a rollback can never serve the built-ins under a pack's version label.
const BuiltinChainVersion = "core"

// PackLifecycle keeps a verified candidate separate from the active evaluator.
// Shadow evaluates the candidate with audit-only actions; activation is only
// published after the policy CAS succeeds. An optional static signature
// verifier applies to every staged/loaded manifest (see
// NewPackLifecycleWithVerifier); activation/rollback history semantics are
// independent of it.
type PackLifecycle struct {
	mu       sync.RWMutex
	current  string
	previous string
	policy   PolicyVersionCAS
	mode     Mode
	active   *Hook
	shadow   *Hook
	staged   *Hook
	prior    *Hook
	// verifier is the optional pack-signature verifier consulted for every
	// staged manifest. nil preserves the fail-closed default: a declared
	// signature cannot be staged without a verifier.
	verifier SignatureVerifier
	// priorUnrestorable records why the previous pack could not be loaded at
	// adopt time. A rollback must then fail closed BEFORE the CAS instead of
	// swapping the version label while the hook chain falls back to the
	// built-ins — never claim enforcement of a chain it does not have.
	priorUnrestorable error
}

// NewPackLifecycle creates a lifecycle bound to the public policy CAS API.
func NewPackLifecycle(currentVersion string, mode Mode, policy PolicyVersionCAS) *PackLifecycle {
	return &PackLifecycle{current: currentVersion, mode: mode, policy: policy}
}

// NewPackLifecycleWithVerifier is NewPackLifecycle plus the static pack
// signature verifier applied to every manifest this lifecycle stages
// (Stage/StageSources). Constructing the lifecycle with the verifier —
// instead of passing it per call — is the fail-safe default for wiring:
// every staging path (startup, admin API, replica re-stage) verifies signed
// packs automatically.
func NewPackLifecycleWithVerifier(currentVersion string, mode Mode, policy PolicyVersionCAS, verifier SignatureVerifier) *PackLifecycle {
	return &PackLifecycle{current: currentVersion, mode: mode, policy: policy, verifier: verifier}
}

// Stage verifies and registers a pack for shadow simulation without changing
// the active hook.
func (p *PackLifecycle) Stage(root string, manifest []byte) (VerifiedPack, error) {
	if p == nil {
		return VerifiedPack{}, errors.New("guard pack stage: nil lifecycle")
	}
	return p.StageSources([]PackSource{{Root: root, Manifest: manifest}})
}

// loadPackDetectors verifies each source and returns the per-pack
// verification results plus their combined detector list.
func loadPackDetectors(sources []PackSource, verifier SignatureVerifier) ([]VerifiedPack, []VersionedDetector, error) {
	var detectors []VersionedDetector
	verified := make([]VerifiedPack, 0, len(sources))
	for _, source := range sources {
		pack, packDetectors, err := LoadDetectorPackWithVerifier(source.Root, source.Manifest, verifier)
		if err != nil {
			return nil, nil, err
		}
		verified = append(verified, pack)
		detectors = append(detectors, packDetectors...)
	}
	return verified, detectors, nil
}

// StageSources verifies each manifest in its own directory and stages their
// detectors as one atomic activation candidate. No candidate becomes active
// until Activate's policy CAS succeeds, and staging never touches the
// activation history: previous keeps naming the version a rollback would
// restore, so a stage-without-activate (or a failed Activate) cannot turn
// the rollback CAS into a degenerate current -> current transition.
func (p *PackLifecycle) StageSources(sources []PackSource) (VerifiedPack, error) {
	if p == nil {
		return VerifiedPack{}, errors.New("guard pack stage: nil lifecycle")
	}
	if len(sources) == 0 {
		return VerifiedPack{}, errors.New("guard pack stage: at least one source is required")
	}
	verified, detectors, err := loadPackDetectors(sources, p.verifier)
	if err != nil {
		return VerifiedPack{}, err
	}
	evaluator, err := NewExtendedEvaluator(detectors...)
	if err != nil {
		return VerifiedPack{}, err
	}
	p.mu.Lock()
	p.shadow = NewWithEvaluator(ModeLog, evaluator)
	p.staged = NewWithEvaluator(p.mode, evaluator)
	p.mu.Unlock()
	if len(verified) == 1 {
		return verified[0], nil
	}
	// Multi-pack candidates report a synthetic identity that pins every
	// contributing pack id and version plus a digest over the per-pack
	// digests, so the staged candidate is still auditable as one unit.
	return VerifiedPack{Manifest: PackManifest{PackID: "active-packs", PackVersion: p.stagedVersion(), RuntimeAPI: RuntimeVersion}, Digest: combinedPackDigest(verified)}, nil
}

// LoadPackHook verifies the sources and builds the enforce-mode hook chain
// without touching any lifecycle state. Hydration uses it to load the durable
// previous pack, so a rollback restores the real previous detectors instead
// of silently serving the built-in chain under the previous version label.
// Declared signatures fail closed; use LoadPackHookWithVerifier for signed
// packs.
func LoadPackHook(mode Mode, sources []PackSource) (*Hook, error) {
	return LoadPackHookWithVerifier(mode, nil, sources)
}

// LoadPackHookWithVerifier is LoadPackHook with the explicit signature
// policy applied to every source manifest.
func LoadPackHookWithVerifier(mode Mode, verifier SignatureVerifier, sources []PackSource) (*Hook, error) {
	if len(sources) == 0 {
		return nil, errors.New("guard pack load: at least one source is required")
	}
	_, detectors, err := loadPackDetectors(sources, verifier)
	if err != nil {
		return nil, err
	}
	evaluator, err := NewExtendedEvaluator(detectors...)
	if err != nil {
		return nil, err
	}
	return NewWithEvaluator(mode, evaluator), nil
}

func combinedPackDigest(packs []VerifiedPack) string {
	parts := make([]string, 0, len(packs))
	for _, pack := range packs {
		parts = append(parts, fmt.Sprintf("%s:%s", pack.Manifest.PackID, pack.Digest))
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(digest[:])
}

// ShadowHook returns the staged detector chain in audit-only mode.
func (p *PackLifecycle) ShadowHook() *Hook {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.shadow
}

// ActiveHook returns the currently selected enforce/log hook.
func (p *PackLifecycle) ActiveHook() *Hook {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	active := p.active
	mode := p.mode
	p.mu.RUnlock()
	if active != nil {
		return active
	}
	return New(mode)
}

// Activate changes the persisted policy version with CAS before exposing the
// staged hook as active.
func (p *PackLifecycle) Activate(ctx context.Context) error {
	if p == nil {
		return errors.New("guard pack activate: no staged pack")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.staged == nil {
		return errors.New("guard pack activate: no staged pack")
	}
	if p.policy == nil {
		return errors.New("guard pack activate: policy CAS API is not configured")
	}
	if err := p.policy.CompareAndSwap(ctx, p.current, p.stagedVersion()); err != nil {
		return fmt.Errorf("guard pack activate: policy CAS: %w", err)
	}
	// The new prior is the chain that was actually active, so a later
	// rollback restores a real hook; any adopt-time unrestorable marker is
	// obsolete from here on.
	p.priorUnrestorable = nil
	p.prior, p.active = p.active, p.staged
	p.previous, p.current = p.current, p.stagedVersion()
	p.staged = nil
	return nil
}

// StagedVersion returns the durable version identity of the staged candidate
// ("pack@version", or the joined multi-pack form) — the exact value Activate
// would use as the CAS "to" argument and the value the durable policy store
// records. Empty when nothing is staged. It lets wiring reconcile a staged
// candidate against the durable record before deciding between a CAS
// transition and an idempotent adopt.
func (p *PackLifecycle) StagedVersion() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.stagedVersion()
}

// AdoptStaged publishes the staged candidate as the active hook WITHOUT
// running the policy CAS, re-anchoring the version history to the caller's
// durable record. It exists for the replica-adopt path: the caller has
// already established that the durable policy record names exactly the
// staged version (a restart or twin replica re-staging the active version),
// and the durable CAS adapter refuses a from == to transition — so the CAS
// must not run again. previous must be the durable previous_version and
// prior the hook chain that version resolves to on this surface (nil only
// when previous is the built-in chain, BuiltinChainVersion or empty), so a
// later Rollback CASes the transition the durable row expects AND restores
// the real previous detectors. When the durable previous pack exists but
// could not be loaded, the caller must use AdoptStagedUnrestorable — this
// method refuses a pack-labelled previous without a loaded chain, which
// would make the rollback serve built-ins under that label.
func (p *PackLifecycle) AdoptStaged(previous string, prior *Hook) error {
	if p == nil {
		return errors.New("guard pack adopt: nil lifecycle")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.staged == nil {
		return errors.New("guard pack adopt: no staged pack")
	}
	staged := p.stagedVersion()
	if staged != p.current {
		return fmt.Errorf("guard pack adopt: staged version %q does not match the durable active version %q", staged, p.current)
	}
	if prior == nil && previous != "" && previous != BuiltinChainVersion {
		return fmt.Errorf("guard pack adopt: previous pack %q has no loaded hook chain; load it or adopt it as unrestorable", previous)
	}
	p.priorUnrestorable = nil
	p.prior, p.active = prior, p.staged
	p.previous, p.current = previous, staged
	p.staged = nil
	return nil
}

// AdoptStagedUnrestorable publishes the staged candidate as the active hook
// WITHOUT running the policy CAS when the durable previous pack exists but
// could not be resolved or loaded on this surface. The active chain keeps
// enforcing, while a later Rollback fails closed with reason BEFORE the CAS:
// an explicit error, no durable write, and no hook swap — the lifecycle
// never claims enforcement of a detector chain it does not have. previous
// must name a pack (the built-in chain is always restorable; use AdoptStaged
// for it).
func (p *PackLifecycle) AdoptStagedUnrestorable(previous string, reason error) error {
	if p == nil {
		return errors.New("guard pack adopt: nil lifecycle")
	}
	if previous == "" || previous == BuiltinChainVersion {
		return errors.New("guard pack adopt: the built-in previous chain is always restorable; use AdoptStaged")
	}
	if reason == nil {
		reason = errors.New("previous pack not loaded")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.staged == nil {
		return errors.New("guard pack adopt: no staged pack")
	}
	staged := p.stagedVersion()
	if staged != p.current {
		return fmt.Errorf("guard pack adopt: staged version %q does not match the durable active version %q", staged, p.current)
	}
	p.priorUnrestorable = reason
	p.prior, p.active = nil, p.staged
	p.previous, p.current = previous, staged
	p.staged = nil
	return nil
}

// Rollback restores the prior policy version through the same CAS boundary.
// The restoration target is verified BEFORE the CAS (an unrestorable previous
// pack refuses with an explicit error), and the two-slot history stays real:
// the deactivated chain becomes the prior of the version the swap writes into
// previous, so a second rollback restores that version's real detectors —
// never the built-ins under a pack's version label.
func (p *PackLifecycle) Rollback(ctx context.Context) error {
	if p == nil {
		return errors.New("guard pack rollback: no active pack")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active == nil {
		return errors.New("guard pack rollback: no active pack")
	}
	// Verify the restoration target BEFORE the CAS: a rollback whose previous
	// pack is not loaded must refuse with an explicit error and leave the
	// active chain enforcing — swapping only the version label would serve
	// the built-ins while the durable record claims the previous pack.
	if p.priorUnrestorable != nil {
		return fmt.Errorf("guard pack rollback: previous pack %q is not restorable on this surface: %w", p.previous, p.priorUnrestorable)
	}
	if p.policy == nil {
		return errors.New("guard pack rollback: policy CAS API is not configured")
	}
	if err := p.policy.CompareAndSwap(ctx, p.current, p.previous); err != nil {
		return fmt.Errorf("guard pack rollback: policy CAS: %w", err)
	}
	p.current, p.previous = p.previous, p.current
	// Keep the real two-slot history (mirrors Activate's history swap): the
	// chain that was enforcing current IS the loaded chain for the version the
	// swap just recorded in previous. Keeping it as prior means a second
	// rollback restores the real previous detectors; dropping it (prior = nil)
	// would leave previous naming a pack whose chain nobody holds, so the next
	// rollback would serve the built-ins under that pack's version label.
	// When prior was nil (previous was the built-in chain) the swap installs
	// nil as active — ActiveHook then serves the built-ins, which is exactly
	// what a rollback to BuiltinChainVersion must do.
	p.active, p.prior = p.prior, p.active
	p.shadow = nil
	// A rollback is a return to the last known-good state: any candidate that
	// was staged but not activated is dropped so it cannot be activated after
	// the operator asked to go back. Re-staging is cheap and explicit.
	p.staged = nil
	return nil
}

func (p *PackLifecycle) stagedVersion() string {
	if p == nil || p.staged == nil || p.staged.evaluator == nil {
		return ""
	}
	var versions []string
	seen := make(map[string]struct{})
	packVersions := make(map[string]string)
	for _, detector := range p.staged.evaluator.detectors {
		id := detector.Identity()
		if id.PackID != "core.guardrails" {
			packVersions[id.PackID] = id.PackVersion
			version := id.PackID + "@" + id.PackVersion
			if _, ok := seen[version]; !ok {
				seen[version] = struct{}{}
				versions = append(versions, version)
			}
		}
	}
	if len(packVersions) == 1 {
		// Single-pack candidate: the version identity must carry the pack
		// id ("pack@version"), not the bare pack version — the CAS "to"
		// value is stored durably and compared across replicas, so a bare
		// "1" would be ambiguous between different packs.
		for packID, packVersion := range packVersions {
			return packID + "@" + packVersion
		}
	}
	return strings.Join(versions, ",")
}
