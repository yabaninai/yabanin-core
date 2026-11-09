package cli

// Durable guard-pack coordination: ONE reconciliation semantic shared by the
// semantic shared by the gateway startup (loadGuardHooks) and the admin
// runner (services/run → HydrateGuardPackLifecycle).
//
// The gateway process and the admin process each hold their OWN lifecycle
// instance — in-memory hook chains cannot be shared across processes — and
// that is safe by construction: the durable guard_pack_state row (migration
// 0013, one-statement CAS) is the coordination point. Every activation or
// rollback in either process goes through the same compare-and-swap, so
// exactly one concurrent writer wins and every other process reads the
// winner's version from the row.
//
// Startup semantics (durable store, env-configured packs):
//   - record absent             → Activate bootstraps the row (from "core").
//   - staged == durable active  → idempotent adopt, no CAS (a restart or a
//     twin replica re-staging the active version; the durable adapter
//     refuses from == to, so re-running the CAS would fail the start).
//   - staged != durable active  → Activate re-asserts the env packs through
//     the CAS (the historical posture: env-based startup activation keeps
//     working; the transition is recorded durably). On a CAS conflict — an
//     admin-API activation or another replica won the race between our read
//     and our CAS — the loser reads the winner's version and ADOPTS it when
//     it is loadable from the pack root; otherwise the lifecycle keeps the
//     built-in hook chain (loud warning, the same posture as a missing pack
//     root) while its version identity stays rebased on the durable truth.
//
// The admin runner reconciles READ-ONLY: it never re-asserts env packs at
// startup (startup activation belongs to the gateway, the data plane); it
// rebases its version identity onto the durable record and hydrates the
// durable active packs so activate/rollback CAS from live versions
// immediately after a restart.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/policystore"
)

// coreDurableVersion is the version identity of the built-in hook chain: the
// lifecycle's starting point and the durable record of a rolled-back pack.
const coreDurableVersion = guardhooks.BuiltinChainVersion

// GuardPackPolicyStore is the durable coordination surface both processes
// drive: the policy-version CAS plus the state read used to rebase a
// lifecycle onto the durable record. *policystore.GuardPolicyCAS is the
// production implementation; tests use scripted equivalents.
type GuardPackPolicyStore interface {
	CompareAndSwap(ctx context.Context, from, to string) error
	ActiveGuardPackState(ctx context.Context) (policystore.GuardPackState, error)
}

// compile pin: the durable adapter is the production coordination surface.
var _ GuardPackPolicyStore = (*policystore.GuardPolicyCAS)(nil)

// localGuardPolicyStore is the no-DB fallback: without a database there is
// nothing to coordinate with, so the CAS is a no-op and the state read
// always reports "no durable activation" — the lifecycle keeps the legacy
// env-based bootstrap semantics bit-for-bit.
type localGuardPolicyStore struct{}

func (localGuardPolicyStore) CompareAndSwap(context.Context, string, string) error { return nil }

func (localGuardPolicyStore) ActiveGuardPackState(context.Context) (policystore.GuardPackState, error) {
	return policystore.GuardPackState{}, nil
}

// guardPackPolicyFor selects the coordination point: the durable
// guard_pack_state CAS when a DB pool exists, the local no-op store
// otherwise (no-DB deployments keep working exactly as before — no
// coordination to fail).
func guardPackPolicyFor(pool *pgxpool.Pool) GuardPackPolicyStore {
	if pool == nil {
		return localGuardPolicyStore{}
	}
	return policystore.NewGuardPolicyCAS(pool)
}

// GuardPackDurable is the reconciled guard-pack wiring for one process.
type GuardPackDurable struct {
	// Lifecycle reflects the durable record (nil only together with a
	// non-nil error). When the durable active packs are not loadable on this
	// surface, the lifecycle is rebased onto the durable truth while its
	// hook chain stays the built-in one.
	Lifecycle *guardhooks.PackLifecycle
	// Policy is the durable CAS backing the lifecycle (always non-nil when
	// the lifecycle was built against a DB pool).
	Policy *policystore.GuardPolicyCAS
}

// ReconcileGuardPackLifecycle is the shared lifecycle constructor: the
// gateway startup (loadGuardHooks) and any runner driving env-configured
// packs build their lifecycle here, over the coordination point selected by
// guardPackPolicyFor. The pack-signature verifier resolved once at process
// startup is applied to every manifest this lifecycle stages and to every
// durable pack it resolves (nil keeps the fail-closed no-verifier default).
// When the durable winner of a lost startup race is not loadable locally,
// the returned lifecycle serves the built-in hook chain and a loud warning
// has been logged.
func ReconcileGuardPackLifecycle(ctx context.Context, pool *pgxpool.Pool, l *slog.Logger, mode guardhooks.Mode, packRoot string, sources []guardhooks.PackSource, verifier guardhooks.SignatureVerifier) (*guardhooks.PackLifecycle, error) {
	return reconcileGuardPackLifecycle(ctx, guardPackPolicyFor(pool), l, mode, packRoot, sources, verifier)
}

// reconcileGuardPackLifecycle stages the candidate sources and publishes
// them through the policy store, rebasing the lifecycle's version identity
// onto the durable record first (see the file comment for the full
// semantics). A non-nil error without a CAS conflict (unreadable record,
// stage failure, store failure) refuses the startup.
func reconcileGuardPackLifecycle(ctx context.Context, policy GuardPackPolicyStore, l *slog.Logger, mode guardhooks.Mode, packRoot string, sources []guardhooks.PackSource, verifier guardhooks.SignatureVerifier) (*guardhooks.PackLifecycle, error) {
	state, err := policy.ActiveGuardPackState(ctx)
	if err != nil {
		return nil, fmt.Errorf("read durable guard pack state: %w", err)
	}
	current, previous := coreDurableVersion, ""
	if state.ActiveVersion != "" {
		current, previous = state.ActiveVersion, state.PreviousVersion
	}
	lifecycle := guardhooks.NewPackLifecycleWithVerifier(current, mode, policy, verifier)
	if _, err := lifecycle.StageSources(sources); err != nil {
		return nil, err
	}
	if staged := lifecycle.StagedVersion(); staged == current {
		// Idempotent adopt: the durable record already names exactly this
		// version (a restart with unchanged env, or a twin replica). The
		// durable adapter refuses from == to, so the CAS must not run.
		if err := adoptWithPrior(lifecycle, l, mode, packRoot, previous, verifier); err != nil {
			return nil, err
		}
		l.Info("guard detector packs adopted from the durable policy state", "active_version", current, "mode", mode)
		return lifecycle, nil
	}
	staged := lifecycle.StagedVersion()
	if err := lifecycle.Activate(ctx); err == nil {
		l.Info("guard detector packs activated", "active_version", staged, "mode", mode)
		return lifecycle, nil
	} else if !errors.Is(err, policystore.ErrGuardPackConflict) {
		return nil, err
	}
	// Lost the race: exactly-one-winner semantics mean another writer (an
	// admin-API activation or a twin replica's startup) moved the durable
	// row between our read and our CAS. The loser reads the winner's version
	// and adopts it when it is loadable locally.
	return adoptDurableWinner(ctx, policy, l, mode, packRoot, verifier)
}

// adoptDurableWinner re-reads the durable record after a lost CAS and adopts
// the winner's version from the pack root. When the winner is not loadable
// on this replica (its packs are missing or fail verification — including a
// declared signature this surface's verifier rejects — or the winner is the
// built-in chain), the returned lifecycle is rebased onto the durable truth
// while its hook chain stays the built-in one — a loud warning has been
// logged, matching the hydration degrade posture.
func adoptDurableWinner(ctx context.Context, policy GuardPackPolicyStore, l *slog.Logger, mode guardhooks.Mode, packRoot string, verifier guardhooks.SignatureVerifier) (*guardhooks.PackLifecycle, error) {
	state, err := policy.ActiveGuardPackState(ctx)
	if err != nil {
		return nil, fmt.Errorf("re-read durable guard pack state after CAS conflict: %w", err)
	}
	lifecycle := guardhooks.NewPackLifecycleWithVerifier(state.ActiveVersion, mode, policy, verifier)
	sources, resolveErr := resolveDurableGuardPackSources(packRoot, state.ActiveVersion, verifier)
	degrade := func(reason error) (*guardhooks.PackLifecycle, error) {
		l.Warn("guard pack activation raced a durable winner this replica cannot load — running with built-in guard hooks only",
			"durable_active_version", state.ActiveVersion, "reason", fmt.Sprint(reason))
		return lifecycle, nil
	}
	if resolveErr != nil {
		return degrade(resolveErr)
	}
	if len(sources) == 0 {
		return degrade(nil) // the winner is the built-in chain (durable rollback)
	}
	if _, err := lifecycle.StageSources(sources); err != nil {
		return degrade(err)
	}
	if err := adoptWithPrior(lifecycle, l, mode, packRoot, state.PreviousVersion, verifier); err != nil {
		return nil, err
	}
	l.Warn("guard pack activation raced a durable winner — adopted the durable active packs",
		"durable_active_version", state.ActiveVersion, "mode", mode)
	return lifecycle, nil
}

// loadDurablePrior resolves and loads the durable previous pack so a later
// rollback restores the real previous detectors. A pack that fails resolution
// or verification (including signature verification when a verifier is
// configured) is an error — the caller adopts the active pack as
// unrestorable instead of letting a rollback claim enforcement of a chain it
// does not have. The built-in chain needs no load and is handled by the
// caller.
func loadDurablePrior(mode guardhooks.Mode, packRoot, previous string, verifier guardhooks.SignatureVerifier) (*guardhooks.Hook, error) {
	sources, err := resolveDurableGuardPackSources(packRoot, previous, verifier)
	if err != nil {
		return nil, err
	}
	return guardhooks.LoadPackHookWithVerifier(mode, verifier, sources)
}

// adoptWithPrior publishes the staged candidate re-anchored to the durable
// record, loading the durable previous pack first so a rollback restores its
// real detectors. The built-in previous chain is always restorable — a nil
// prior hook tells the lifecycle the rollback restores the built-ins. An
// unloadable previous pack degrades to an unrestorable adopt (loud warning):
// the active chain keeps enforcing, while a rollback fails closed with an
// explicit error before the CAS — never serving the built-in chain under the
// previous pack's version label.
func adoptWithPrior(lifecycle *guardhooks.PackLifecycle, l *slog.Logger, mode guardhooks.Mode, packRoot, previous string, verifier guardhooks.SignatureVerifier) error {
	if previous == "" || previous == coreDurableVersion {
		return lifecycle.AdoptStaged(previous, nil)
	}
	prior, err := loadDurablePrior(mode, packRoot, previous, verifier)
	if err != nil {
		l.Warn("durable previous guard pack not usable on this surface — rollback will refuse until an activation re-anchors history",
			"previous_version", previous, "reason", err.Error())
		return lifecycle.AdoptStagedUnrestorable(previous, err)
	}
	return lifecycle.AdoptStaged(previous, prior)
}

// HydrateGuardPackLifecycle builds the admin process's guard-pack lifecycle
// READ-ONLY: the version identity is rebased onto the durable record and the
// durable active packs are staged + adopted (never activated) — together
// with the durable previous pack, so the activate and rollback routes CAS
// from the live durable versions and restore the real previous detectors
// right after a restart. The verifier resolved once by the admin startup
// applies to every hydrated manifest (nil keeps the fail-closed default). A
// hydration failure keeps the rebased lifecycle without an active hook:
// activation still works, rollback honestly answers "no active pack" until
// an activation is staged (fail-closed, never a half-claimed rollback). An
// unreadable coordination point is reported as an error — the caller keeps
// the routes unwired (503) instead of mounting a surface whose CAS
// preconditions are doomed.
func HydrateGuardPackLifecycle(ctx context.Context, pool *pgxpool.Pool, l *slog.Logger, mode guardhooks.Mode, packDir string, verifier guardhooks.SignatureVerifier) (GuardPackDurable, error) {
	cas := policystore.NewGuardPolicyCAS(pool)
	lifecycle, err := hydrateGuardPackLifecycle(ctx, cas, l, mode, packDir, verifier)
	return GuardPackDurable{Lifecycle: lifecycle, Policy: cas}, err
}

// hydrateGuardPackLifecycle is the pool-free hydration core (testable against
// a scripted coordination surface).
func hydrateGuardPackLifecycle(ctx context.Context, policy GuardPackPolicyStore, l *slog.Logger, mode guardhooks.Mode, packDir string, verifier guardhooks.SignatureVerifier) (*guardhooks.PackLifecycle, error) {
	state, err := policy.ActiveGuardPackState(ctx)
	if err != nil {
		return nil, err
	}
	current := state.ActiveVersion
	if current == "" {
		current = coreDurableVersion
	}
	lifecycle := guardhooks.NewPackLifecycleWithVerifier(current, mode, policy, verifier)
	if current == coreDurableVersion {
		// No durable pack activation (or rolled back to the built-in chain):
		// the lifecycle starts on the built-in identity with no active hook,
		// so rollback honestly answers "no active pack" until an activation
		// is staged.
		return lifecycle, nil
	}
	sources, resolveErr := resolveDurableGuardPackSources(packDir, state.ActiveVersion, verifier)
	if resolveErr == nil {
		_, resolveErr = lifecycle.StageSources(sources)
	}
	if resolveErr == nil {
		// Load the durable previous pack too: the rollback route must
		// restore the real previous detectors, not the built-in chain under
		// the previous version label. An unloadable previous degrades to an
		// unrestorable adopt (warned); rollback then answers an explicit
		// error until an activation re-anchors the history.
		resolveErr = adoptWithPrior(lifecycle, l, mode, packDir, state.PreviousVersion, verifier)
	}
	if resolveErr != nil {
		l.Warn("admin guard-pack lifecycle: durable active packs not usable on this surface — activate works, rollback answers 409 until an activation is staged",
			"active_version", state.ActiveVersion, "reason", resolveErr.Error())
		return lifecycle, nil
	}
	l.Info("admin guard-pack lifecycle hydrated from the durable policy state", "active_version", state.ActiveVersion)
	return lifecycle, nil
}

// resolveDurableGuardPackSources maps a durable active-version identity back
// to on-disk pack sources: "pack@version" (single) or the joined
// "id@version,id@version" multi-pack form — exactly the identity
// PackLifecycle.StagedVersion produces. "core" (the built-in chain) resolves
// to no sources. Each manifest is decoded under this surface's verifier (a
// declared signature without one fails closed here, so a signed durable pack
// is never resolved into a load path that could not verify it) and must
// declare exactly the requested identity, so a moved or rewritten pack
// directory fails resolution and the caller degrades loudly instead of
// enforcing the wrong pack.
func resolveDurableGuardPackSources(packRoot, identity string, verifier guardhooks.SignatureVerifier) ([]guardhooks.PackSource, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return nil, errors.New("empty durable guard pack identity")
	}
	if identity == coreDurableVersion {
		return nil, nil
	}
	var sources []guardhooks.PackSource
	seen := make(map[string]struct{})
	for _, part := range strings.Split(identity, ",") {
		packID, version, ok := strings.Cut(strings.TrimSpace(part), "@")
		if !ok || packID == "" || version == "" || filepath.Base(packID) != packID || packID == "." || packID == ".." {
			return nil, fmt.Errorf("malformed durable guard pack identity %q", part)
		}
		if _, dup := seen[packID]; dup {
			continue
		}
		seen[packID] = struct{}{}
		manifestPath := filepath.Join(packRoot, packID, "manifest.json")
		manifest, err := os.ReadFile(manifestPath) // #nosec G304 -- packID is validated as a single clean path component; the root is operator-configured.
		if err != nil {
			return nil, fmt.Errorf("read manifest for durable pack %q: %w", packID, err)
		}
		decoded, err := guardhooks.DecodePackManifestWithVerifier(manifest, verifier)
		if err != nil {
			return nil, fmt.Errorf("decode manifest for durable pack %q: %w", packID, err)
		}
		if decoded.PackID != packID || decoded.PackVersion != version {
			return nil, fmt.Errorf("durable pack %s@%s not found on disk (manifest declares %s@%s)", packID, version, decoded.PackID, decoded.PackVersion)
		}
		sources = append(sources, guardhooks.PackSource{Root: filepath.Join(packRoot, packID), Manifest: manifest})
	}
	return sources, nil
}
