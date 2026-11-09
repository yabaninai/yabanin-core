package cli

// Runtime guard-pack adoption for RUNNING gateway replicas (FIX-03, audit
// CA-02): the gateway used to capture lifecycle.ActiveHook() once at startup,
// so after an admin-API activation every already-running replica kept
// enforcing the old detectors until restart. This file closes that gap with
// two mechanisms and a defined convergence contract:
//
//   - Per-request atomic snapshot: gw.guardHook() resolves the CURRENT hook
//     for every request — the live lifecycle when no runtime watcher is
//     wired (same-process Activate/Rollback, e.g. the audit scenario), or
//     one atomic pointer load of the watcher's hook snapshot otherwise.
//     Hook values are immutable and safe for concurrent Apply, so no request
//     can observe torn state: every request enforces exactly one valid
//     version — never a mixture of two.
//   - Durable version adoption: a background watcher probes the durable
//     guard_pack_state row (one lightweight single-row read) on an interval
//     with jitter and atomically swaps the enforced hook when the durable
//     version moved. Pack chains are materialized statelessly with
//     guardhooks.LoadPackHookWithVerifier (no lifecycle history is touched)
//     and never write the durable row — the admin process remains the only
//     CAS writer.
//
// Convergence contract (FIX-03, defined before the acceptance tests):
//
//   C1 (intra-process): a request that begins after Activate/Rollback
//      returned on the process's own lifecycle observes the post-transition
//      hook. No interval involved.
//   C2 (cross-process): a durable activation/rollback visible in the row at
//      time T is enforced by every healthy replica no later than
//      T + 2×interval + materialize (default interval 2s, ±20% jitter ⇒
//      ≲4.8s plus pack load). The integration test asserts adoption within
//      10s of the activation.
//   C3 (last known good): a failed probe (store unreadable) or a failed
//      materialization (pack missing/corrupt on this replica) keeps the
//      previous hook enforcing; the failure is surfaced on every failed
//      probe (Warn log carrying requested_version vs applied_version plus
//      gateway_guard_pack_watch_failures_total); the process never crashes
//      on it.
//   C4 (no stranded replica): probes repeat every interval, so a lost or
//      failed adoption converges on the first successful probe after
//      recovery — at most one interval later. A replica can never be stuck
//      on a stale version longer than the store/pack outage plus one
//      interval.

import (
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/metrics"
)

const (
	// guardPackWatchInterval is the durable-version probe cadence (C2/C4).
	guardPackWatchInterval = 2 * time.Second
	// guardPackWatchJitter de-synchronizes replicas so they do not probe the
	// store in lockstep; it also bounds the contract's jitter term.
	guardPackWatchJitter = 0.2
)

// guardPackWatcher adopts durable guard-pack activations into a running
// replica. It owns the atomic hook snapshot the request path reads and is
// the only runtime mutator of that snapshot (single writer, atomic readers).
type guardPackWatcher struct {
	store    GuardPackPolicyStore
	packRoot string
	mode     guardhooks.Mode
	log      *slog.Logger
	interval time.Duration
	// verifier is the static pack-signature verifier resolved once at
	// startup (nil = no verifier configured): every materialized manifest is
	// decoded under it, so a signed durable pack can only be adopted after
	// its signature verifies on this replica too.
	verifier guardhooks.SignatureVerifier

	// hook is the enforced chain: never nil after construction, swapped
	// atomically by the watcher. Readers load it once per request.
	hook atomic.Pointer[guardhooks.Hook]
	// applied is the durable version identity currently enforced; empty
	// until the first probe materializes the row (the startup hook is
	// trusted for requests in that window — it reflects the row by the
	// startup reconciliation contract).
	applied atomic.Value // string
}

// newGuardPackWatcher builds the watcher around the startup hook. The
// lifecycle that produced it stays the authority for same-process
// transitions; the watcher only ever replaces the snapshot from the durable
// row (under the same signature verifier the startup used).
func newGuardPackWatcher(store GuardPackPolicyStore, l *slog.Logger, mode guardhooks.Mode, packRoot string, initial *guardhooks.Hook, verifier guardhooks.SignatureVerifier) *guardPackWatcher {
	if initial == nil {
		initial = guardhooks.New(mode)
	}
	w := &guardPackWatcher{
		store:    store,
		packRoot: packRoot,
		mode:     mode,
		log:      l,
		interval: guardPackWatchInterval,
		verifier: verifier,
	}
	w.hook.Store(initial)
	return w
}

// currentHook returns the enforced chain (one atomic load per request).
func (w *guardPackWatcher) currentHook() *guardhooks.Hook {
	if w == nil {
		return nil
	}
	return w.hook.Load()
}

// appliedVersion reports the durable version identity currently enforced
// ("" until the first successful probe).
func (w *guardPackWatcher) appliedVersion() string {
	applied, _ := w.applied.Load().(string)
	return applied
}

// Run probes until ctx is cancelled. The first probe fires immediately so a
// replica that started behind the durable row (or degraded at startup)
// converges right away, then probes continue on the jittered interval.
func (w *guardPackWatcher) Run(ctx context.Context) {
	w.probeOnce(ctx)
	timer := time.NewTimer(w.nextDelay())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			w.probeOnce(ctx)
			timer.Reset(w.nextDelay())
		}
	}
}

// nextDelay returns the interval with ±jitter. The jitter source is
// crypto/rand (gosec G404-clean): nothing here needs a reproducible or
// statistically certified sequence, but a security scanner cannot tell
// jitter from value generation, and one 8-byte read per probe interval is
// free — so the weak-source question never arises.
func (w *guardPackWatcher) nextDelay() time.Duration {
	factor := 1 + guardPackWatchJitter*(2*jitterFloat64()-1)
	return time.Duration(float64(w.interval) * factor)
}

// jitterFloat64 returns a uniform float64 in [0,1) from the
// cryptographically secure source, degenerating to the un-jittered midpoint
// if the OS source is unreadable (jitter is a load-shaping nicety, never a
// correctness input — the contract bounds hold with any constant).
func jitterFloat64() float64 {
	var buf [8]byte
	if _, err := crand.Read(buf[:]); err != nil {
		return 0.5
	}
	return float64(binary.LittleEndian.Uint64(buf[:])>>11) / (1 << 53)
}

// probeOnce is one durable-version check (C2/C3/C4). Any failure keeps the
// last known-good hook enforcing and is surfaced with both versions.
func (w *guardPackWatcher) probeOnce(ctx context.Context) {
	state, err := w.store.ActiveGuardPackState(ctx)
	if err != nil {
		metrics.GuardPackWatchFailuresTotal.Inc()
		w.log.Warn("guard pack runtime probe failed — keeping last known-good hook",
			"applied_version", w.appliedVersion(), "reason", err.Error())
		return
	}
	requested := state.ActiveVersion
	if requested == "" {
		requested = coreDurableVersion
	}
	if requested == w.appliedVersion() {
		return
	}
	hook, err := w.materialize(requested)
	if err != nil {
		metrics.GuardPackWatchFailuresTotal.Inc()
		w.log.Warn("guard pack runtime adoption failed — keeping last known-good hook",
			"requested_version", requested, "applied_version", w.appliedVersion(),
			"reason", err.Error())
		return
	}
	w.hook.Store(hook)
	w.applied.Store(requested)
	metrics.GuardPackRuntimeAdoptionsTotal.Inc()
	w.log.Info("guard pack runtime adoption applied",
		"requested_version", requested, "applied_version", requested, "mode", string(w.mode))
}

// materialize builds the hook chain for a durable version identity WITHOUT
// touching lifecycle history and without writing the durable row: "core" is
// the built-in chain (the durable rollback posture), anything else must
// resolve from the pack root and verify — exactly the stateless loader the
// hydration path uses for runtime materialization, under this process's
// pack-signature verifier (a tampered or unverifiable signed pack fails
// here, and probeOnce keeps the last known-good hook enforcing).
func (w *guardPackWatcher) materialize(requested string) (*guardhooks.Hook, error) {
	if requested == coreDurableVersion {
		return guardhooks.New(w.mode), nil
	}
	sources, err := resolveDurableGuardPackSources(w.packRoot, requested, w.verifier)
	if err != nil {
		return nil, err
	}
	return guardhooks.LoadPackHookWithVerifier(w.mode, w.verifier, sources)
}
