package router

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/reireirei/yabanin/pkg/classifier"
)

//
// D1: the quality source is a VERSIONED snapshot (identity = version string,
// e.g. an agenteval run id) with per-model aggregate scores.
// D2: application is owner-approved only — the runtime consumes snapshots
// handed to it; approving/rotating them is an owner action, never automatic.
// D3: the surface is the existing per-org routing_mode ("quality").
// D4: an overlap comparison (vN vs vN+1) is the evidence required before any
// traffic shift; CompareQualitySnapshots provides it and NEVER switches
// anything by itself.
//
// Test-set leak invariant: QualitySnapshot can carry ONLY model names,
// aggregate scores/sample counts and version/provenance metadata. There is no
// field that could hold an eval episode, case row, prompt or verdict — the
// type pins the invariant by construction.

// QualityMinSamples is the minimum number of evaluated samples a model needs
// before its score may steer routing (mirrors the adminstore
// qualityMinVerdicts=20 floor). Below it the model is treated as
// insufficient data and the selection falls back to the classifier path.
const QualityMinSamples = 20

// Fallback reasons reported in QualityOutcome (surfaced by the gateway as
// decision Reason "quality_fallback:<reason>").
const (
	QualityFallbackNoSnapshot        = "no_snapshot"
	QualityFallbackSourceUnavailable = "source_unavailable"
	QualityFallbackStale             = "stale_snapshot"
	QualityFallbackInsufficientData  = "insufficient_data"
	// QualityFallbackUnprovenanced reports a snapshot whose provenance is
	// damaged (no version identity and/or no creation time). Serve-time
	// staleness (Fresh) is a caller policy over a maxAge; a snapshot with
	// NO provenance at all is unusable at every age, so the router refuses
	// it itself — not only via the caller's freshness gate — and degrades
	// to the unchanged classifier selection (N09-P03-T04: stale/unversioned
	// scores never steer production routing).
	QualityFallbackUnprovenanced = "unprovenanced_snapshot"
)

// UsableForRouting reports whether a snapshot carries the provenance the
// quality path requires to steer traffic: a version identity (D1) and a
// creation time (the anchor the freshness contract measures from). A snapshot
// without either is damaged provenance and never steers routing.
func (s *QualitySnapshot) UsableForRouting() bool {
	return s != nil && s.Version != "" && !s.CreatedAt.IsZero()
}

// ErrQualityUnavailable is returned by QualitySource implementations when no
// usable snapshot exists for the org. The gateway treats it (and any other
// source error) as an explicit fallback to the unchanged classifier path.
var ErrQualityUnavailable = errors.New("quality source unavailable")

// QualityScore is the measured quality of one model: an aggregate score
// (conventionally [0,1]) and the number of evaluated samples behind it.
type QualityScore struct {
	Score   float64 `json:"score"`
	Samples int     `json:"samples"`
}

// QualitySnapshot is a versioned, org-scoped view of measured model quality.
// Overall holds class-agnostic scores; PerClass, when a source provides a
// class split, overrides Overall for that class. PolicyProfile names the
// evaluation policy profile the run executed under (the manifest profile),
// when the source records it: two snapshots with different, non-empty
// profiles measure different metric populations and are not comparable
// evidence for a traffic shift.
type QualitySnapshot struct {
	Version       string                                       `json:"version"`
	Source        string                                       `json:"source,omitempty"`
	CreatedAt     time.Time                                    `json:"created_at"`
	GitCommit     string                                       `json:"git_commit,omitempty"`
	DatasetDigest string                                       `json:"dataset_digest,omitempty"`
	PolicyProfile string                                       `json:"policy_profile,omitempty"`
	Overall       map[string]QualityScore                      `json:"overall,omitempty"`
	PerClass      map[classifier.Class]map[string]QualityScore `json:"per_class,omitempty"`
}

// ScoresFor returns the score table to use for a class: the class-specific
// table when present, otherwise the overall one.
func (s *QualitySnapshot) ScoresFor(cls classifier.Class) map[string]QualityScore {
	if s == nil {
		return nil
	}
	if m, ok := s.PerClass[cls]; ok && len(m) > 0 {
		return m
	}
	return s.Overall
}

// Fresh reports whether the snapshot is within maxAge of now. A zero
// CreatedAt or a future-dated snapshot is never fresh (fail-closed: an
// unversioned or forged-fresh source must not steer traffic).
func (s *QualitySnapshot) Fresh(maxAge time.Duration, now time.Time) bool {
	if s == nil || s.CreatedAt.IsZero() {
		return false
	}
	age := now.Sub(s.CreatedAt)
	return age >= 0 && age <= maxAge
}

// QualitySource serves the owner-approved quality snapshot for an org (D1/D2).
// Implementations must be read-only at runtime: snapshot creation, versioning
// and approval happen out-of-band.
type QualitySource interface {
	QualitySnapshot(ctx context.Context, orgID string) (*QualitySnapshot, error)
}

// QualityOutcome explains how quality participated in a selection: Used with
// the snapshot Version, or a FallbackReason naming why the classifier path
// decided instead ("" when quality was not consulted at all).
type QualityOutcome struct {
	Used           bool
	Version        string
	FallbackReason string
}

// SelectModelWithQuality picks the model for cls the same way
// SelectModelWithAffinity does — identical pool resolution, empty-pool
// fallback chain and per-org sovereignty filter (PB4.5 is never bypassed) —
// but inside that already-filtered pool the VERSIONED quality ranking decides
// instead of weighted round-robin.
//
// When snap is nil, no pool model has >= QualityMinSamples evaluated samples,
// or the router errors, the existing affinity/weighted selection runs
// unchanged and the outcome carries the fallback reason. The KV-cache
// affinity preference never overrides a strictly better score; it only breaks
// ties between equally scored candidates.
func (tr *TierRouter) SelectModelWithQuality(ctx context.Context, cls classifier.Class, orgID, preferredModel string, snap *QualitySnapshot) (ModelInfo, QualityOutcome, error) {
	pools, err := tr.ensureLoaded(ctx)
	if err != nil {
		return ModelInfo{}, QualityOutcome{}, err
	}
	pool, err := tr.resolvePolicyPool(ctx, pools, cls, orgID)
	if err != nil {
		return ModelInfo{}, QualityOutcome{}, err
	}
	if snap != nil {
		// Damaged provenance (no version identity, no creation time) never
		// steers — the caller's freshness gate already refuses such
		// snapshots, and the router enforces the same floor independently so
		// the invariant holds regardless of caller.
		if !snap.UsableForRouting() {
			m := tr.selectPreferredOrWeighted(ctx, pool, orgID, preferredModel)
			return m, QualityOutcome{Version: snap.Version, FallbackReason: QualityFallbackUnprovenanced}, nil
		}
		if best, ok := pickBestQualityModel(pool, snap.ScoresFor(cls), preferredModel); ok {
			return best, QualityOutcome{Used: true, Version: snap.Version}, nil
		}
		m := tr.selectPreferredOrWeighted(ctx, pool, orgID, preferredModel)
		return m, QualityOutcome{Version: snap.Version, FallbackReason: QualityFallbackInsufficientData}, nil
	}
	m := tr.selectPreferredOrWeighted(ctx, pool, orgID, preferredModel)
	return m, QualityOutcome{FallbackReason: QualityFallbackNoSnapshot}, nil
}

// pickBestQualityModel returns the highest-scoring pool model with at least
// QualityMinSamples samples. Only models present in the (policy-filtered)
// pool can win — score entries for other models are ignored. Iteration
// follows the pool order, so equal scores resolve stably; the affinity
// preference may only claim a tie.
func pickBestQualityModel(pool []ModelInfo, scores map[string]QualityScore, preferredModel string) (ModelInfo, bool) {
	var best ModelInfo
	var bestScore float64
	found := false
	for _, m := range pool {
		s, ok := scores[m.Name]
		if !ok || s.Samples < QualityMinSamples {
			continue
		}
		tieBreak := s.Score == bestScore && m.Name == preferredModel && best.Name != preferredModel
		if !found || s.Score > bestScore || tieBreak {
			best, bestScore, found = m, s.Score, true
		}
	}
	return best, found
}

// QualityModelDelta is one model's movement between two snapshot versions.
type QualityModelDelta struct {
	Model    string       `json:"model"`
	Previous QualityScore `json:"previous"`
	Next     QualityScore `json:"next"`
	Delta    float64      `json:"delta"` // Next.Score - Previous.Score
}

// QualityOverlapEvidence is the D4 proof computed over the vN/vN+1 model
// intersection BEFORE any traffic shift. ShiftAllowed=false means "hold":
// the next-version favorite lacks data, lacks a baseline, or regressed.
type QualityOverlapEvidence struct {
	PreviousVersion string              `json:"previous_version"`
	NextVersion     string              `json:"next_version"`
	Compared        []QualityModelDelta `json:"compared"`
	BestNextModel   string              `json:"best_next_model"`
	BestNextScore   float64             `json:"best_next_score"`
	Regression      bool                `json:"regression"`
	ShiftAllowed    bool                `json:"shift_allowed"`
	Reason          string              `json:"reason"`
}

// qualityScoreEpsilon absorbs float noise when comparing scores.
const qualityScoreEpsilon = 1e-9

// CompareQualitySnapshots compares the proposed next snapshot against the currently applied one on
// their model intersection and reports whether the next-version favorite may
// take traffic. It is EVIDENCE ONLY — nothing here applies, switches or
// snapshots anything; the shift itself stays owner-approved (D2).
//
// Fail-closed rules:
//   - profiles recorded on both sides but different                    → hold (profile_mismatch)
//   - no next-version model with >= minSamples samples → hold (insufficient_data)
//   - favorite not measured in prev (no baseline overlap)       → hold (no_baseline_overlap)
//   - favorite's next score below its previous score            → hold (favorite_regressed)
//   - otherwise                                                  → shift allowed (overlap_ok)
//
// minSamples <= 0 falls back to QualityMinSamples.
func CompareQualitySnapshots(prev, next *QualitySnapshot, minSamples int) QualityOverlapEvidence {
	if minSamples <= 0 {
		minSamples = QualityMinSamples
	}
	ev := QualityOverlapEvidence{ShiftAllowed: false}
	if next != nil {
		ev.NextVersion = next.Version
	}
	if prev != nil {
		ev.PreviousVersion = prev.Version
	}
	// Provenance conflict: snapshots recorded under different evaluation
	// policy profiles are not comparable — an overlap computed across them
	// would compare different metric populations and could dress a shift in
	// false evidence. Fail closed (hold). A missing profile on either side
	// is absence, not conflict, so legacy snapshots still compare on their
	// model overlap.
	if prev != nil && next != nil &&
		prev.PolicyProfile != "" && next.PolicyProfile != "" &&
		prev.PolicyProfile != next.PolicyProfile {
		ev.Reason = "profile_mismatch"
		return ev
	}
	if next == nil || len(next.Overall) == 0 {
		ev.Reason = "insufficient_data"
		return ev
	}

	// Favorite: best next-version score among sufficiently sampled models;
	// ties resolve to the alphabetically first model for determinism.
	names := make([]string, 0, len(next.Overall))
	for name, s := range next.Overall {
		if s.Samples >= minSamples {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		ev.Reason = "insufficient_data"
		return ev
	}
	sort.Strings(names)
	fav := names[0]
	for _, name := range names {
		if next.Overall[name].Score > next.Overall[fav].Score {
			fav = name
		}
	}
	ev.BestNextModel = fav
	ev.BestNextScore = next.Overall[fav].Score

	// Deltas over the intersection (sorted for stable evidence output).
	if prev != nil {
		inter := make([]string, 0, len(prev.Overall))
		for name := range prev.Overall {
			if _, ok := next.Overall[name]; ok {
				inter = append(inter, name)
			}
		}
		sort.Strings(inter)
		for _, name := range inter {
			p, n := prev.Overall[name], next.Overall[name]
			ev.Compared = append(ev.Compared, QualityModelDelta{
				Model: name, Previous: p, Next: n, Delta: n.Score - p.Score,
			})
		}
	}

	if prev == nil {
		ev.Reason = "no_baseline_overlap"
		return ev
	}
	prevScore, hasBaseline := prev.Overall[fav]
	if !hasBaseline {
		ev.Reason = "no_baseline_overlap"
		return ev
	}
	if next.Overall[fav].Score < prevScore.Score-qualityScoreEpsilon {
		ev.Regression = true
		ev.Reason = "favorite_regressed"
		return ev
	}
	ev.ShiftAllowed = true
	ev.Reason = "overlap_ok"
	return ev
}
