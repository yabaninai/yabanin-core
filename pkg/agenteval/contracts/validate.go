package contracts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// costEpsilon is the maximum tolerated |episode_estimate − Σ call costs|
// difference before the validator reports double counting or drift.
const costEpsilon = 1e-6

// Validate checks a run directory against the journal contract:
// schema-conformant JSON/JSONL, unique IDs, referential integrity, and the
// money invariants of plan §Г.6 (unknown ≠ zero, no double counting).
// Error messages carry identifiers and line numbers only.
func Validate(dir string) error {
	var errs []error
	add := func(err error) { errs = append(errs, err) }

	manifest, err := loadManifest(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	if manifest.SchemaVersion != SchemaVersion {
		add(fmt.Errorf("manifest.schema_version = %d, want %d", manifest.SchemaVersion, SchemaVersion))
	}
	if !uuidRe.MatchString(manifest.RunID) {
		add(fmt.Errorf("manifest.run_id %q is not a canonical UUID", manifest.RunID))
	}
	if len(manifest.Arms) == 0 {
		add(fmt.Errorf("manifest.arms is empty"))
	}
	if err := ValidateTaskTag(profileTaskTag(manifest.Profile)); err != nil && manifest.Profile != "" {
		add(err)
	}

	episodeRecs, err := loadJSONL[EpisodeRecord](filepath.Join(dir, "episodes.jsonl"))
	if err != nil {
		return fmt.Errorf("episodes.jsonl: %w", err)
	}
	episodeIDs := map[string]int{} // id → line
	var episodes []EpisodeRecord
	for _, lr := range episodeRecs {
		rec := lr.Rec
		episodes = append(episodes, rec)
		if !rec.ExecutionStatus.Valid() {
			add(fmt.Errorf("episodes.jsonl line %d: unknown execution_status %q", lr.Line, rec.ExecutionStatus))
		}
		if prev, dup := episodeIDs[rec.EpisodeID]; dup {
			add(fmt.Errorf("episodes.jsonl line %d: duplicate episode_id %q (first seen line %d)", lr.Line, rec.EpisodeID, prev))
			continue
		}
		episodeIDs[rec.EpisodeID] = lr.Line
		if rec.RootID == "" {
			add(fmt.Errorf("episodes.jsonl line %d: empty root_id", lr.Line))
		}
	}

	callRecs, err := loadJSONL[CallRecord](filepath.Join(dir, "calls.jsonl"))
	if err != nil {
		return fmt.Errorf("calls.jsonl: %w", err)
	}
	callIDs := map[string]int{}
	callCostByEpisode := map[string]float64{}
	callCostUnknown := map[string]bool{}
	for _, lr := range callRecs {
		rec := lr.Rec
		if prev, dup := callIDs[rec.CallID]; dup {
			add(fmt.Errorf("calls.jsonl line %d: duplicate call_id %q (first seen line %d)", lr.Line, rec.CallID, prev))
			continue
		}
		callIDs[rec.CallID] = lr.Line
		if _, ok := episodeIDs[rec.EpisodeID]; !ok {
			add(fmt.Errorf("calls.jsonl line %d: call %q references unknown episode_id %q", lr.Line, rec.CallID, rec.EpisodeID))
		}
		switch rec.Status {
		case "ok", "error", "timeout":
		default:
			add(fmt.Errorf("calls.jsonl line %d: call %q has invalid status %q", lr.Line, rec.CallID, rec.Status))
		}
		if rec.Cost.ObservedUSD == nil {
			if rec.Status == "ok" && !rec.Cost.Uncertain {
				add(fmt.Errorf("calls.jsonl line %d: call %q is ok with unknown observed cost but uncertain=false", lr.Line, rec.CallID))
			}
			callCostUnknown[rec.EpisodeID] = true
		} else {
			callCostByEpisode[rec.EpisodeID] += *rec.Cost.ObservedUSD
		}
	}

	toolRecs, err := loadJSONL[ToolEvent](filepath.Join(dir, "tools.jsonl"))
	if err != nil {
		return fmt.Errorf("tools.jsonl: %w", err)
	}
	toolIDs := map[string]int{}
	for _, lr := range toolRecs {
		ev := lr.Rec
		if prev, dup := toolIDs[ev.EventID]; dup {
			add(fmt.Errorf("tools.jsonl line %d: duplicate event_id %q (first seen line %d)", lr.Line, ev.EventID, prev))
			continue
		}
		toolIDs[ev.EventID] = lr.Line
		if _, ok := callIDs[ev.CallRef]; !ok {
			add(fmt.Errorf("tools.jsonl line %d: tool event %q references unknown call_ref %q", lr.Line, ev.EventID, ev.CallRef))
		}
		if _, ok := episodeIDs[ev.EpisodeID]; !ok {
			add(fmt.Errorf("tools.jsonl line %d: tool event %q references unknown episode_id %q", lr.Line, ev.EventID, ev.EpisodeID))
		}
		if ev.Phase == "denied" && (ev.DenyReason == nil || *ev.DenyReason == "") {
			add(fmt.Errorf("tools.jsonl line %d: denied tool event %q has no deny_reason", lr.Line, ev.EventID))
		}
	}

	verdictRecs, err := loadJSONL[VerdictRecord](filepath.Join(dir, "verdicts.jsonl"))
	if err != nil {
		return fmt.Errorf("verdicts.jsonl: %w", err)
	}
	verdictIDs := map[string]int{}
	for _, lr := range verdictRecs {
		v := lr.Rec
		if prev, dup := verdictIDs[v.VerdictID]; dup {
			add(fmt.Errorf("verdicts.jsonl line %d: duplicate verdict_id %q (first seen line %d)", lr.Line, v.VerdictID, prev))
			continue
		}
		verdictIDs[v.VerdictID] = lr.Line
		if _, ok := episodeIDs[v.EpisodeID]; !ok {
			add(fmt.Errorf("verdicts.jsonl line %d: verdict %q references unknown episode_id %q", lr.Line, v.VerdictID, v.EpisodeID))
		}
	}

	for _, ep := range episodes {
		if ep.Cost.EstimatedUSD == nil || callCostUnknown[ep.EpisodeID] {
			continue // uncertain episodes are exempt from the sum check
		}
		sum := callCostByEpisode[ep.EpisodeID]
		if diff := *ep.Cost.EstimatedUSD - sum; diff > costEpsilon || diff < -costEpsilon {
			add(fmt.Errorf("episode %q cost drift: estimated %.6f vs Σ calls %.6f (> %g) — double counting?",
				ep.EpisodeID, *ep.Cost.EstimatedUSD, sum, costEpsilon))
		}
	}

	return errorsJoin(errs)
}

// profileTaskTag extracts the task-tag portion the validator checks on the
// manifest profile (custom profiles use free text and are skipped).
func profileTaskTag(profile string) string { return profile }

func errorsJoin(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	sort.Slice(errs, func(i, j int) bool { return errs[i].Error() < errs[j].Error() })
	var b strings.Builder
	for i, err := range errs {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(err.Error())
	}
	return fmt.Errorf("%d validation error(s): %s", len(errs), b.String())
}

func loadManifest(path string) (Manifest, error) {
	var m Manifest
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path is the caller-provided run directory, not request input
	if err != nil {
		return m, err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return m, err
	}
	return m, nil
}

// lineRec pairs a decoded JSONL record with its 1-based source line.
type lineRec[T any] struct {
	Line int
	Rec  T
}

func loadJSONL[T any](path string) ([]lineRec[T], error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is the caller-provided run directory, not request input
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []lineRec[T]
	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var rec T
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, lineRec[T]{Line: line, Rec: rec})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
