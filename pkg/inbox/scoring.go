// Scoring law for the unified security inbox (E06-P01 W03-C01).
//
// Two SEPARATE semantics live here, and they are deliberately not
// interchangeable:
//
//   - Severity answers "how bad" (model.go dictionary low|medium|high,
//     pinned by the 0027 CHECK). Its only source is the finding verdicts
//     carried by the folded events; the group law is escalation = max.
//   - Confidence answers "how well grouped" (0..1). Its sources are
//     grouping-quality signals only: source completeness, event count
//     (corroboration) and dedup certainty. Verdict words NEVER enter it,
//     and event counts NEVER enter severity — the independence test in
//     scoring_test.go pins both directions.
//
// This file is the pure law. Wiring it into the projection (replacing the
// provisional constants in projection.go) is the next dependent card's
// change; until then projection.go keeps provisionalSeverity/
// provisionalConfidence and this package's law is consumed by tests and
// the W03-C03 contract guard.

package inbox

import (
	"errors"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/secevents"
)

// ErrNoEvents reports a scoring call over an empty fold. An incident always
// has at least one source event (model Validate: EventCount >= 1), so an
// empty input is a caller bug, not a zero-severity incident.
var ErrNoEvents = errors.New("inbox: scoring: at least one event required")

// ErrNoVerdict reports a fold in which NO event carries a readable finding
// verdict. Scoring refuses to invent a severity for such a group: the caller
// decides the fallback (the projection keeps its provisional value), the law
// never silently degrades an unreadable group to "low".
var ErrNoVerdict = errors.New("inbox: scoring: no readable finding verdict in fold")

// ErrUnreadableVerdict reports a summary that carries a severity= token
// which is not a dictionary word — a truncated token (the 1024-byte
// TrimSummary cap cutting mid-word), an empty value, or an out-of-
// dictionary word. Presence-but-corrupt is a data-integrity problem and
// fails closed: it must not be read as "no verdict" (that would understate
// severity) nor skipped in favor of another token.
var ErrUnreadableVerdict = errors.New("inbox: scoring: unreadable severity token")

// severityRank orders the dictionary for the escalation (max) law.
func severityRank(s string) (int, bool) {
	switch s {
	case SeverityLow:
		return 0, true
	case SeverityMedium:
		return 1, true
	case SeverityHigh:
		return 2, true
	}
	return -1, false
}

// Escalate is the group severity law: the maximum of the given verdict
// words. An empty argument list or any non-dictionary word is an error —
// escalation never invents or silently drops a verdict it cannot rank.
func Escalate(severities ...string) (string, error) {
	if len(severities) == 0 {
		return "", fmt.Errorf("%w: escalate needs at least one verdict", ErrNoVerdict)
	}
	best, bestRank := "", -1
	for _, s := range severities {
		rank, ok := severityRank(s)
		if !ok {
			return "", fmt.Errorf("%w: %q not in the low|medium|high dictionary", ErrUnreadableVerdict, s)
		}
		if rank > bestRank {
			best, bestRank = s, rank
		}
	}
	return best, nil
}

// verdictTokenPrefix is the summary token prefix the adapter writes for
// every finding (pkg/secevents/adapter.go buildFindingEvents):
//
//	"policy <name> v<version> <mode>: <step> category=<c> severity=<s> action=<a>"
//
// The wire schema (secevents schema.go wire) has no structured severity
// field in v1, so this token is the ONLY carrier of the finding verdict.
const verdictTokenPrefix = "severity="

// EventVerdict recovers one event's finding verdict from its summary.
//
//   - ok=true: a dictionary verdict was recovered; severity is it.
//   - ok=false, err=nil: the summary carries no severity= token at all —
//     the event is not findings-shaped and contributes no severity signal
//     (it still counts toward the confidence denominators).
//   - err!=nil: a severity= token exists but is unreadable (truncated,
//     empty or out-of-dictionary) — fail closed, refuse to score.
//
// If more than one well-formed token is present (only possible through
// producer-side injection into the free-text name/step fields), the MAXIMUM
// is returned: an injected token must not be able to lower a real verdict.
func EventVerdict(e secevents.Event) (severity string, ok bool, err error) {
	return VerdictFromSummary(e.Summary)
}

// VerdictFromSummary is EventVerdict over a raw summary string.
func VerdictFromSummary(summary string) (string, bool, error) {
	best, bestRank := "", -1
	for _, tok := range strings.Fields(summary) {
		if !strings.HasPrefix(tok, verdictTokenPrefix) {
			continue
		}
		word := strings.TrimPrefix(tok, verdictTokenPrefix)
		rank, ok := severityRank(word)
		if !ok {
			return "", false, fmt.Errorf("%w: token %q in summary %q", ErrUnreadableVerdict, tok, summary)
		}
		if rank > bestRank {
			best, bestRank = word, rank
		}
	}
	if bestRank < 0 {
		return "", false, nil
	}
	return best, true, nil
}

// Score is the computed severity+confidence pair of one folded group. The
// two fields are the two independent semantics of the W03-C01 card.
type Score struct {
	// Severity is the escalated finding verdict (low|medium|high).
	Severity string
	// Confidence is the grouping-quality score in [0,1].
	Confidence float64
}

// Confidence weights: source completeness dominates (a damaged or
// evidence-less source undermines the incident regardless of volume),
// corroboration (event count) is the main grouping-quality gain, and dedup
// certainty is a normally-saturated health flag (it is 1 whenever the fold
// carries no duplicate event ids). The weights sum to 1, so confidence is
// a convex combination and stays in [0,1] by construction.
const (
	weightCompleteness   = 0.6
	weightCorroboration  = 0.3
	weightDedupCertainty = 0.1
)

// ScoreEvents computes the W03-C01 scoring law over a fold.
//
// Determinism: every input is a count or a max over dictionary words, so
// the result is independent of slice order (pinned by test) and of time.
//
// Confidence = 0.6*completeness + 0.3*corroboration + 0.1*dedupCertainty:
//
//   - completeness: share of events that are complete sources — a readable
//     finding verdict AND at least one evidence reference.
//   - corroboration: (n-1)/(n+3) over the fold size n — a single event
//     contributes 0 (an isolated finding is the weakest group), the signal
//     saturates towards 1 as events accumulate.
//   - dedupCertainty: distinct event ids / n. The durable store dedups by
//     event id (ON CONFLICT DO NOTHING), so a healthy fold is exactly 1.0;
//     a lower value flags duplicate-laden input (double reads, replay
//     overlap) whose grouping quality is suspect.
//
// Severity = Escalate over the readable verdicts; a fold with NO readable
// verdict is ErrNoVerdict (fail-closed — the caller keeps its fallback,
// the law never invents "low").
func ScoreEvents(events []secevents.Event) (Score, error) {
	if len(events) == 0 {
		return Score{}, ErrNoEvents
	}
	verdicts := make([]string, 0, len(events))
	complete := 0
	ids := make(map[string]struct{}, len(events))
	for _, e := range events {
		sev, ok, err := EventVerdict(e)
		if err != nil {
			return Score{}, err
		}
		if ok {
			verdicts = append(verdicts, sev)
			if len(e.Evidence) > 0 {
				complete++
			}
		}
		if e.EventID != "" {
			ids[e.EventID] = struct{}{}
		}
	}
	if len(verdicts) == 0 {
		return Score{}, ErrNoVerdict
	}
	severity, err := Escalate(verdicts...)
	if err != nil {
		return Score{}, err // unreachable via the loop above; kept for law independence
	}
	n := float64(len(events))
	confidence := weightCompleteness*(float64(complete)/n) +
		weightCorroboration*((n-1)/(n+3)) +
		weightDedupCertainty*(float64(len(ids))/n)
	return Score{Severity: severity, Confidence: confidence}, nil
}
