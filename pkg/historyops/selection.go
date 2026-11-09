package historyops

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// Family names one selectable history family (02-PREVIEW-OPERATION-DESIGN §1).
// Only these five are selectable; request_lineage and policy_decisions are
// protected families (DO-NOT-TOUCH): they are never selectable, never planned
// and never destroyed.
type Family string

// Selectable history families. Wire-stable values.
const (
	FamilyRequestLogs         Family = "request_logs"
	FamilyToolCalls           Family = "tool_calls"
	FamilyToolCallInvocations Family = "tool_call_invocations"
	FamilyCacheEntries        Family = "cache_entries"
	FamilySessions            Family = "sessions"
)

// SelectableFamilies lists every family a selection may name, in canonical
// (sorted) order — the digest normalizes family order, so the canonical list
// and the digest sort must stay in sync.
var SelectableFamilies = []Family{
	FamilyCacheEntries,
	FamilyRequestLogs,
	FamilySessions,
	FamilyToolCallInvocations,
	FamilyToolCalls,
}

// protectedFamilies names families that are never selectable. Accepting them
// in a selection would put the engine on a path toward destroying lineage or
// policy data (05-DO-NOT-TOUCH), so ParseFamily refuses them explicitly.
var protectedFamilies = []string{"request_lineage", "policy_decisions"}

// ParseFamily maps a wire family name to a Family. Protected family names are
// refused with protected_family; unknown names are a malformed selection.
func ParseFamily(name string) (Family, error) {
	for _, p := range protectedFamilies {
		if name == p {
			return "", Refuse(RefusalProtectedFamily,
				"family %q is protected and cannot be selected", name)
		}
	}
	for _, f := range SelectableFamilies {
		if string(f) == name {
			return f, nil
		}
	}
	return "", fmt.Errorf("%w: unknown family %q", ErrInvalidRequest, name)
}

// Operation names a history operation. The digest binds an operation to its
// selection, so a preview's digest is replayable only for the same op.
type Operation string

// Supported operations. Values are wire-stable identifiers.
const (
	OpPreview          Operation = "preview"
	OpArchiveCopy      Operation = "archive_copy"
	OpArchiveRemoveHot Operation = "archive_and_remove_hot"
	OpPurge            Operation = "purge"
	OpRedactContent    Operation = "redact_content"
)

// AllOperations lists every operation the engine knows, including preview
// (preview jobs are enqueueable like any other job so their lifecycle —
// cancel, status, journal — is uniform).
var AllOperations = []Operation{
	OpPreview, OpArchiveCopy, OpArchiveRemoveHot, OpPurge, OpRedactContent,
}

// ValidOperation reports whether op is one of the engine's operations.
func ValidOperation(op Operation) bool {
	for _, o := range AllOperations {
		if o == op {
			return true
		}
	}
	return false
}

// needsDestination reports whether the operation requires a cold destination
// (02-PREVIEW-OPERATION-DESIGN §2: archive operations without a working
// destination are refused).
func (op Operation) needsDestination() bool {
	return op == OpArchiveCopy || op == OpArchiveRemoveHot
}

// Period is a closed [From, To] time window. A selection only ever covers
// closed periods: To must not reach into the currently open hour (the
// open-period rule, mirroring services/loggerd closedBoundary semantics).
type Period struct {
	From time.Time
	To   time.Time
}

// Validate checks the period against now. From must be strictly before To,
// and To must lie strictly before the start of the current open hour: the
// selection predicates are inclusive (created_at <= To, the exact list
// predicate), so To == boundary would pull in the boundary instant that
// belongs to the still-open period.
func (p Period) Validate(now time.Time) error {
	if p.From.IsZero() || p.To.IsZero() {
		return fmt.Errorf("%w: period from/to are required", ErrInvalidRequest)
	}
	if !p.From.Before(p.To) {
		return fmt.Errorf("%w: period from must be strictly before to", ErrInvalidRequest)
	}
	if !p.To.Before(openPeriodBoundary(now)) {
		return Refuse(RefusalOpenPeriod,
			"period reaches into the open period (boundary %s)",
			openPeriodBoundary(now).UTC().Format(time.RFC3339))
	}
	return nil
}

// openPeriodBoundary returns the start of the currently open period: only
// rows strictly older than this instant belong to fully closed objects.
// Hourly granularity, mirroring LogExporter.closedBoundary
// (services/loggerd/export_s3.go) so cleanup and cold export always agree on
// what "closed" means.
func openPeriodBoundary(now time.Time) time.Time {
	return now.UTC().Truncate(time.Hour)
}

// SelectionFilters is the cleanup-relevant, metadata-only subset of the
// request-list filter surface. Deliberately absent: ContentSearch (q) and
// Query (YQL) — content selectors are refused at parse time per the
// catalogue, so they cannot sneak into a digest. Struct-typed fields keep the
// canonical marshal deterministic (digest scheme §4).
type SelectionFilters struct {
	Model        string  `json:"model,omitempty"`
	ErrorOnly    bool    `json:"error_only,omitempty"`
	MinStatus    int     `json:"min_status,omitempty"`
	TaskID       string  `json:"task_id,omitempty"`
	AgentID      string  `json:"agent_id,omitempty"`
	RequestID    string  `json:"request_id,omitempty"`
	MinLatencyMs int64   `json:"min_latency_ms,omitempty"`
	MaxLatencyMs int64   `json:"max_latency_ms,omitempty"`
	MinTokens    int64   `json:"min_tokens,omitempty"`
	MaxTokens    int64   `json:"max_tokens,omitempty"`
	MinCostUSD   float64 `json:"min_cost_usd,omitempty"`
	MaxCostUSD   float64 `json:"max_cost_usd,omitempty"`
	CacheHit     string  `json:"cache_hit,omitempty"`
}

// validate rejects malformed bounds early so no malformed selection reaches a
// digest or a job row.
func (f SelectionFilters) validate() error {
	if f.MinStatus < 0 || f.MinLatencyMs < 0 || f.MaxLatencyMs < 0 ||
		f.MinTokens < 0 || f.MaxTokens < 0 || f.MinCostUSD < 0 || f.MaxCostUSD < 0 {
		return fmt.Errorf("%w: negative filter bounds", ErrInvalidRequest)
	}
	switch f.CacheHit {
	case "", "exact", "semantic", "miss":
	default:
		return fmt.Errorf("%w: cache_hit must be exact|semantic|miss", ErrInvalidRequest)
	}
	return nil
}

// applyTo copies the selection filters into an adminstore.RequestListFilters
// so downstream counting (preview) and planning (operation runners) reuse the
// exact list predicate (requestListWhere) instead of a drifting second filter
// builder. Page/PageSize stay zero: history operations are never paginated.
func (f SelectionFilters) applyTo(rl adminstore.RequestListFilters) adminstore.RequestListFilters {
	rl.Model = f.Model
	rl.TaskID = f.TaskID
	rl.AgentID = f.AgentID
	rl.RequestID = f.RequestID
	rl.ErrorOnly = f.ErrorOnly
	rl.MinStatus = f.MinStatus
	rl.CacheHit = f.CacheHit
	rl.MinLatencyMs = f.MinLatencyMs
	rl.MaxLatencyMs = f.MaxLatencyMs
	rl.MinTokens = f.MinTokens
	rl.MaxTokens = f.MaxTokens
	rl.MinCostUSD = f.MinCostUSD
	rl.MaxCostUSD = f.MaxCostUSD
	return rl
}

// Selection is the identity of what an operation would affect: org (and
// optional team), a closed period, explicit families and metadata filters.
// The selection tuple (§1) is the digest input — two selections with equal
// canonical encodings MUST produce the same digest.
type Selection struct {
	OrgID    string           `json:"org_id"`
	TeamID   string           `json:"team_id,omitempty"`
	Period   Period           `json:"-"`
	From     string           `json:"period_from"` // RFC3339, canonicalized to UTC
	To       string           `json:"period_to"`   // RFC3339, canonicalized to UTC
	Families []Family         `json:"families"`
	Filters  SelectionFilters `json:"filters"`
}

// NewSelection builds and validates a selection. Family order is normalized
// (canonical sorted order) so digest inputs are order-insensitive.
func NewSelection(orgID, teamID string, period Period, families []Family, filters SelectionFilters, now time.Time) (Selection, error) {
	if orgID == "" {
		return Selection{}, fmt.Errorf("%w: org is required", ErrInvalidRequest)
	}
	if err := filters.validate(); err != nil {
		return Selection{}, err
	}
	if err := period.Validate(now); err != nil {
		return Selection{}, err
	}
	if len(families) == 0 {
		return Selection{}, fmt.Errorf("%w: at least one family is required", ErrInvalidRequest)
	}
	normalized := normalizeFamilies(families)
	return Selection{
		OrgID:    orgID,
		TeamID:   teamID,
		Period:   period,
		From:     period.From.UTC().Format(time.RFC3339Nano),
		To:       period.To.UTC().Format(time.RFC3339Nano),
		Families: normalized,
		Filters:  filters,
	}, nil
}

// normalizeFamilies deduplicates and sorts families so {tool_calls,
// request_logs} and {request_logs, tool_calls} digest identically.
func normalizeFamilies(families []Family) []Family {
	seen := make(map[Family]bool, len(families))
	out := make([]Family, 0, len(families))
	for _, f := range families {
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Validate re-checks an existing selection against now (used when a selection
// is replayed later, e.g. by an operation runner inside its snapshot). Beyond
// the period rules it cross-checks the digest-carrying From/To wire strings
// against the Period instants: the digest signs the strings while counts and
// plans use the instants (Selection.RequestListFilters), so a hand-assembled
// desynced selection must fail closed instead of signing window B and
// executing window A.
func (s Selection) Validate(now time.Time) error {
	if s.OrgID == "" {
		return fmt.Errorf("%w: org is required", ErrInvalidRequest)
	}
	if err := s.Filters.validate(); err != nil {
		return err
	}
	if err := s.Period.Validate(now); err != nil {
		return err
	}
	if err := selectionWindowMatches(s.Period.From, s.From); err != nil {
		return err
	}
	return selectionWindowMatches(s.Period.To, s.To)
}

// selectionWindowMatches parses the canonical RFC3339 wire string and
// requires the exact instant the selection predicates use. An unparseable
// (or empty) string is malformed, not "no window" — fail closed.
func selectionWindowMatches(instant time.Time, wire string) error {
	parsed, err := time.Parse(time.RFC3339Nano, wire)
	if err != nil || !parsed.Equal(instant) {
		return fmt.Errorf("%w: period wire string %q does not match the selection window",
			ErrInvalidRequest, wire)
	}
	return nil
}

// RequestListFilters builds the adminstore filter for counting/planning: the
// selection filters mapped onto the exact list surface (org included), so
// preview counts and plan batches agree with the explorer's list predicate.
func (s Selection) RequestListFilters() adminstore.RequestListFilters {
	return s.Filters.applyTo(adminstore.RequestListFilters{
		OrgID: s.OrgID,
		From:  s.Period.From,
		To:    s.Period.To,
	})
}

// selectionParams is the accepted query-parameter surface for selections.
// Content selectors (q, query) are present in the wider list surface but are
// REFUSED here (selector_rejected) rather than silently dropped: a dropped
// selector would produce counts/digests that disagree with what the caller
// saw in the explorer.
var selectionParams = map[string]struct{}{
	"model": {}, "task_id": {}, "agent_id": {}, "request_id": {},
	"errors": {}, "min_status": {}, "cache_hit": {},
	"min_latency_ms": {}, "max_latency_ms": {},
	"min_tokens": {}, "max_tokens": {},
	"min_cost_usd": {}, "max_cost_usd": {},
	"from": {}, "to": {}, "families": {}, "team_id": {},
}

// ParseSelection builds a Selection from query parameters, mirroring the
// parseRequestListFilters surface minus everything history operations must
// refuse. Content-search (q) and YQL (query) selectors are refused at parse
// time per the refusal catalogue (§7): history cleanup is never driven by
// content predicates. Unknown parameters are malformed requests.
func ParseSelection(orgID string, params url.Values, now time.Time) (Selection, error) {
	for key := range params {
		if _, ok := selectionParams[key]; !ok {
			if key == "q" || key == "query" {
				return Selection{}, Refuse(RefusalSelectorRejected,
					"content selectors (%s) cannot drive history operations", key)
			}
			return Selection{}, fmt.Errorf("%w: unknown parameter %q", ErrInvalidRequest, key)
		}
	}
	var period Period
	if v := params.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Selection{}, fmt.Errorf("%w: invalid from: %v", ErrInvalidRequest, err)
		}
		period.From = t
	}
	if v := params.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Selection{}, fmt.Errorf("%w: invalid to: %v", ErrInvalidRequest, err)
		}
		period.To = t
	}
	familiesParam := params.Get("families")
	if familiesParam == "" {
		return Selection{}, fmt.Errorf("%w: families is required", ErrInvalidRequest)
	}
	var families []Family
	for _, name := range strings.Split(familiesParam, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		f, err := ParseFamily(name)
		if err != nil {
			return Selection{}, err
		}
		families = append(families, f)
	}
	filters := SelectionFilters{
		Model:     params.Get("model"),
		TaskID:    params.Get("task_id"),
		AgentID:   params.Get("agent_id"),
		RequestID: params.Get("request_id"),
		ErrorOnly: params.Get("errors") == "true" || params.Get("errors") == "1",
		CacheHit:  params.Get("cache_hit"),
	}
	var err error
	if filters.MinLatencyMs, err = parseSelectionI64(params.Get("min_latency_ms"), "min_latency_ms"); err != nil {
		return Selection{}, err
	}
	if filters.MaxLatencyMs, err = parseSelectionI64(params.Get("max_latency_ms"), "max_latency_ms"); err != nil {
		return Selection{}, err
	}
	if filters.MinTokens, err = parseSelectionI64(params.Get("min_tokens"), "min_tokens"); err != nil {
		return Selection{}, err
	}
	if filters.MaxTokens, err = parseSelectionI64(params.Get("max_tokens"), "max_tokens"); err != nil {
		return Selection{}, err
	}
	if filters.MinCostUSD, err = parseSelectionF64(params.Get("min_cost_usd"), "min_cost_usd"); err != nil {
		return Selection{}, err
	}
	if filters.MaxCostUSD, err = parseSelectionF64(params.Get("max_cost_usd"), "max_cost_usd"); err != nil {
		return Selection{}, err
	}
	if v := params.Get("min_status"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 0 {
			return Selection{}, fmt.Errorf("%w: invalid min_status %q", ErrInvalidRequest, v)
		}
		filters.MinStatus = n
	}
	return NewSelection(orgID, params.Get("team_id"), period, families, filters, now)
}

// parseSelectionI64 parses an optional numeric selection filter. Absent
// (empty) and explicit zero stay 0 — filter unset; a malformed or negative
// value is a malformed request: silently clamping to 0 would DROP the
// caller's filter, so the previewed/signed scope would disagree with what
// the caller asked for (fail-closed parse discipline, mirroring min_status).
func parseSelectionI64(v, field string) (int64, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: invalid %s %q", ErrInvalidRequest, field, v)
	}
	return n, nil
}

// parseSelectionF64 mirrors parseSelectionI64 for float bounds; non-finite
// values are malformed (NaN/Inf would poison the canonical digest encoding).
func parseSelectionF64(v, field string) (float64, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("%w: invalid %s %q", ErrInvalidRequest, field, v)
	}
	return n, nil
}
