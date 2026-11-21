package eventpublisher

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// UnmarshalJSON keeps legacy events without an invocation ID readable while
// rejecting an explicitly invalid identity before a queued event can replay.
func (event *Event) UnmarshalJSON(data []byte) error {
	type wire Event
	decoded := struct {
		*wire
		ID json.RawMessage `json:"invocation_id"`
	}{wire: (*wire)(event)}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	if decoded.ID == nil {
		return nil
	}
	var id string
	if err := json.Unmarshal(decoded.ID, &id); err != nil || !validInvocationID(id) {
		return errors.New("invalid terminal invocation ID")
	}
	event.InvocationID = id
	return nil
}

func validInvocationID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// accountingFields uses the scalar encodings read back from a Redis stream.
func (event *Event) accountingFields(ts int64) map[string]string {
	return map[string]string{
		"event_type":              event.EventType,
		"used_org_key":            boolStreamValue(event.UsedOrgKey),
		"org_id":                  event.OrgID,
		"request_id":              event.RequestID,
		"model_requested":         event.ModelRequested,
		"model_used":              event.ModelUsed,
		"status_code":             strconv.FormatInt(event.StatusCode, 10),
		"duration_ms":             strconv.FormatInt(event.DurationMs, 10),
		"tokens_in":               strconv.FormatInt(event.TokensIn, 10),
		"tokens_out":              strconv.FormatInt(event.TokensOut, 10),
		"estimated_cost_usd":      strconv.FormatFloat(event.EstimatedCostUSD, 'f', -1, 64),
		"resale_cost_usd":         strconv.FormatFloat(event.ResaleCostUSD, 'f', -1, 64),
		"cost_status":             event.CostStatus,
		"usage_source":            event.UsageSource,
		"termination":             event.Termination,
		"ts":                      strconv.FormatInt(ts, 10),
		"session_id":              event.SessionID,
		"team_id":                 event.TeamID,
		"agent_id":                event.AgentID,
		"task_id":                 event.TaskID,
		"endpoint":                event.Endpoint,
		"cache_hit_type":          event.CacheHitType,
		"cache_read_tokens":       strconv.FormatInt(event.CacheReadTokens, 10),
		"cache_creation_tokens":   strconv.FormatInt(event.CacheCreationTokens, 10),
		"ab_group":                event.ABGroup,
		"tier_used":               event.TierUsed,
		"counterfactual_cost_usd": strconv.FormatFloat(event.CounterfactualCostUSD, 'f', -1, 64),
		"reservations":            event.Reservations,
		"first_token_ms":          strconv.FormatInt(event.FirstTokenMs, 10),
		"attempt_count":           strconv.Itoa(event.AttemptCount),
		"retry_count":             strconv.Itoa(event.RetryCount),
	}
}

func (event *Event) accountingForPublish(ts int64) (map[string]string, error) {
	if event.InvocationID == "" {
		return event.accountingFields(ts), nil
	}
	return event.TerminalAccountingFields()
}

// TerminalAccountingFields returns the content-free fields persisted for
// recovery. The caller stamps TS before saving the facts or publishing.
func (event *Event) TerminalAccountingFields() (map[string]string, error) {
	if event == nil || event.OrgID == "" || event.TS <= 0 {
		return nil, errors.New("terminal accounting requires a tenant and producer timestamp")
	}
	if !validInvocationID(event.InvocationID) {
		return nil, errors.New("invalid terminal invocation ID")
	}
	switch event.EventType {
	case "request.completed", "request.failed", "request.shadow_completed", "request.budget_exceeded":
	default:
		return nil, errors.New("invalid terminal accounting event type")
	}
	if !validTerminalCosts(event.EstimatedCostUSD, event.ResaleCostUSD, event.CounterfactualCostUSD) {
		return nil, errors.New("invalid terminal accounting cost")
	}
	reservations, err := event.terminalReservations()
	if err != nil {
		return nil, err
	}
	fields := event.accountingFields(event.TS)
	fields["reservations"] = reservations
	fields["invocation_id"] = event.InvocationID
	fields["api_key_id"] = event.APIKeyID
	fields["session_key_id"] = event.SessionKeyID
	fields["user_id"] = event.UserID
	fields["prompt_hash"] = ResolvePromptHash(event.PromptHash, event.Payload)
	return fields, nil
}

func validTerminalCosts(amounts ...float64) bool {
	for _, amount := range amounts {
		if amount < 0 || math.IsNaN(amount) || math.IsInf(amount, 0) {
			return false
		}
	}
	return true
}

// Reservations are the one nested wire field permitted in durable facts.
// Re-encode the typed tuples so ignored or overwritten JSON text cannot persist.
type terminalReservation struct {
	ScopeKind     string  `json:"scope_kind"`
	ScopeKey      string  `json:"scope_key"`
	Period        *string `json:"period"`
	AllowanceID   int64   `json:"allowance_id"`
	BoundMicroUSD *int64  `json:"bound_micro_usd"`
}

func (tuple terminalReservation) matches(event *Event) bool {
	if tuple.ScopeKey == "" || tuple.Period == nil || tuple.AllowanceID <= 0 || tuple.BoundMicroUSD == nil || *tuple.BoundMicroUSD < 0 {
		return false
	}
	switch tuple.ScopeKind {
	case "wallet":
		return tuple.ScopeKey == event.OrgID && *tuple.Period == ""
	case "session":
		return tuple.ScopeKey == event.SessionKeyID && *tuple.Period == ""
	case "team_month":
		return tuple.ScopeKey == event.TeamID && canonicalPeriod(*tuple.Period, "2006-01")
	case "agent_day":
		return tuple.ScopeKey == event.AgentID && canonicalPeriod(*tuple.Period, "2006-01-02")
	}
	return false
}

func canonicalPeriod(value, layout string) bool {
	parsed, err := time.Parse(layout, value)
	return err == nil && parsed.Format(layout) == value
}

func (event *Event) terminalReservations() (string, error) {
	raw := event.Reservations
	if raw == "" {
		return "", nil
	}
	var tuples []terminalReservation
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tuples); err != nil || tuples == nil {
		return "", errors.New("invalid terminal reservation tuples")
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return "", errors.New("invalid trailing terminal reservation data")
	}
	seen := map[string]bool{}
	for _, tuple := range tuples {
		if !tuple.matches(event) || seen[tuple.ScopeKind] {
			return "", errors.New("invalid terminal reservation identity or amounts")
		}
		seen[tuple.ScopeKind] = true
	}
	encoded, err := json.Marshal(tuples)
	return string(encoded), err
}
