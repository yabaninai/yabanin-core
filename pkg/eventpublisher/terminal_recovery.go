package eventpublisher

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

var terminalFieldSchema = (&Event{}).terminalFields("")

// DecodeTerminalAccounting reconstructs the Redis scalar map from committed
// facts. The admitted keys are authoritative and the producer defines the schema.
func DecodeTerminalAccounting(data []byte, invocationID, orgID string) (map[string]any, error) {
	var raw map[string]*string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("decode terminal accounting: %w", err)
	}
	if len(raw) != len(terminalFieldSchema) {
		return nil, errors.New("unexpected terminal accounting field count")
	}
	fields := make(map[string]any, len(raw))
	for key := range terminalFieldSchema {
		v := raw[key]
		if v == nil {
			return nil, fmt.Errorf("missing terminal accounting scalar %s", key)
		}
		if !validAccountingScalar(key, *v) {
			return nil, fmt.Errorf("invalid terminal accounting scalar %s", key)
		}
		fields[key] = *v
	}
	if err := checkStoredAttribution(raw, invocationID, orgID); err != nil {
		return nil, err
	}
	return fields, nil
}
func validAccountingScalar(key, value string) bool {
	switch key {
	case "used_org_key":
		return value == "" || value == "true"
	case "ts":
		return canonicalIntegerAtLeast(value, 1)
	case "estimated_cost_usd", "resale_cost_usd", "counterfactual_cost_usd":
		n, err := strconv.ParseFloat(value, 64)
		return err == nil && validTerminalCosts(n) && strconv.FormatFloat(n, 'f', -1, 64) == value
	case "tokens_in", "tokens_out", "cache_read_tokens", "cache_creation_tokens", "status_code", "duration_ms", "first_token_ms", "attempt_count", "retry_count":
		return canonicalIntegerAtLeast(value, 0)
	case "event_type":
		return isTerminalEventType(value)
	}
	return true
}
func canonicalIntegerAtLeast(value string, minimum int64) bool {
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n >= minimum && strconv.FormatInt(n, 10) == value
}

func checkStoredAttribution(raw map[string]*string, id, org string) error {
	if !validInvocationID(id) || org == "" || *raw["invocation_id"] != id || *raw["org_id"] != org {
		return errors.New("terminal accounting does not match admission")
	}
	ev := Event{OrgID: org, TeamID: *raw["team_id"], AgentID: *raw["agent_id"], SessionKeyID: *raw["session_key_id"], Reservations: *raw["reservations"]}
	reservations, err := ev.terminalReservations()
	if err != nil || reservations != ev.Reservations {
		return errors.New("invalid stored terminal reservations")
	}
	return nil
}
