package callout

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Param keys. "url" is reserved by the core for the callout kind (see
// pkg/pipeline StepSpec.Params); the builtin/* spellings take it from
// params. All other keys are callout-owned and validated at compile time —
// an unknown or malformed value must fail the policy load, never the
// request.
const (
	paramKeyURL             = "url"
	paramKeyMode            = "mode"
	paramKeyExpose          = "expose"
	paramKeyResponse        = "response"
	paramKeyFindingAction   = "finding_action"
	paramKeyFindingCategory = "finding_category"
	paramKeyFindingSeverity = "finding_severity"
	paramKeyMaxResponse     = "max_response_bytes"
)

// stepMode selects what a "callout"-kind step does.
type stepMode string

const (
	modeDetect stepMode = "detect"
	modeMutate stepMode = "mutate"
)

// yamlName is the params.mode value spelling.
func (m stepMode) yamlName() string { return string(m) }

// exposeKind selects the payload projection sent to the endpoint.
type exposeKind string

const (
	exposeMessages exposeKind = "messages" // default: message contents only
	exposeBody     exposeKind = "body"     // full Body — documented risk
	exposeFields   exposeKind = "fields"   // fields:a,b,c — selected body fields
)

// responseFormat selects the detect response contract.
type responseFormat string

const (
	responseFindings responseFormat = "findings" // default: findings array
	responseBoolean  responseFormat = "boolean"  // JSON true/false
)

// Defaults for finding fields not supplied by the scanner.
const (
	defaultFindingCategory  = "callout"
	defaultBooleanSeverity  = "high"
	defaultFindingsSeverity = "medium"
)

// stepConfig is the compile-time-validated configuration of one callout
// step. It is immutable after construction and shared between runs (the
// step contract requires goroutine safety).
type stepConfig struct {
	endpoint string // endpoint key: scheme://host/path — no query, no userinfo
	expose   exposeKind
	fields   []string
	response responseFormat
	action   pipeline.Action // default finding action / boolean-mode action
	category string          // boolean-mode finding category
	severity string          // boolean-mode finding severity
	maxReply int64           // response body cap (per-step override of Deps)
}

// parseStepConfig validates the params of one step. Every failure here is a
// policy LOAD error (factories run at compile time): a malformed callout can
// never surface at request time.
func parseStepConfig(params map[string]any, rt *Runtime, mode stepMode) (stepConfig, error) {
	cfg := stepConfig{}

	rawURL, ok := params[paramKeyURL].(string)
	if !ok || rawURL == "" {
		return cfg, fmt.Errorf("params.%s: non-empty string URL is required", paramKeyURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return cfg, fmt.Errorf("params.%s %q: %w", paramKeyURL, rawURL, err)
	}
	switch u.Scheme {
	case "http", "https":
		// ok
	default:
		return cfg, fmt.Errorf("params.%s %q: scheme must be http or https", paramKeyURL, u.Scheme)
	}
	if u.User != nil {
		return cfg, fmt.Errorf("params.%s: userinfo is not allowed (credentials never travel in policy URLs)", paramKeyURL)
	}
	if u.Host == "" {
		return cfg, fmt.Errorf("params.%s: host is required", paramKeyURL)
	}
	if u.Fragment != "" {
		return cfg, fmt.Errorf("params.%s: fragment is not allowed", paramKeyURL)
	}
	if !rt.hostAllowed(u.Hostname()) {
		return cfg, fmt.Errorf("params.%s: host %q is not in the callout egress allow-list (policies cannot widen egress)", paramKeyURL, u.Hostname())
	}
	cfg.endpoint = endpointKey(u)

	// expose
	switch v := params[paramKeyExpose].(type) {
	case nil:
		cfg.expose = exposeMessages
	case string:
		kind, fields, err := parseExpose(v)
		if err != nil {
			return cfg, err
		}
		cfg.expose = kind
		cfg.fields = fields
	default:
		return cfg, fmt.Errorf("params.%s: must be a string (messages | body | fields:a,b,c)", paramKeyExpose)
	}

	// response format (detect only; the mutate contract is fixed)
	if mode == modeDetect {
		switch v := params[paramKeyResponse].(type) {
		case nil:
			cfg.response = responseFindings
		case string:
			if v == "" {
				cfg.response = responseFindings
				break
			}
			switch responseFormat(v) {
			case responseFindings, responseBoolean:
				cfg.response = responseFormat(v)
			default:
				return cfg, fmt.Errorf("params.%s %q: want findings|boolean", paramKeyResponse, v)
			}
		default:
			return cfg, fmt.Errorf("params.%s: must be a string (findings|boolean)", paramKeyResponse)
		}
	} else if _, present := params[paramKeyResponse]; present {
		return cfg, fmt.Errorf("params.%s: not valid for mutate steps (the mutate contract is fixed)", paramKeyResponse)
	}

	// finding_* params
	cfg.action, err = parseFindingAction(params[paramKeyFindingAction])
	if err != nil {
		return cfg, err
	}
	switch v := params[paramKeyFindingCategory].(type) {
	case nil:
		cfg.category = defaultFindingCategory
	case string:
		if v == "" {
			return cfg, fmt.Errorf("params.%s: must not be empty", paramKeyFindingCategory)
		}
		cfg.category = v
	default:
		return cfg, fmt.Errorf("params.%s: must be a string", paramKeyFindingCategory)
	}
	switch v := params[paramKeyFindingSeverity].(type) {
	case nil:
		cfg.severity = defaultBooleanSeverity
	case string:
		if v == "" {
			return cfg, fmt.Errorf("params.%s: must not be empty", paramKeyFindingSeverity)
		}
		cfg.severity = v
	default:
		return cfg, fmt.Errorf("params.%s: must be a string", paramKeyFindingSeverity)
	}

	// response size cap
	switch v := params[paramKeyMaxResponse].(type) {
	case nil:
		cfg.maxReply = rt.deps.MaxResponseBytes
	case int:
		if v <= 0 {
			return cfg, fmt.Errorf("params.%s: must be positive", paramKeyMaxResponse)
		}
		cfg.maxReply = int64(v)
	case int64:
		if v <= 0 {
			return cfg, fmt.Errorf("params.%s: must be positive", paramKeyMaxResponse)
		}
		cfg.maxReply = v
	case float64:
		if v <= 0 || v != float64(int64(v)) {
			return cfg, fmt.Errorf("params.%s: must be a positive integer", paramKeyMaxResponse)
		}
		cfg.maxReply = int64(v)
	default:
		return cfg, fmt.Errorf("params.%s: must be a positive integer", paramKeyMaxResponse)
	}

	return cfg, nil
}

// parseExpose parses the params.expose value: "messages" (default), "body"
// or "fields:a,b,c".
func parseExpose(v string) (exposeKind, []string, error) {
	switch {
	case v == string(exposeMessages):
		return exposeMessages, nil, nil
	case v == string(exposeBody):
		return exposeBody, nil, nil
	case strings.HasPrefix(v, string(exposeFields)+":"):
		list := strings.Split(strings.TrimPrefix(v, string(exposeFields)+":"), ",")
		fields := make([]string, 0, len(list))
		seen := make(map[string]bool, len(list))
		for _, f := range list {
			f = strings.TrimSpace(f)
			if f == "" {
				return "", nil, fmt.Errorf("params.%s %q: empty field name", paramKeyExpose, v)
			}
			if seen[f] {
				return "", nil, fmt.Errorf("params.%s %q: field %q listed twice", paramKeyExpose, v, f)
			}
			seen[f] = true
			fields = append(fields, f)
		}
		return exposeFields, fields, nil
	default:
		return "", nil, fmt.Errorf("params.%s %q: want messages | body | fields:a,b,c", paramKeyExpose, v)
	}
}

// parseFindingAction validates params.finding_action; empty defaults to deny
// (fail closed: an unconfigured action must never loosen the verdict).
func parseFindingAction(v any) (pipeline.Action, error) {
	switch a := v.(type) {
	case nil:
		return pipeline.ActionDeny, nil
	case string:
		if a == "" {
			return pipeline.ActionDeny, nil
		}
		act := pipeline.Action(a)
		switch act {
		case pipeline.ActionDeny, pipeline.ActionMask, pipeline.ActionFlag, pipeline.ActionAllow:
			return act, nil
		default:
			return "", fmt.Errorf("params.%s %q: want deny|mask|flag|allow", paramKeyFindingAction, a)
		}
	default:
		return "", fmt.Errorf("params.%s: must be a string", paramKeyFindingAction)
	}
}

// endpointKey renders the endpoint identity used for breakers, singleflight
// keys and metrics: scheme://host[/path] — query and userinfo are dropped
// (queries may carry per-request secrets; the label must stay bounded and
// secret-free).
func endpointKey(u *url.URL) string {
	key := u.Scheme + "://" + u.Host
	if u.Path != "" && u.Path != "/" {
		key += u.Path
	}
	return key
}

// marshalContent builds the request envelope {"expose": ..., "content": ...}.
type requestEnvelope struct {
	Expose  string          `json:"expose"`
	Content json.RawMessage `json:"content"`
}

// contentString marshals s as a JSON string.
func contentString(s string) (json.RawMessage, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
