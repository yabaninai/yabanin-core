package builtins

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// modelWhitelistStep gates the routing identity (RequestMeta.Model) against
// a pattern list. Meta is read-only by contract; the step inspects it and
// never touches the payload text. An unknown model (nil Meta or empty
// Model) is a violation — fail-closed.
type modelWhitelistStep struct {
	pipeline.DetectorBase
	kinds    map[pipeline.PayloadKind]bool
	act      pipeline.Action
	patterns []*regexp.Regexp
}

// Name returns the step implementation name.
func (*modelWhitelistStep) Name() string { return "builtin/model-whitelist" }

// Run reports a violation when the request model matches no pattern.
func (s *modelWhitelistStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	model := ""
	if in.Meta != nil {
		model = in.Meta.Model
	}
	for _, re := range s.patterns {
		if re.MatchString(model) {
			return nil
		}
	}
	out.Findings = append(out.Findings, finding(
		p.StepID(), "model", sevMedium, "",
		fmt.Sprintf("model %q is not in the whitelist", model), s.act,
	))
	return nil
}

// NewModelWhitelist builds builtin/model-whitelist.
//
// Params: "models" (required non-empty list of glob patterns; '*' matches
// any run of characters including '/', '?' matches one character; exact
// names are patterns without wildcards), plus the common kinds/action.
func NewModelWhitelist(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	models, err := paramStrings(params, "models")
	if err != nil {
		return nil, err
	}
	patterns := make([]*regexp.Regexp, 0, len(models))
	for _, m := range models {
		re, err := compileGlob(m)
		if err != nil {
			return nil, fmt.Errorf("params.models: %w", err)
		}
		patterns = append(patterns, re)
	}
	return &modelWhitelistStep{kinds: kinds, act: act, patterns: patterns}, nil
}

// compileGlob anchors a glob ('*' → any run, '?' → one char; everything
// else literal) into a regexp.
func compileGlob(pattern string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			sb.WriteString(".*")
		case '?':
			sb.WriteString(".")
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

// compile-time guard: model-whitelist is a read-only Detector.
var _ pipeline.Detector = (*modelWhitelistStep)(nil)

// metadataRequiredStep checks the request's routing metadata (RequestMeta):
// "keys" entries name Meta fields ("org", "key", "model", "provider" —
// required non-empty) or Labels entries (any other name, required non-empty
// label value); "labels" entries are exact label=value pairs.
type metadataRequiredStep struct {
	pipeline.DetectorBase
	kinds  map[pipeline.PayloadKind]bool
	act    pipeline.Action
	keys   []string
	labels map[string]string
}

// Name returns the step implementation name.
func (*metadataRequiredStep) Name() string { return "builtin/metadata-required" }

// Run reports one finding per missing key / wrong label pair.
func (s *metadataRequiredStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	meta := in.Meta // may be nil: everything is then missing (fail-closed)
	labelOf := func(k string) (string, bool) {
		if meta == nil || meta.Labels == nil {
			return "", false
		}
		v, ok := meta.Labels[k]
		return v, ok
	}
	report := func(evidence string) {
		out.Findings = append(out.Findings, finding(
			p.StepID(), "metadata", sevMedium, "", evidence, s.act,
		))
	}
	for _, k := range s.keys {
		switch k {
		case "org", "key", "model", "provider":
			v := ""
			if meta != nil {
				switch k {
				case "org":
					v = meta.Org
				case "key":
					v = meta.Key
				case "model":
					v = meta.Model
				case "provider":
					v = meta.Provider
				}
			}
			if v == "" {
				report("missing meta key: " + k)
			}
		default:
			if v, ok := labelOf(k); !ok || v == "" {
				report("missing label: " + k)
			}
		}
	}
	// Labels iterate in sorted-key order: identical inputs must produce
	// findings in identical order (pipeline determinism contract).
	labelKeys := make([]string, 0, len(s.labels))
	for k := range s.labels {
		labelKeys = append(labelKeys, k)
	}
	slices.Sort(labelKeys)
	for _, k := range labelKeys {
		want := s.labels[k]
		have, ok := labelOf(k)
		if !ok {
			report("missing label: " + k)
			continue
		}
		if have != want {
			report(fmt.Sprintf("label %q: want %q have %q", k, want, have))
		}
	}
	return nil
}

// NewMetadataRequired builds builtin/metadata-required.
//
// Params: "keys" (Meta fields / Labels entries) and "labels" (required
// label=value pairs); at least one entry overall is required, plus the
// common kinds/action.
func NewMetadataRequired(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	var keys []string
	if raw, ok := params["keys"]; ok && raw != nil {
		if keys, err = anyToStrings(raw); err != nil {
			return nil, fmt.Errorf("params.keys: %w", err)
		}
		for _, k := range keys {
			if k == "" {
				return nil, fmt.Errorf("params.keys: empty entries are not allowed")
			}
		}
	}
	labels := map[string]string{}
	if raw, ok := params["labels"]; ok && raw != nil {
		m, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("params.labels: must be a map of label=value pairs")
		}
		for k, v := range m {
			s, err := anyToString(v)
			if err != nil {
				return nil, fmt.Errorf("params.labels.%s: %w", k, err)
			}
			labels[k] = s
		}
	}
	if len(keys) == 0 && len(labels) == 0 {
		return nil, fmt.Errorf("params.keys/params.labels: at least one required entry is necessary (a step with no requirements can never fire)")
	}
	return &metadataRequiredStep{kinds: kinds, act: act, keys: keys, labels: labels}, nil
}

// compile-time guard: metadata-required is a read-only Detector.
var _ pipeline.Detector = (*metadataRequiredStep)(nil)
