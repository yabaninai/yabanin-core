package builtins

import (
	"context"
	"fmt"
	"net/textproto"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Header-rewrite bounds and validation limits.
const (
	maxHeaderNameLen  = 256
	maxHeaderValueLen = 8 << 10 // 8 KiB
	maxHeaderSet      = 64
)

// headerRewriteStep is builtin/header-rewrite: it edits the upstream request
// headers of the payload (Payload.Headers, OP-5) — params {set: {...},
// remove: [...]}. Removals apply first, then sets (a set wins over a remove
// of the same name). Header names are canonicalized
// (textproto.CanonicalMIMEHeaderKey); a value or name containing CR, LF or
// NUL is a factory error — header INJECTION into the upstream request can
// never pass policy load. The step only touches the run's payload clone
// (engine Clone duplicates the map), never the caller's payload.
//
// Kinds: request only by default (headers are a request-to-upstream
// surface); "kinds" may narrow to a subset of request only.
type headerRewriteStep struct {
	pipeline.MutatorBase
	kinds  map[pipeline.PayloadKind]bool
	set    map[string]string
	remove []string // canonicalized
}

// Name returns the step implementation name.
func (*headerRewriteStep) Name() string { return NameHeaderRewrite }

// Run applies remove then set to in.Headers in place. A nil Headers map is
// created only when a set needs it; pure-remove runs on headerless payloads
// stay a no-op (Mutated stays nil).
func (h *headerRewriteStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !h.kinds[in.Kind] {
		return nil
	}
	for _, name := range h.remove {
		if err := ctx.Err(); err != nil {
			return err
		}
		delete(in.Headers, name)
	}
	for name, value := range h.set {
		if err := ctx.Err(); err != nil {
			return err
		}
		if in.Headers == nil {
			in.Headers = make(map[string]string, len(h.set))
		}
		in.Headers[name] = value
	}
	return nil
}

// NewHeaderRewrite builds builtin/header-rewrite.
//
// Params: "set" (map name→value; at least one of set/remove is required),
// "remove" (list of header names), plus the common kinds param. Names must
// be valid MIME header tokens; values must not contain CR/LF/NUL and stay
// within the 8 KiB value cap — violations are policy LOAD errors.
func NewHeaderRewrite(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params, pipeline.KindRequest)
	if err != nil {
		return nil, err
	}
	for k := range kinds {
		if k != pipeline.KindRequest {
			return nil, fmt.Errorf("params.kinds: %q: header-rewrite is request-only", k)
		}
	}
	rawSet, hasSet := params["set"]
	rawRemove, hasRemove := params["remove"]
	if (!hasSet || rawSet == nil) && (!hasRemove || rawRemove == nil) {
		return nil, fmt.Errorf("params: at least one of \"set\" or \"remove\" is required")
	}
	set := make(map[string]string)
	if hasSet && rawSet != nil {
		m, ok := rawSet.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("params.set: must be a map of header name to value, got %T", rawSet)
		}
		if len(m) > maxHeaderSet {
			return nil, fmt.Errorf("params.set: %d entries exceed the limit %d", len(m), maxHeaderSet)
		}
		for name, v := range m {
			canonical, err := canonicalHeaderKey(name)
			if err != nil {
				return nil, fmt.Errorf("params.set: %w", err)
			}
			value, err := anyToString(v)
			if err != nil {
				return nil, fmt.Errorf("params.set[%s]: %w", name, err)
			}
			if len(value) > maxHeaderValueLen {
				return nil, fmt.Errorf("params.set[%s]: value is %d bytes, exceeds the %d-byte limit", name, len(value), maxHeaderValueLen)
			}
			if strings.ContainsAny(value, "\r\n\x00") {
				return nil, fmt.Errorf("params.set[%s]: value contains CR/LF/NUL (header injection)", name)
			}
			set[canonical] = value
		}
	}
	var remove []string
	if hasRemove && rawRemove != nil {
		items, err := anyToStrings(rawRemove)
		if err != nil {
			return nil, fmt.Errorf("params.remove: %w", err)
		}
		for _, name := range items {
			canonical, err := canonicalHeaderKey(name)
			if err != nil {
				return nil, fmt.Errorf("params.remove: %w", err)
			}
			remove = append(remove, canonical)
		}
	}
	return &headerRewriteStep{kinds: kinds, set: set, remove: remove}, nil
}

// canonicalHeaderKey validates a header name (non-empty, RFC 7230 token
// bytes only — textproto.CanonicalMIMEHeaderKey alone is not enough: it
// returns invalid names unchanged) and returns the canonical form.
func canonicalHeaderKey(name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("header name is empty")
	}
	if len(name) > maxHeaderNameLen {
		return "", fmt.Errorf("header name is %d bytes, exceeds the %d-byte limit", len(name), maxHeaderNameLen)
	}
	if strings.ContainsAny(name, "\r\n\x00") {
		return "", fmt.Errorf("header name %q contains CR/LF/NUL (header injection)", name)
	}
	for i := 0; i < len(name); i++ {
		if !isTokenByte(name[i]) {
			return "", fmt.Errorf("header name %q: byte %d is not a valid header-token character", name, i)
		}
	}
	canonical := textproto.CanonicalMIMEHeaderKey(name)
	if canonical == "" {
		return "", fmt.Errorf("header name %q is not a valid MIME header token", name)
	}
	return canonical, nil
}

// isTokenByte reports whether b is an RFC 7230 header token byte:
// "!#$%&'*+-.^_`|~", DIGIT, ALPHA.
func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", b) >= 0
}

// compile-time guard: header-rewrite is a Mutator.
var _ pipeline.Mutator = (*headerRewriteStep)(nil)
