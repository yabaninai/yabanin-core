package builtins

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// urlFindRe extracts candidate URLs. The pattern is linear (bounded
// {0,15} scheme run, single negated char class, no nesting) — ReDoS-safe by
// construction. The broad scheme shape lets the step FLAG disallowed schemes
// (ftp://, file://, …) instead of silently not seeing them.
var urlFindRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]{0,15}://[^\s<>"'` + "`" + `]+`)

// urlTrimChars are stripped from a candidate match tail so prose punctuation
// ("see https://x.com.") does not become part of the host.
const urlTrimChars = ".,;:!?)]}'\"»"

// maxURLFindings caps findings per run.
const maxURLFindings = 50

// urlCheckStep inspects URLs found in the payload text against the configured
// scheme allow-list and host allow/deny lists. It is fully offline: it never
type urlCheckStep struct {
	pipeline.DetectorBase
	kinds   map[pipeline.PayloadKind]bool
	act     pipeline.Action
	schemes map[string]bool
	allow   []string // empty = any host allowed
	deny    []string
}

// Name returns the step implementation name.
func (*urlCheckStep) Name() string { return "builtin/url-check" }

// Run extracts URLs and reports one finding per offending URL (scheme or
// host policy violation, or unparsable candidate).
func (s *urlCheckStep) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !s.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	if text == "" {
		return nil
	}
	matches := urlFindRe.FindAllStringIndex(text, maxURLFindings)
	for _, m := range matches {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := strings.TrimRight(text[m[0]:m[1]], urlTrimChars)
		if ev, why := s.violation(raw); why {
			out.Findings = append(out.Findings, finding(
				p.StepID(), "url", sevMedium,
				span(m[0], m[0]+len(raw)), clipEvidence(ev, maxEvidence), s.act,
			))
		}
	}
	return nil
}

// violation returns (evidence, true) when the URL breaks the step's policy.
func (s *urlCheckStep) violation(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "unparsable URL: " + raw, true
	}
	scheme := strings.ToLower(u.Scheme)
	if !s.schemes[scheme] {
		return "scheme not allowed: " + raw, true
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "no host: " + raw, true
	}
	if s.hostMatches(s.deny, host) {
		return "host denied: " + raw, true
	}
	if len(s.allow) > 0 && !s.hostMatches(s.allow, host) {
		return "host not allowed: " + raw, true
	}
	return "", false
}

// hostMatches reports whether host equals or falls under any entry; entries
// of the form "*.example.com" match any subdomain (example.com itself must
// be listed separately).
func (s *urlCheckStep) hostMatches(entries []string, host string) bool {
	for _, e := range entries {
		if e == host {
			return true
		}
		if suffix, ok := strings.CutPrefix(e, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		}
	}
	return false
}

// NewURLCheck builds builtin/url-check.
//
// Params: "schemes" (default ["https","http"]), "allow_hosts" (empty = any
// host), "deny_hosts", both supporting "*.example.com" wildcard suffixes,
// plus the common kinds/action. Entries are lower-cased; empty entries are
// load errors.
func NewURLCheck(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	schemes := []string{"https", "http"}
	if raw, ok := params["schemes"]; ok && raw != nil {
		if schemes, err = anyToStrings(raw); err != nil {
			return nil, fmt.Errorf("params.schemes: %w", err)
		}
	}
	if len(schemes) == 0 {
		return nil, fmt.Errorf("params.schemes: at least one scheme is required")
	}
	schemeSet := make(map[string]bool, len(schemes))
	for _, sc := range schemes {
		sc = strings.ToLower(strings.TrimSpace(sc))
		if sc == "" {
			return nil, fmt.Errorf("params.schemes: empty entries are not allowed")
		}
		schemeSet[sc] = true
	}
	normalize := func(key string) ([]string, error) {
		raw, ok := params[key]
		if !ok || raw == nil {
			return nil, nil
		}
		items, err := anyToStrings(raw)
		if err != nil {
			return nil, fmt.Errorf("params.%s: %w", key, err)
		}
		for i, it := range items {
			it = strings.ToLower(strings.TrimSpace(it))
			if it == "" {
				return nil, fmt.Errorf("params.%s: empty entries are not allowed", key)
			}
			items[i] = it
		}
		return items, nil
	}
	allow, err := normalize("allow_hosts")
	if err != nil {
		return nil, err
	}
	deny, err := normalize("deny_hosts")
	if err != nil {
		return nil, err
	}
	return &urlCheckStep{kinds: kinds, act: act, schemes: schemeSet, allow: allow, deny: deny}, nil
}

// compile-time guard: url-check is a read-only Detector.
var _ pipeline.Detector = (*urlCheckStep)(nil)
