package builtins

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/reireirei/yabanin/pkg/pipeline"
)

// Shared machinery of the span-driven mutators (builtin/redact,
// builtin/pseudonymize).
//
// SPAN SOURCE CONTRACT: the inspected text of a payload is payloadText —
// message contents joined with "\n", falling back to Body, then StreamChunk
// (the detector convention, doc.go). Findings locate evidence with
// Span "start:end" BYTE offsets into exactly that text. A span mutator
// therefore re-derives the same layout, validates every finding span
// (bounds, rune boundaries, one message segment per span) and FAILS the step
// on a stale span — the default on_error=fail_closed turns layout drift
// (a text-mutating step between detector and redactor) into a loud policy
// error instead of a silent wrong-place redaction. Order detectors and their
// span mutator adjacently, or set on_error.
//
// IDEMPOTENCY BOUNDARY: text produced by these mutators — "[REDACTED:cat:n]"
// and "{{YPP_n}}" tokens — is protected: findings spans overlapping a token
// are skipped and own-pattern scans never match inside a token. Re-running a
// composed detector→mutator policy on already-mutated text is a no-op, and
// redact→pseudonymize (or the reverse) stacked on the SAME findings is a
// safe no-op for the later step, never a corruption of the earlier tokens.

const (
	// defSpanMaxInput / maxSpanMaxInput bound the text a span mutator will
	// process (mirrors builtin/regex: fail-closed beyond the cap).
	defSpanMaxInput = 1 << 20 // 1 MiB
	maxSpanMaxInput = 64 << 20
	// maxSpanPatterns caps the configured own-pattern list (policy load
	// bound); maxSpanMatches caps matches of one pattern per text segment.
	maxSpanPatterns = 32
	maxSpanMatches  = 100
	// maxPseudonyms bounds the alias map of one run; maxPseudonymCarrierBytes
	// bounds the session carrier label written by carry=session.
	maxPseudonyms            = 256
	maxPseudonymCarrierBytes = 16 << 10
	// PseudonymCarrierLabel is the reserved payload.Meta.Labels key of the
	// carry=session carrier (JSON object alias→original).
	//
	// OP-8 CONTRACT (MultiTurn): pseudonymize writes this label on the
	// mutated payload; the gateway MUST persist it with the session and MUST
	// strip it before dispatching upstream or to the client — the values are
	// the original sensitive strings. The next request of the session passes
	// the stored carrier back in Meta.Labels; pseudonymize seeds its map
	// from it, so the same original maps to the same {{YPP_n}} across turns.
	// The carrier lives in the run/session context only: it is never cached
	// globally, never logged (decision-log hashes evidence) and dies with
	// the session. request_only (carry=none) never touches Meta.
	PseudonymCarrierLabel = "ypp.pseudonyms.v1"
)

// redactTokenRe matches a token emitted by builtin/redact; aliasTokenRe
// matches a token emitted by builtin/pseudonymize. Both are immutable
// package state (compile-once, no mutation) — the same pattern as the
// guardhooks detector set.
var (
	redactTokenRe = regexp.MustCompile(`\[REDACTED:[^:\[\]\n]+:[0-9]+\]`)
	aliasTokenRe  = regexp.MustCompile(`\{\{YPP_[0-9]+\}\}`)
	aliasExactRe  = regexp.MustCompile(`^\{\{YPP_([0-9]+)\}\}$`)
)

// spanPattern is one configured own-pattern of a span mutator.
type spanPattern struct {
	category string
	re       *regexp.Regexp
}

// spanMutator is the shared configuration of redact/pseudonymize: kinds
// gate, category filter over findings, own patterns and the input cap.
// Immutable after construction (goroutine-safe by contract).
type spanMutator struct {
	kinds    map[pipeline.PayloadKind]bool
	cats     map[string]bool // nil = every findings category
	wilds    []string        // category prefixes from "x.*" entries
	patterns []spanPattern
	maxInput int
}

// categorySelected reports whether a findings category passes the filter
// (absent filter selects everything).
func (c spanMutator) categorySelected(cat string) bool {
	if len(c.cats) == 0 && len(c.wilds) == 0 {
		return true
	}
	if c.cats[cat] {
		return true
	}
	return slices.ContainsFunc(c.wilds, func(w string) bool { return strings.HasPrefix(cat, w) })
}

// parseSpanMutator builds the shared configuration. defKinds is the step's
// default kinds set (parseKinds semantics apply for an explicit "kinds").
func parseSpanMutator(params map[string]any, defKinds ...pipeline.PayloadKind) (spanMutator, error) {
	kinds, err := parseKinds(params, defKinds...)
	if err != nil {
		return spanMutator{}, err
	}
	cats, wilds, err := parseCategoryFilter(params)
	if err != nil {
		return spanMutator{}, err
	}
	patterns, err := parseSpanPatterns(params)
	if err != nil {
		return spanMutator{}, err
	}
	maxInput, err := paramInt(params, "max_input", defSpanMaxInput)
	if err != nil {
		return spanMutator{}, err
	}
	if maxInput <= 0 || maxInput > maxSpanMaxInput {
		return spanMutator{}, fmt.Errorf("params.max_input: %d: must be in (0, %d] bytes", maxInput, maxSpanMaxInput)
	}
	return spanMutator{kinds: kinds, cats: cats, wilds: wilds, patterns: patterns, maxInput: maxInput}, nil
}

// parseCategoryFilter resolves the optional "categories" param: exact names
// plus trailing-wildcard entries ("presidio.*" → prefix "presidio."). A bare
// "*" selects everything, i.e. no filter.
func parseCategoryFilter(params map[string]any) (exact map[string]bool, wilds []string, err error) {
	raw, ok := params["categories"]
	if !ok || raw == nil {
		return nil, nil, nil
	}
	items, err := anyToStrings(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("params.categories: %w", err)
	}
	exact = make(map[string]bool, len(items))
	for _, it := range items {
		if it == "" {
			return nil, nil, fmt.Errorf("params.categories: empty entries are not allowed")
		}
		if it == "*" {
			continue
		}
		if name, ok := strings.CutSuffix(it, ".*"); ok {
			if name == "" {
				return nil, nil, fmt.Errorf("params.categories: %q: wildcard needs a base category", it)
			}
			wilds = append(wilds, name+".")
			continue
		}
		if strings.ContainsAny(it, "*?[") {
			return nil, nil, fmt.Errorf("params.categories: %q: only a trailing \".*\" wildcard is supported", it)
		}
		exact[it] = true
	}
	if len(exact) == 0 && len(wilds) == 0 {
		return nil, nil, nil
	}
	return exact, wilds, nil
}

// parseSpanPatterns resolves the optional "patterns" param: a list of
// {category, pattern} entries (YAML maps arrive as []any of map[string]any;
// a single map is accepted as a one-entry list). Patterns go through the
// same RE2 audit as builtin/regex (no nested quantifiers, bounded
// expansion) — a bad pattern is a policy LOAD error.
func parseSpanPatterns(params map[string]any) ([]spanPattern, error) {
	raw, ok := params["patterns"]
	if !ok || raw == nil {
		return nil, nil
	}
	var items []any
	switch v := raw.(type) {
	case []any:
		items = v
	case map[string]any:
		items = []any{v}
	default:
		return nil, fmt.Errorf("params.patterns: list of {category, pattern} maps is required, got %T", raw)
	}
	out := make([]spanPattern, 0, len(items))
	for i, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("params.patterns[%d]: must be a map with \"category\" and \"pattern\", got %T", i, it)
		}
		cat, err := paramString(m, "category")
		if err != nil {
			return nil, fmt.Errorf("params.patterns[%d]: %w", i, err)
		}
		pat, err := paramString(m, "pattern")
		if err != nil {
			return nil, fmt.Errorf("params.patterns[%d]: %w", i, err)
		}
		re, err := compileAuditedRegex(pat)
		if err != nil {
			return nil, fmt.Errorf("params.patterns[%d].pattern: %w", i, err)
		}
		out = append(out, spanPattern{category: cat, re: re})
	}
	if len(out) > maxSpanPatterns {
		return nil, fmt.Errorf("params.patterns: %d entries exceed the limit %d", len(out), maxSpanPatterns)
	}
	return out, nil
}

// segKind discriminates which payload text source the inspected text came
// from (payloadText precedence: messages → body → stream chunk).
type segKind int

const (
	segMessages segKind = iota
	segBody
	segChunk
)

// textSegment is one editable run of the inspected text: a non-empty message
// content, or the whole Body / StreamChunk. start/end are offsets in the
// JOINED inspected text (the span coordinate system).
type textSegment struct {
	msgIdx int // index into Payload.Messages; -1 for body/chunk
	text   string
	start  int
}

// textLayout is the joined inspected text decomposed into editable segments.
type textLayout struct {
	kind segKind
	segs []textSegment
}

// layoutOf re-derives the inspected-text layout of p — the exact inverse
// image of payloadText (empty messages are skipped, "\n" only between
// included messages, body/chunk fallback).
func layoutOf(p *pipeline.Payload) textLayout {
	var segs []textSegment
	off, has := 0, false
	for i, m := range p.Messages {
		if m.Content == "" {
			continue
		}
		if has {
			off++ // the "\n" join separator of payloadText
		}
		segs = append(segs, textSegment{msgIdx: i, text: m.Content, start: off})
		off += len(m.Content)
		has = true
	}
	if has {
		return textLayout{kind: segMessages, segs: segs}
	}
	if len(p.Body) > 0 {
		return textLayout{kind: segBody, segs: []textSegment{{msgIdx: -1, text: string(p.Body)}}}
	}
	if p.StreamChunk != "" {
		return textLayout{kind: segChunk, segs: []textSegment{{msgIdx: -1, text: p.StreamChunk}}}
	}
	return textLayout{kind: segMessages}
}

// writeBack stores new segment texts into the payload in place.
func writeBack(p *pipeline.Payload, l textLayout, texts []string) {
	switch l.kind {
	case segMessages:
		for i, seg := range l.segs {
			p.Messages[seg.msgIdx].Content = texts[i]
		}
	case segBody:
		p.Body = []byte(texts[0])
	case segChunk:
		p.StreamChunk = texts[0]
	}
}

// plannedEdit is one pending replacement in local segment coordinates.
type plannedEdit struct {
	seg         int
	start, end  int
	category    string
	fromFinding bool
}

// protectedRanges returns the token spans (redaction + alias) already present
// in text — the idempotency guard of the span mutators.
func protectedRanges(text string) [][2]int {
	var out [][2]int
	for _, re := range []*regexp.Regexp{redactTokenRe, aliasTokenRe} {
		for _, loc := range re.FindAllStringIndex(text, -1) {
			out = append(out, [2]int{loc[0], loc[1]})
		}
	}
	return out
}

// overlaps reports whether any protected range intersects [s,e).
func overlapsProtected(prot [][2]int, s, e int) bool {
	for _, r := range prot {
		if s < r[1] && r[0] < e {
			return true
		}
	}
	return false
}

// collectSpanEdits merges the two span sources into one deterministic,
// overlap-free edit plan:
//
//  1. findings spans of the run so far (filtered by categories, validated
//     against the layout — stale/invalid spans are step errors);
//  2. own-pattern matches, scanned per segment.
//
// Edits are sorted by position (stable: findings before patterns on ties —
// declaration order); overlapping spans merge into the earlier one, so a
// position never receives two replacements.
func collectSpanEdits(ctx context.Context, cfg spanMutator, l textLayout, findings []pipeline.Finding) ([]plannedEdit, error) {
	prot := make([][][2]int, len(l.segs))
	for i, seg := range l.segs {
		prot[i] = protectedRanges(seg.text)
	}
	var edits []plannedEdit
	for _, f := range findings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if f.Span == "" || !cfg.categorySelected(f.Category) {
			continue
		}
		s, e, ok := parseSpan(f.Span)
		if !ok {
			return nil, fmt.Errorf("finding %s/%s: span %q is not \"start:end\"", f.Step, f.Category, f.Span)
		}
		segIdx, ls, le, ok := locateSegment(l, s, e)
		if !ok {
			return nil, fmt.Errorf("finding %s/%s: span %d:%d is stale for the current payload layout (stale detector→mutator ordering, or the text changed in between)", f.Step, f.Category, s, e)
		}
		if overlapsProtected(prot[segIdx], ls, le) {
			continue // already-substituted text: the idempotency boundary
		}
		edits = append(edits, plannedEdit{seg: segIdx, start: ls, end: le, category: f.Category, fromFinding: true})
	}
	for si, seg := range l.segs {
		for _, pat := range cfg.patterns {
			for _, m := range pat.re.FindAllStringIndex(seg.text, maxSpanMatches) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if overlapsProtected(prot[si], m[0], m[1]) {
					continue
				}
				edits = append(edits, plannedEdit{seg: si, start: m[0], end: m[1], category: pat.category})
			}
		}
	}
	slices.SortStableFunc(edits, func(a, b plannedEdit) int {
		if a.seg != b.seg {
			return a.seg - b.seg
		}
		if a.start != b.start {
			return a.start - b.start
		}
		return a.end - b.end
	})
	return mergeEdits(edits), nil
}

// parseSpan parses the "start:end" byte-offset convention.
func parseSpan(s string) (int, int, bool) {
	a, b, ok := strings.Cut(s, ":")
	if !ok {
		return 0, 0, false
	}
	start, err1 := strconv.Atoi(a)
	end, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// locateSegment maps a joined-text span onto its segment; a span must sit
// inside ONE segment and respect UTF-8 rune boundaries (byte offsets never
// split a rune).
func locateSegment(l textLayout, s, e int) (segIdx, ls, le int, ok bool) {
	for i, seg := range l.segs {
		if s < seg.start || e > seg.start+len(seg.text) {
			continue
		}
		ls, le = s-seg.start, e-seg.start
		if ls == le {
			return i, ls, le, false
		}
		if !utf8.RuneStart(seg.text[ls]) || (le < len(seg.text) && !utf8.RuneStart(seg.text[le])) {
			return i, ls, le, false
		}
		return i, ls, le, true
	}
	return 0, 0, 0, false
}

// mergeEdits drops overlapping spans (the wider/earlier one wins: spans are
// sorted by start, so an overlap extends the current run; the FIRST span's
// category stays). Adjacent spans (end == next start) stay separate edits.
func mergeEdits(edits []plannedEdit) []plannedEdit {
	out := make([]plannedEdit, 0, len(edits))
	for _, e := range edits {
		if len(out) > 0 {
			last := &out[len(out)-1]
			if last.seg == e.seg && e.start < last.end {
				if e.end > last.end {
					last.end = e.end
				}
				continue
			}
		}
		out = append(out, e)
	}
	return out
}

// applySpanEdits replaces every planned edit via repl (ord is the 1-based
// ordinal of the edit across the whole payload, in position order) and
// returns the new per-segment texts aligned with l.segs. The caller writes
// them back with writeBack.
func applySpanEdits(ctx context.Context, l textLayout, edits []plannedEdit, repl func(e plannedEdit, ord int) (string, error)) ([]string, error) {
	texts := make([]string, len(l.segs))
	for i := range l.segs {
		texts[i] = l.segs[i].text
	}
	ord := 0
	for segIdx := range l.segs {
		var editsInSeg []plannedEdit
		for _, e := range edits {
			if e.seg == segIdx {
				editsInSeg = append(editsInSeg, e)
			}
		}
		if len(editsInSeg) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var sb strings.Builder
		pos := 0
		for _, e := range editsInSeg {
			ord++
			sb.WriteString(l.segs[segIdx].text[pos:e.start])
			r, err := repl(e, ord)
			if err != nil {
				return nil, err
			}
			sb.WriteString(r)
			pos = e.end
		}
		sb.WriteString(l.segs[segIdx].text[pos:])
		texts[segIdx] = sb.String()
	}
	return texts, nil
}

// tokenCategory sanitizes a category for embedding in "[REDACTED:<cat>:n]":
// only [A-Za-z0-9._-] survive; anything else becomes "_" so the token stays
// parseable by redactTokenRe.
func tokenCategory(cat string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		default:
			return '_'
		}
	}, cat)
}

// decodePseudonymCarrier parses a carry-session carrier (JSON alias→original)
// and returns the alias→original map plus the highest alias number in it.
func decodePseudonymCarrier(raw string) (map[string]string, int, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, 0, err
	}
	maxN := 0
	for alias := range m {
		g := aliasExactRe.FindStringSubmatch(alias)
		if g == nil {
			return nil, 0, fmt.Errorf("carrier alias %q is not a {{YPP_n}} token", alias)
		}
		if n, err := strconv.Atoi(g[1]); err == nil && n > maxN {
			maxN = n
		}
	}
	return m, maxN, nil
}

// encodePseudonymCarrier serializes the alias→original map. encoding/json
// sorts string map keys, so the carrier is deterministic for equal maps.
func encodePseudonymCarrier(aliasToOriginal map[string]string) (string, error) {
	b, err := json.Marshal(aliasToOriginal)
	if err != nil {
		return "", err
	}
	if len(b) > maxPseudonymCarrierBytes {
		return "", fmt.Errorf("pseudonym carrier is %d bytes, exceeds the %d-byte limit (%d aliases; lower the PII density or disable carry)", len(b), maxPseudonymCarrierBytes, len(aliasToOriginal))
	}
	return string(b), nil
}
