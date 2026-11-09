package handlers

//
// TestUIActionsInventory is the UI-side complement of the route lock-step
// gates: it extracts every admin-API call the dashboard makes from the
// TypeScript sources (web/dashboard/src) and resolves each one against
// docs/api/admin.openapi.yaml — the same documented surface that
// TestAdminRoutesInventory pins to the walked router. A UI action without a
// documented operation is exactly the "hidden UI-only endpoint" the packet
// negative criterion blocks: the dashboard cannot reach anything that is not
// a golden, permission-classed admin route.
//
// Resolution is transitive: UI action → admin.openapi.yaml operation →
// walked SetupRouter route (TestAdminRoutesInventory enforces the second
// arrow). The walked-router set is used here only to refine failure
// messages (route-exists-but-undocumented vs no-route-at-all).
//
// Extraction rules (kept deliberately narrow so a parse gap fails loudly
// instead of silently shrinking the inventory):
//   - transport helpers fetchJSON/readJSON (GET), postJSON (explicit method
//     literal or default POST) and sendMutation (method: '…' in the init
//     object, fetch default GET when absent) get a literal first-argument
//     URL; fetchJSON/postJSON/readJSON URLs are /api-prefixed exactly like
//     the runtime transport does.
//   - a direct fetch('…') with a literal path (the /auth/csrf bootstrap,
//     the /auth/logout portal escape) is inventoried as-is.
//   - ${…} template holes become {} wildcards; query strings are cut at the
//     first '?'. A URL that is not a static literal (identifier, `+`
//     concatenation, leftover template syntax) is a hard failure so new
//     call shapes must extend the extractor, not dodge it.
//   - *.test.ts(x) fixtures are not runtime UI actions and are skipped.
//
// The full inventory can be printed with:
//
//	UI_ACTIONS_INVENTORY_GENERATE=1 go test ./services/admin/handlers/ -run TestUIActionsInventoryGenerate
//
// which is the mechanical source of the packet inventory artifact
// (artifacts/internal-delivery-program/N07-P07/).

import (
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// dashboardSrcRoot is the dashboard TypeScript source tree, relative to this
// package directory (services/admin/handlers).
const dashboardSrcRoot = "../../../web/dashboard/src"

// envUIActionsDump enables TestUIActionsInventoryGenerate.
const envUIActionsDump = "UI_ACTIONS_INVENTORY_GENERATE"

// uiAction is one distinct (method, path) call the dashboard makes. Files
// records every call site ("file:line") that produces it.
type uiAction struct {
	Method string
	Path   string
	Files  []string
}

// key sorts and deduplicates actions.
func (a uiAction) key() string { return a.Method + " " + a.Path }

// uiDynamicCall marks a call site the extractor refuses to guess about.
type uiDynamicCall struct {
	File string // "file:line"
	Why  string
}

// templateHole matches a ${…} hole of a TypeScript template literal (no
// nested closing brace until the hole ends — true for every dashboard URL).
var templateHole = regexp.MustCompile(`\$\{[^}]*\}`)

// methodLiteral matches an explicit HTTP method argument or init property.
var methodLiteral = regexp.MustCompile(`method\s*:\s*'([A-Z]+)'`)

// extractUIActions walks dashboardSrcRoot and returns the distinct actions
// (sorted by key) plus the number of literal call sites and scanned files.
// Dynamic/unparseable call sites are returned separately so the caller can
// fail loudly: an inventory that silently skips shapes is not an inventory.
func extractUIActions(tb testing.TB) (actions []uiAction, callSites, files int, dynamic []uiDynamicCall) {
	tb.Helper()
	var filesScanned int
	fsys := os.DirFS(dashboardSrcRoot)
	err := fs.WalkDir(fsys, ".", func(rel string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".ts") && !strings.HasSuffix(name, ".tsx") {
			return nil
		}
		// Test fixtures mock arbitrary paths ('/x', '/api/things'); they are
		// not shipped UI actions.
		if strings.Contains(name, ".test.") {
			return nil
		}
		raw, err := fs.ReadFile(fsys, rel)
		if err != nil {
			return err
		}
		filesScanned++
		scanFileActions(tb, rel, string(raw), &actions, &callSites, &dynamic)
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", dashboardSrcRoot, err)
	}
	sort.Slice(actions, func(i, j int) bool {
		if actions[i].Path != actions[j].Path {
			return actions[i].Path < actions[j].Path
		}
		return actions[i].Method < actions[j].Method
	})
	// Merge call sites of duplicate (method, path) pairs.
	merged := actions[:0]
	for _, a := range actions {
		if n := len(merged); n > 0 && merged[n-1].key() == a.key() {
			merged[n-1].Files = append(merged[n-1].Files, a.Files...)
			continue
		}
		merged = append(merged, a)
	}
	sort.Slice(dynamic, func(i, j int) bool { return dynamic[i].File < dynamic[j].File })
	return merged, callSites, filesScanned, dynamic
}

// scanFileActions extracts the call sites of one file. It finds the four
// transport helpers plus direct fetch('…') literals, parses the argument
// list with a string/comment-aware tokenizer and normalizes the URL.
func scanFileActions(tb testing.TB, rel, src string, actions *[]uiAction, callSites *int, dynamic *[]uiDynamicCall) {
	tb.Helper()
	fail := func(line int, why string) {
		*dynamic = append(*dynamic, uiDynamicCall{File: fmt.Sprintf("%s:%d", rel, line), Why: why})
	}
	for _, hit := range findCallSites(src, []string{"fetchJSON", "readJSON", "postJSON", "sendMutation", "fetch"}) {
		line := 1 + strings.Count(src[:hit.argStart], "\n")
		switch hit.helper {
		case "fetchJSON", "readJSON":
			method := "GET"
			path, ok := normalizeUIPath(true, hit.urlLiteral)
			if !ok {
				fail(line, "non-literal or unparseable URL for "+hit.helper+": "+truncate(hit.urlLiteral))
				continue
			}
			if transportForwarding(path) {
				continue // the /api${url} forwarding inside the transport layer, not an action
			}
			*actions = append(*actions, uiAction{Method: method, Path: path, Files: []string{fmt.Sprintf("%s:%d", rel, line)}})
			*callSites++
		case "postJSON":
			path, ok := normalizeUIPath(true, hit.urlLiteral)
			if !ok {
				fail(line, "non-literal or unparseable URL for postJSON: "+truncate(hit.urlLiteral))
				continue
			}
			if transportForwarding(path) {
				continue // transport-layer forwarding, not an action
			}
			method := "POST"
			if args := splitTopLevelArgs(hit.restArgs); len(args) >= 2 {
				// args[0] is the body; args[1] the explicit method argument.
				if arg := strings.TrimSpace(args[1]); arg != "" {
					if m, ok := unquotedVerb(arg); ok {
						method = m
					} else {
						fail(line, "postJSON method is not a literal verb: "+truncate(arg))
						continue
					}
				}
			}
			*actions = append(*actions, uiAction{Method: method, Path: path, Files: []string{fmt.Sprintf("%s:%d", rel, line)}})
			*callSites++
		case "sendMutation":
			path, ok := normalizeUIPath(false, hit.urlLiteral)
			if !ok {
				fail(line, "non-literal or unparseable URL for sendMutation: "+truncate(hit.urlLiteral))
				continue
			}
			if transportForwarding(path) {
				continue // transport-layer forwarding, not an action
			}
			// fetch() defaults to GET when the init object carries no
			// method; every shipped sendMutation site passes one.
			method := "GET"
			init := hit.restArgs
			if args := splitTopLevelArgs(hit.restArgs); len(args) >= 1 {
				init = args[0]
			}
			if m := methodLiteral.FindStringSubmatch(init); m != nil {
				method = m[1]
			}
			*actions = append(*actions, uiAction{Method: method, Path: path, Files: []string{fmt.Sprintf("%s:%d", rel, line)}})
			*callSites++
		case "fetch":
			// Only literal bootstrap paths (the /auth/* calls in
			// transport.ts); everything else (agentTestURL) is a
			// data-plane call built at runtime, inventoried in the
			// packet artifact, not here.
			path, ok := normalizeUIPath(false, hit.urlLiteral)
			if !ok {
				continue // runtime-built fetch target: not an admin-surface literal
			}
			if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/auth/") {
				continue
			}
			method := "GET"
			if m := methodLiteral.FindStringSubmatch(hit.restArgs); m != nil {
				method = m[1]
			}
			*actions = append(*actions, uiAction{Method: method, Path: path, Files: []string{fmt.Sprintf("%s:%d", rel, line)}})
			*callSites++
		}
	}
}

// transportForwarding reports whether the normalized path is the transport
// layer forwarding a caller-supplied URL (readJSON(`/api${url}`) and
// sendMutation(`/api${url}`, …) in http.ts) — every segment past the
// literal /api prefix is a wildcard, so the site denotes no concrete
// capability.
func transportForwarding(path string) bool {
	segs := strings.Split(path, "/")
	if len(segs) < 3 || segs[1] != "api" {
		return false
	}
	for _, seg := range segs[2:] {
		if seg != "{}" && seg != "{+}" {
			return false
		}
	}
	return true
}

// truncate shortens a raw literal for an error message.
func truncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}

// unquotedVerb reports the HTTP verb when arg is a quoted method literal.
func unquotedVerb(arg string) (string, bool) {
	if len(arg) >= 2 {
		if q := arg[0]; q == '\'' || q == '"' {
			if end := strings.IndexByte(arg[1:], q); end >= 0 {
				v := arg[1 : 1+end]
				switch v {
				case "POST", "PUT", "PATCH", "DELETE":
					return v, true
				}
			}
		}
	}
	return "", false
}

// normalizeUIPath turns a raw TypeScript literal into a comparable path:
// a trailing ${…} hole that produces a query string is stripped, remaining
// query strings are cut at the first '?', the leading helper-built prefix
// hole (${orgBase(orgId)}) becomes a multi-segment wildcard {+}, every
// other ${…} hole becomes a one-segment wildcard {}, and the /api prefix
// applied by the runtime transport is added for the helper calls that add
// it. ok=false marks a URL the extractor refuses to guess about
// (identifier fragments, concatenation, unterminated template syntax).
func normalizeUIPath(apiPrefix bool, raw string) (string, bool) {
	// A trailing hole may only be a query-string builder (e.g.
	// `${suffix ? `?${suffix}` : ''}`); anything else must be static.
	if stripped, ok := stripQuerySuffixHole(raw); ok {
		raw = stripped
	}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		raw = raw[:i]
	}
	// Helper-built leading prefix (orgBase → /organizations/{orgId}):
	// one hole, unknown segment count, tail must match a documented path.
	// The hole expands to a /-rooted segment run, so {+} becomes its own
	// segment after the /api prefix.
	if strings.HasPrefix(raw, "${") {
		if hole := templateHole.FindString(raw); hole != "" && strings.HasPrefix(raw[len(hole):], "/") {
			raw = "/{+}" + raw[len(hole):]
		}
	}
	raw = templateHole.ReplaceAllString(raw, "{}")
	if raw == "/api{}" {
		// readJSON(`/api${url}`)-style transport forwarding: the caller
		// supplies everything past the prefix, so the site denotes no
		// concrete action (callers skip it via transportForwarding).
		return "/api/{+}", true
	}
	if apiPrefix && !strings.HasPrefix(raw, "/api/") {
		raw = "/api" + raw
	}
	if !strings.HasPrefix(raw, "/") {
		return "", false
	}
	for _, seg := range strings.Split(raw, "/")[1:] {
		switch seg {
		case "{}", "{+}":
			continue
		}
		if seg == "" {
			return "", false // trailing or doubled slash: not a static path
		}
		for _, r := range seg {
			ok := r == '_' || r == '-' || r == '.' || r == '~' || r == '@' || r == '=' ||
				(r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
			if !ok {
				return "", false
			}
		}
	}
	return raw, true
}

// stripQuerySuffixHole reports whether raw ends with a ${…} hole whose
// expression builds a query string (contains a `?` template), and returns
// the path without it. A hole that contributes PATH segments must not be
// stripped — it stays a visible wildcard instead. Nested ${…} holes are
// handled by trying closing candidates from the last one backwards.
func stripQuerySuffixHole(raw string) (string, bool) {
	if !strings.HasSuffix(raw, "}") {
		return raw, false
	}
	for idx := strings.LastIndex(raw, "${"); idx >= 0; idx = strings.LastIndex(raw[:idx], "${") {
		end, ok := scanTSExpr(raw, idx+2, 1)
		if !ok || end != len(raw) {
			continue // not the hole that closes the literal
		}
		if strings.Contains(raw[idx+2:len(raw)-1], "`?") {
			return raw[:idx], true
		}
		return raw, false
	}
	return raw, false
}

// callSite is one parsed call: the helper name, the raw first-argument
// literal and the raw text of the remaining arguments (method extraction).
type callSite struct {
	helper     string
	urlLiteral string
	restArgs   string
	argStart   int // offset of the helper name in the source (for line numbers)
}

// findCallSites locates helper( … ) and fetch( … ) call sites with a
// string/comment-aware scan. The first argument must be a complete '…',
// "…" or `…` literal; anything else produces no site here (helpers) and the
// caller's completeness checks keep dynamic fetch targets out of scope.
func findCallSites(src string, helpers []string) []callSite {
	var out []callSite
	i := 0
	for i < len(src) {
		// Skip comments so documented names never parse as calls.
		switch {
		case strings.HasPrefix(src[i:], "//"):
			if j := strings.Index(src[i:], "\n"); j >= 0 {
				i += j
				continue
			}
			i = len(src)
			continue
		case strings.HasPrefix(src[i:], "/*"):
			if j := strings.Index(src[i:], "*/"); j >= 0 {
				i += j + 2
				continue
			}
			i = len(src)
			continue
		}
		if q := src[i]; q == '\'' || q == '"' || q == '`' {
			// Skip over any literal so names inside strings never match.
			if _, next, ok := scanTSLiteral(src, i); ok {
				i = next
				continue
			}
			i++
			continue
		}
		matched := ""
		for _, h := range helpers {
			if strings.HasPrefix(src[i:], h) {
				before := byte(0)
				if i > 0 {
					before = src[i-1]
				}
				if i+len(h) < len(src) && (isIdentPart(before) || isIdentPart(src[i+len(h)])) {
					continue // longer identifier, not the helper
				}
				matched = h
				break
			}
		}
		if matched == "" {
			i++
			continue
		}
		j := i + len(matched)
		// Optional generic type arguments <…> between the name and "(".
		if j < len(src) && src[j] == '<' {
			depth := 0
			for ; j < len(src); j++ {
				if src[j] == '<' {
					depth++
				} else if src[j] == '>' {
					depth--
					if depth == 0 {
						j++
						break
					}
				}
			}
			if depth != 0 {
				return out // unterminated generic: stop scanning this file
			}
		}
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\n') {
			j++
		}
		if j >= len(src) || src[j] != '(' {
			i = j
			continue
		}
		args, ok := scanCallArgs(src, j+1)
		if !ok {
			i = j
			continue
		}
		first, rest, hasFirst := splitCallArgs(args)
		if !hasFirst {
			i = j
			continue
		}
		urlLit, restArgs, litOK := firstArgLiteral(first, rest)
		if litOK {
			out = append(out, callSite{helper: matched, urlLiteral: urlLit, restArgs: restArgs, argStart: i})
		}
		i = j + 1
	}
	return out
}

// splitTopLevelArgs splits raw argument text (already past the first
// argument's separating comma) into its top-level comma-separated
// arguments, string-literal aware.
func splitTopLevelArgs(args string) []string {
	var out []string
	depth := 0
	start := 0
	i := 0
	for i < len(args) {
		c := args[i]
		switch c {
		case '\'', '"', '`':
			_, n, ok := scanTSLiteral(args, i)
			if !ok {
				i++
				continue
			}
			i = n
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, args[start:i])
				start = i + 1
			}
		}
		i++
	}
	out = append(out, args[start:])
	return out
}

// isIdentPart reports whether c can be part of a TypeScript identifier.
func isIdentPart(c byte) bool {
	return c == '_' || c == '$' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// scanTSLiteral scans the literal starting at src[start] ('…', "…" or `…`,
// with escapes and arbitrarily nested ${…} template holes). It returns the
// literal's raw text (including quotes) and the index just past it.
func scanTSLiteral(src string, start int) (raw string, next int, ok bool) {
	if start >= len(src) {
		return "", start, false
	}
	q := src[start]
	if q != '\'' && q != '"' && q != '`' {
		return "", start, false
	}
	i := start + 1
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\\' && i+1 < len(src):
			i += 2
		case q == '`' && c == '$' && i+1 < len(src) && src[i+1] == '{':
			j, ok2 := scanTSExpr(src, i+2, 1)
			if !ok2 {
				return "", start, false
			}
			i = j
		case c == q:
			return src[start : i+1], i + 1, true
		default:
			i++
		}
	}
	return "", start, false
}

// scanTSExpr scans a ${…} template-hole expression from src[start] until the
// brace opened at the given depth closes. Nested literals are skipped so a
// nested template (`…` inside the hole) cannot end the outer literal early.
func scanTSExpr(src string, start, braceDepth int) (int, bool) {
	i := start
	for i < len(src) {
		c := src[i]
		switch c {
		case '\'', '"', '`':
			_, n, ok := scanTSLiteral(src, i)
			if !ok {
				return 0, false
			}
			i = n
		case '{':
			braceDepth++
			i++
		case '}':
			braceDepth--
			i++
			if braceDepth == 0 {
				return i, true
			}
		default:
			i++
		}
	}
	return 0, false
}

// scanCallArgs returns the raw text between the call's parentheses,
// balancing (), [] and {} and skipping literals; comments are not expected
// inside dashboard call arguments and abort the parse (no site).
func scanCallArgs(src string, start int) (string, bool) {
	depth := 0
	i := start
	for i < len(src) {
		c := src[i]
		switch c {
		case '\'', '"', '`':
			_, n, ok := scanTSLiteral(src, i)
			if !ok {
				return "", false
			}
			i = n
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				if c == ')' {
					return src[start:i], true
				}
				return "", false
			}
			depth--
		}
		i++
	}
	return "", false
}

// splitCallArgs splits the raw argument text into the first argument and the
// remainder at the first top-level comma.
func splitCallArgs(args string) (first, rest string, hasFirst bool) {
	depth := 0
	i := 0
	for i < len(args) {
		c := args[i]
		switch c {
		case '\'', '"', '`':
			_, n, ok := scanTSLiteral(args, i)
			if !ok {
				return args, "", true
			}
			i = n
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				return args[:i], args[i+1:], true
			}
		}
		i++
	}
	return args, "", true
}

// firstArgLiteral validates that first is exactly one string literal and
// returns its VALUE (outer quotes stripped; ${…} holes kept for path
// normalization) plus the remaining raw arguments.
func firstArgLiteral(first, rest string) (urlLiteral, restArgs string, ok bool) {
	trimmed := strings.TrimSpace(first)
	if trimmed == "" {
		return "", "", false
	}
	raw, next, ok2 := scanTSLiteral(trimmed, 0)
	if !ok2 || strings.TrimSpace(trimmed[next:]) != "" {
		return "", "", false // identifier, concatenation or mixed expression
	}
	return raw[1 : len(raw)-1], rest, true
}

// pathSegmentsCompatible reports whether a UI path ({} one-segment and {+}
// multi-segment wildcards) can address a route pattern ({name} wildcards):
// literals equal, either side wildcard wins; a UI {+} absorbs one or more
// trailing segments of the route pattern (helper-built prefixes).
func pathSegmentsCompatible(uiPath, routePattern string) bool {
	return segmentsMatch(strings.Split(uiPath, "/"), strings.Split(routePattern, "/"))
}

func segmentsMatch(ui, route []string) bool {
	if len(ui) == 0 {
		return len(route) == 0
	}
	if ui[0] == "{+}" {
		for take := 1; take <= len(route); take++ {
			if segmentsMatch(ui[1:], route[take:]) {
				return true
			}
		}
		return false
	}
	if len(route) == 0 {
		return false
	}
	if ui[0] == "{}" || strings.HasPrefix(route[0], "{") || ui[0] == route[0] {
		return segmentsMatch(ui[1:], route[1:])
	}
	return false
}

// resolveDocumented finds the documented operation a UI action addresses.
// UI wildcard actions ({+} absorbs one or more segments) are frequently
// compatible with dozens of spec patterns, so the winner must be chosen by
// a deterministic specificity ranking — iterating the map directly would
// make the resolved x-permission (and any recorded artifact) flip between
// runs. Ranking: most matched UI literal segments, fewest route wildcards,
// longest route, lexicographic pattern.
func resolveDocumented(documented map[string]routeSpec, action uiAction) (routeSpec, bool) {
	uiLiterals := uiLiteralSegments(action.Path)
	var best routeSpec
	found := false
	for _, spec := range documented {
		if spec.Method != action.Method {
			continue
		}
		if !pathSegmentsCompatible(action.Path, spec.Pattern) {
			continue
		}
		if !found {
			best, found = spec, true
			continue
		}
		br, sr := documentMatchRank(uiLiterals, best), documentMatchRank(uiLiterals, spec)
		if sr < br || (sr == br && spec.Pattern < best.Pattern) {
			best = spec
		}
	}
	return best, found
}

// uiLiteralSegments counts the non-wildcard segments of a UI action path.
func uiLiteralSegments(uiPath string) []string {
	var out []string
	for _, seg := range strings.Split(uiPath, "/") {
		if seg != "" && seg != "{}" && seg != "{+}" {
			out = append(out, seg)
		}
	}
	return out
}

// documentMatchRank orders compatible documented routes from the most
// specific match to the least; lower wins.
func documentMatchRank(uiLiterals []string, spec routeSpec) int {
	route := strings.Split(spec.Pattern, "/")
	literals := 0
	for _, l := range uiLiterals {
		for _, r := range route {
			if l == r {
				literals++
				break
			}
		}
	}
	wildcards := 0
	for _, r := range route {
		if strings.HasPrefix(r, "{") {
			wildcards++
		}
	}
	return -1000*literals + 10*wildcards - len(route)
}

// resolveGolden finds a golden-inventoried route a UI action addresses.
func resolveGolden(routes []routeSpec, action uiAction) (routeSpec, bool) {
	for _, spec := range routes {
		if spec.Method != action.Method {
			continue
		}
		if pathSegmentsCompatible(action.Path, spec.Pattern) {
			return spec, true
		}
	}
	return routeSpec{}, false
}

// parseGoldenRoutes reads a routes golden file ("METHOD <pattern> <chain>",
// '#' comments) into route specs. The golden file is the fully-wired
// inventory the route golden tests pin.
func parseGoldenRoutes(tb testing.TB, path string) []routeSpec {
	tb.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- compile-time golden constants passed by the tests
	if err != nil {
		tb.Fatalf("read golden %s: %v", path, err)
	}
	var out []routeSpec
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			tb.Fatalf("golden %s: unparsable line %q", path, line)
		}
		out = append(out, routeSpec{Method: fields[0], Pattern: fields[1]})
	}
	if len(out) == 0 {
		tb.Fatalf("golden %s: no routes parsed", path)
	}
	return out
}

// gatewaySideOps filters an OpenAPI operation map to gateway-served
// operations (path-level servers on inference hosts), mirroring the
// adminSpecSide classification used by the cross-spec checks.
func gatewaySideOps(tb testing.TB, documented map[string]routeSpec) map[string]routeSpec {
	tb.Helper()
	out := make(map[string]routeSpec, len(documented))
	for key, spec := range documented {
		if !adminSpecSide(spec) {
			out[key] = spec
		}
	}
	if len(out) == 0 {
		tb.Fatalf("no gateway-side operations found in %s — the server-side classification is broken", gatewayOpenAPISpec)
	}
	return out
}

// uiActionFloors are the anti-regression floors: a parser or tree-layout
// regression must not silently empty the inventory. Distinct/calls count the
// shipped dashboard call sites as of 2026-10-31; the sentinel actions pin
// representative shapes of the domains the card names (guard packs,
// tool policies, request explorer, model catalog, session surface).
var uiActionFloors = struct {
	files    int
	calls    int
	distinct int
	sentinel []uiAction
}{
	files:    25,
	calls:    150,
	distinct: 110,
	sentinel: []uiAction{
		{Method: "GET", Path: "/api/guard-packs"},
		{Method: "GET", Path: "/api/organizations/{}/tool-policies"},
		{Method: "GET", Path: "/api/organizations/{}/requests"},
		{Method: "GET", Path: "/api/models"},
		{Method: "GET", Path: "/api/me"},
	},
}

// golden constants for the resolution tiers (relative to this package).
const (
	adminRoutesGolden   = "testdata/routes_admin.golden"
	gatewayRoutesGolden = "../../../pkg/gateway/testdata/routes_gateway.golden"
)

// uiActionBaselines pins the UI actions that do not (yet) resolve to an
// OpenAPI-documented operation, with the exact reason each one is
// acceptable today. The baselines are closed and self-cleaning:
//   - a NEW unresolved UI action (not listed) fails the test — the negative
//     criterion blocks hidden UI-only endpoints;
//   - a LISTED action that became documented (or whose serving route
//     disappeared) fails the test — stale entries must be removed;
//   - every listed action must still match its tier's golden inventory, so
//     a removed route cannot hide behind a stale baseline entry.
var uiActionBaselines = struct {
	// goldenOnly: route exists on the fully-wired admin router
	// (routes_admin.golden) but is absent from docs/api/admin.openapi.yaml.
	// N07-P07-T03 closed the gap for every UI-reachable DB-gated route
	// (credits wallet + top-up + low-balance, feedback list, org region
	// routing) — they are documented and locked to the fully-wired golden
	// walk by dbGatedAdminRoutes in routes_inventory_test.go, so this tier
	// is empty today. The pin stays: any FUTURE served-but-undocumented
	// admin route must be listed here with its reason until its spec entry
	// lands.
	goldenOnly map[string]string
	// gatewayInfra: dashboard calls a GATEWAY data-plane route (agent
	// principal, X-Org-Id) that the public REST spec deliberately excludes
	// (see pkg/gateway/api_openapi_drift_test.go — /api/mcp/* transport
	// surfaces are skipped there); the route stays enforced by the gateway
	// 41-route golden, which the tier check consults.
	gatewayInfra map[string]string
	// unserved: the UI renders an explicit unavailable state for an admin
	// surface that is deliberately NOT served yet (MC-4 contract hole; the
	// store method exists, the route does not). If one of these starts
	// resolving anywhere, the hole is closed and the entry must be removed.
	unserved map[string]string
}{
	goldenOnly: map[string]string{}, // #nosec G101 -- URL-path inventory keys, not credentials
	gatewayInfra: map[string]string{ // #nosec G101 -- URL-path inventory keys, not credentials
		"POST /api/mcp/auth/{}/begin":  "gateway agent-principal OAuth begin; /api/mcp/* excluded from the public REST spec by design",
		"POST /api/mcp/credentials/{}": "gateway agent-principal headers credential; /api/mcp/* excluded from the public REST spec by design",
	},
	unserved: map[string]string{ // #nosec G101 -- URL-path inventory keys, not credentials
		"GET /api/organizations/{}/mcp/user-credentials":          "MC-4 contract hole: admin surface not served; UI renders the explicit unavailable state on 404",
		"DELETE /api/organizations/{}/mcp/user-credentials/{}/{}": "MC-4 contract hole: proposed admin surface, route deliberately not registered",
	},
}

// classifyUIAction resolves one action against the four surfaces and
// returns its tier: "admin-spec", "gateway-spec", "admin-golden-only",
// "gateway-golden-only" or "unserved".
func classifyUIAction(action uiAction, adminSpec, gatewaySpec map[string]routeSpec, adminGolden, gatewayGolden []routeSpec) string {
	if _, ok := resolveDocumented(adminSpec, action); ok {
		return "admin-spec"
	}
	if _, ok := resolveDocumented(gatewaySpec, action); ok {
		return "gateway-spec"
	}
	if _, ok := resolveGolden(adminGolden, action); ok {
		return "admin-golden-only"
	}
	if _, ok := resolveGolden(gatewayGolden, action); ok {
		return "gateway-golden-only"
	}
	return "unserved"
}

// TestUIActionsInventory is the UI-side drift gate: every dashboard API call
// resolves to a documented operation, a golden-inventoried route with a
// pinned reason, or a pinned unserved contract hole — nothing else.
func TestUIActionsInventory(t *testing.T) {
	actions, callSites, files, dynamic := extractUIActions(t)

	if len(dynamic) > 0 {
		for _, d := range dynamic {
			t.Errorf("dashboard call the extractor cannot inventory (%s): %s", d.File, d.Why)
		}
	}
	if files < uiActionFloors.files {
		t.Fatalf("scanned only %d dashboard files — the source walk is broken", files)
	}
	if callSites < uiActionFloors.calls {
		t.Fatalf("extracted only %d call sites (floor %d) — the extractor is broken", callSites, uiActionFloors.calls)
	}
	if len(actions) < uiActionFloors.distinct {
		t.Fatalf("distinct UI actions %d < floor %d — extraction lost entries", len(actions), uiActionFloors.distinct)
	}
	have := make(map[string]bool, len(actions))
	for _, a := range actions {
		have[a.key()] = true
	}
	for _, s := range uiActionFloors.sentinel {
		if !have[s.key()] {
			t.Errorf("sentinel UI action %s missing from the extracted inventory — extraction is broken", s.key())
		}
	}

	adminSpec := parseOpenAPIRoutes(t, adminOpenAPISpec)
	gatewaySpec := gatewaySideOps(t, parseOpenAPIRoutes(t, gatewayOpenAPISpec))
	adminGolden := parseGoldenRoutes(t, adminRoutesGolden)
	gatewayGolden := parseGoldenRoutes(t, gatewayRoutesGolden)

	tierOf := make(map[string]string, len(actions))
	tierCount := map[string]int{}
	for _, a := range actions {
		tier := classifyUIAction(a, adminSpec, gatewaySpec, adminGolden, gatewayGolden)
		tierOf[a.key()] = tier
		tierCount[tier]++
		tierBaselines := map[string]map[string]string{
			"admin-golden-only":   uiActionBaselines.goldenOnly,
			"gateway-golden-only": uiActionBaselines.gatewayInfra,
			"unserved":            uiActionBaselines.unserved,
		}
		if _, pinned := tierBaselines[tier][a.key()]; !pinned {
			switch tier {
			case "admin-spec", "gateway-spec":
				// documented capability: exactly the packet acceptance
			case "admin-golden-only":
				t.Errorf("UI action %s %s (%s): served admin route is missing from %s and unpinned — add it to the spec (N07-P07-T03) or pin it in uiActionBaselines with a reason",
					a.Method, a.Path, strings.Join(a.Files, ", "), adminOpenAPISpec)
			case "gateway-golden-only":
				t.Errorf("UI action %s %s (%s): gateway-only route is not documented and unpinned — pin it in uiActionBaselines.gatewayInfra with a reason",
					a.Method, a.Path, strings.Join(a.Files, ", "))
			default:
				t.Errorf("UI action %s %s (%s): matches NO served route on any surface — hidden UI-only endpoint (negative criterion)",
					a.Method, a.Path, strings.Join(a.Files, ", "))
			}
			continue
		}
	}

	// Baseline staleness: every pinned entry must still classify into its
	// tier (the serving route still exists / the hole still exists) and
	// must not have become documented.
	stale := func(baseline map[string]string, wantTier string) {
		for key := range baseline {
			tier, ok := tierOf[key]
			if !ok {
				t.Errorf("baseline entry %q no longer corresponds to any dashboard call — remove it from uiActionBaselines", key)
				continue
			}
			if tier != wantTier {
				t.Errorf("baseline entry %q now classifies as %q (was %q) — the surface moved; update or remove the pin",
					key, tier, wantTier)
			}
		}
	}
	stale(uiActionBaselines.goldenOnly, "admin-golden-only")
	stale(uiActionBaselines.gatewayInfra, "gateway-golden-only")
	stale(uiActionBaselines.unserved, "unserved")

	t.Logf("UI actions: %d distinct (%d call sites, %d files); tiers: admin-spec=%d gateway-spec=%d admin-golden-only=%d gateway-golden-only=%d unserved=%d",
		len(actions), callSites, files,
		tierCount["admin-spec"], tierCount["gateway-spec"], tierCount["admin-golden-only"],
		tierCount["gateway-golden-only"], tierCount["unserved"])
}

// TestUIActionsInventoryGenerate prints the full UI-action inventory (one
// line per distinct action with its resolution tier and call sites) — the
// mechanical source for artifacts/internal-delivery-program/N07-P07/ packet records.
// Opt-in via envUIActionsDump; without it the test skips.
func TestUIActionsInventoryGenerate(t *testing.T) {
	if os.Getenv(envUIActionsDump) == "" {
		t.Skipf("set %s=1 to print the UI action inventory", envUIActionsDump)
	}
	actions, callSites, files, dynamic := extractUIActions(t)
	adminSpec := parseOpenAPIRoutes(t, adminOpenAPISpec)
	gatewaySpec := gatewaySideOps(t, parseOpenAPIRoutes(t, gatewayOpenAPISpec))
	adminGolden := parseGoldenRoutes(t, adminRoutesGolden)
	gatewayGolden := parseGoldenRoutes(t, gatewayRoutesGolden)
	fmt.Printf("# UI actions: %d distinct, %d call sites, %d files; dynamic/unparseable: %d\n",
		len(actions), callSites, files, len(dynamic))
	for _, d := range dynamic {
		fmt.Printf("# DYNAMIC %s: %s\n", d.File, d.Why)
	}
	for _, a := range actions {
		tier := classifyUIAction(a, adminSpec, gatewaySpec, adminGolden, gatewayGolden)
		perm := "-"
		if spec, ok := resolveDocumented(adminSpec, a); ok {
			perm = spec.Permission
		}
		fmt.Printf("%-6s %-70s tier: %-20s x-permission: %-12s <- %s\n",
			a.Method, a.Path, tier, perm, strings.Join(a.Files, ", "))
	}
}
