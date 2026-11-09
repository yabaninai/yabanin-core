// Package metrics_test — N13-P04-T05 negative-scenario battery (part 1/2:
// firing regression). Part 2 (secrets-in-message invariant) lives in
// alerts_secrets_test.go; both files share the harness helpers declared here.
//
// The card's negative criterion is «Тестовая ошибка вызывает alert; секреты не
// попадают в сообщение» — a test error must fire the RIGHT alert (real rule
// evaluation over real metric state, right alertname, right severity, right
// labels) and no secret material may reach the notification message.
//
// What "real rule evaluation" means here, and what it does not:
//   - The alert rules are loaded from the REAL deploy/prometheus/alert-rules.yml
//     (the single rules file Prometheus actually loads; 29 alerts). Nothing is
//     copied or re-declared: every expr, for:, label and annotation this battery
//     evaluates comes from that file at test time. The expected severity and
//     for: tables below are hand-written double-entry specs; file drift from
//     either table turns the battery red (and a table drift fails against the
//     file too), and the mutation teeth prove each check has a tooth.
//   - The metric state is the REAL default Prometheus registry this process
//     exposes: scenarios drive the real instrumented surfaces (the chi
//     middleware on a real router via httptest — including real 5xx statuses
//     written through the wrapped writer —, the closed silent-failure
//     registry, the exported collector variables that production increments)
//     and the harness samples the gathered registry — not synthetic mirrors.
//   - The evaluator implements the PromQL subset these 29 exprs actually use
//     (selectors + {}=,!=,=~,!~ matchers, range vectors, rate/increase/sum/
//     sum by/max by/histogram_quantile/clamp_min/max_over_time, / + - *,
//     comparisons, `and` with the optional on(...) vector-match clause, NaN
//     semantics) over the harness's sample timeline. It is a deterministic
//     harness, NOT the Prometheus engine; disclosed deltas: rate = (last-
//     first)/(t_last-t_first) over the recorded window (Prom extrapolates to
//     window edges), increase = rate*window, gauge selectors read the last
//     sample, and max_over_time is the max over the recorded samples in the
//     window with no extrapolation (an empty window yields no series, like
//     Prom). Deltas do not weaken the teeth: every
//     threshold/label/for-duration in the assertions is read from the real
//     rules file, and the mutation cells below prove the battery goes red on
//     each class of rule change.
//   - Series that are fed by infrastructure exporters rather than this repo
//     (node_filesystem_*, up) and one counter whose producer package is not
//     linked into this test binary (credit_audit_dropped_total — the collector
//     is unexported in services/admin/handlers; the real queue-overflow path is
//     exercised by the T03 measurement harness) are injected as declared
//     synthetic series with the exact metric/label names the rules reference.
//     Every other series comes from the real registry. The three synthetic
//     alerts fire through the same rule-evaluation path in
//     TestN13P04T05_SyntheticInjectedAlertsStillFire; the remaining 26 have
//     driven real-state scenarios in the main battery, and the battery asserts
//     the two sets exactly partition the rules file.
//
// Firing semantics: a rule fires when its expr returns a non-empty vector for
// `for:` continuously — the harness tracks first-true per alert across ticks
// and reports the fire at the first tick where the state has held for the
// rule's for: duration, exactly like the Prometheus rules manager (minus
// evaluation-interval quantization, which the harness ticks replace).
// Scenarios declare the bad state and the expected fire; the harness extends
// the synthetic clock to first-true + the rule's own for: (+1s tick quantum)
// and asserts the fire lands exactly there — so a for: regression also moves
// the observed fire time and is caught twice (double-entry table + timing).
package metrics_test

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/yaml.v3"

	"github.com/reireirei/yabanin/pkg/cache"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/shadow"
	"github.com/reireirei/yabanin/pkg/tracing"
)

// rulesPath is the real rules file relative to pkg/metrics (the CWD of the
// compiled test binary).
const rulesPath = "../../deploy/prometheus/alert-rules.yml"

// ---------------------------------------------------------------------------
// Rules file model (real file, parsed, never re-declared)
// ---------------------------------------------------------------------------

type alertRule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type ruleGroup struct {
	Name  string      `yaml:"name"`
	Rules []alertRule `yaml:"rules"`
}

type rulesFile struct {
	Groups []ruleGroup `yaml:"groups"`
}

func loadRules(t *testing.T) rulesFile {
	t.Helper()
	raw, err := os.ReadFile(rulesPath)
	if err != nil {
		t.Fatalf("read real rules file: %v", err)
	}
	var rf rulesFile
	if err := yaml.Unmarshal(raw, &rf); err != nil {
		t.Fatalf("parse real rules file: %v", err)
	}
	return rf
}

func (rf rulesFile) byAlert(alert string) (alertRule, bool) {
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			if r.Alert == alert {
				return r, true
			}
		}
	}
	return alertRule{}, false
}

// parsePromDuration accepts what the rules file uses, including "7d" which
// time.ParseDuration rejects.
func parsePromDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("bad day duration %q", s)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// expectedSeverity is the hand-written double-entry spec for the rules file,
// independent of the yaml parse: if the file's severity for an alert drifts
// from this table the battery goes red (and vice versa). Cross-checked against
// the T02 delivery record totals (21 warning + 7 critical + 1 info = 29).
var expectedSeverity = map[string]string{
	"HighGatewayLatencyP99":           "warning",
	"HighGatewayErrorRate":            "critical",
	"UpstreamDown":                    "critical",
	"CircuitBreakerOpen":              "warning",
	"HighFallbackRate":                "warning",
	"LowClassifierAccuracy":           "warning",
	"DiskSpaceLow":                    "warning",
	"HighDeductionFailureRate":        "warning",
	"HighGatewayErrorRateV2":          "warning",
	"ServiceDown":                     "critical",
	"ShadowHighErrorRate":             "warning",
	"ShadowBudgetBurn":                "info",
	"CreditAuditDropped":              "critical",
	"CacheWriteDrops":                 "warning",
	"SilentFailureObserved":           "warning",
	"LeaderFnFailed":                  "warning",
	"RegionCacheInvalidateFailed":     "warning",
	"OTelLogsDropped":                 "warning",
	"LoggerdConsumerStalled":          "warning",
	"BudgetSettlementLagHigh":         "warning",
	"BudgetSettlementLagHighCritical": "critical",
	"BudgetScopeReserveDivergence":    "critical",
	"BudgetWalletInvariantBreach":     "critical",
	"BudgetWalletHeadroomNegative":    "warning",
	"BudgetStrandedCapacityHigh":      "warning",
	"BudgetExpiredReleaseSpike":       "warning",
	"BoundViolationRateHigh":          "warning",
	"AdmissionOverheadP95High":        "warning",
	"ReservationGrantErrors":          "warning",
}

// expectedFor is the double-entry spec for every rule's pending duration.
// The for: value decides how long a bad state persists before paging; a
// regression here (e.g. a copy-paste collapsing 30m to 30s) changes the
// on-call contract without touching any threshold, so it gets the same
// table-and-file lockstep treatment as severity.
var expectedFor = map[string]string{
	"HighGatewayLatencyP99":           "2m",
	"HighGatewayErrorRate":            "2m",
	"UpstreamDown":                    "1m",
	"CircuitBreakerOpen":              "30s",
	"HighFallbackRate":                "2m",
	"LowClassifierAccuracy":           "5m",
	"DiskSpaceLow":                    "5m",
	"HighDeductionFailureRate":        "2m",
	"HighGatewayErrorRateV2":          "2m",
	"ServiceDown":                     "1m",
	"ShadowHighErrorRate":             "10m",
	"ShadowBudgetBurn":                "5m",
	"CreditAuditDropped":              "1m",
	"CacheWriteDrops":                 "5m",
	"SilentFailureObserved":           "5m",
	"LeaderFnFailed":                  "5m",
	"RegionCacheInvalidateFailed":     "5m",
	"OTelLogsDropped":                 "2m",
	"LoggerdConsumerStalled":          "5m",
	"BudgetSettlementLagHigh":         "5m",
	"BudgetSettlementLagHighCritical": "30m",
	"BudgetScopeReserveDivergence":    "10m",
	"BudgetWalletInvariantBreach":     "15m",
	"BudgetWalletHeadroomNegative":    "5m",
	"BudgetStrandedCapacityHigh":      "30m",
	"BudgetExpiredReleaseSpike":       "5m",
	"BoundViolationRateHigh":          "1h",
	"AdmissionOverheadP95High":        "30m",
	"ReservationGrantErrors":          "10m",
}

// syntheticCoveredAlerts lists the alerts whose series cannot come from the
// real registry in this test binary (exporter-fed, or produced by an
// unexported collector in a package not linked here — see the file header).
// They fire through the same rule-evaluation path in
// TestN13P04T05_SyntheticInjectedAlertsStillFire; the main battery must cover
// every other alert, and the two sets must partition the rules file exactly.
var syntheticCoveredAlerts = []string{"DiskSpaceLow", "ServiceDown", "CreditAuditDropped"}

// ---------------------------------------------------------------------------
// PromQL-subset evaluator over the harness timeline
// ---------------------------------------------------------------------------

type sample struct {
	t float64 // seconds on the synthetic clock
	v float64
}

// timeline is the harness's per-series sample log.
type timeline map[string][]sample

func seriesKey(name string, labels map[string]string) string {
	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"\x01"+v)
	}
	sort.Strings(parts)
	return name + "\x00" + strings.Join(parts, "\x02")
}

// vectorElement is one series of a result vector; labels exclude the metric
// name (Prom drops __name__ in aggregation/binary contexts).
type vectorElement struct {
	labels map[string]string
	value  float64
}

type evaluator struct {
	tl timeline
	t  float64 // evaluation instant
}

// AST

type expr interface {
	eval(*evaluator) []vectorElement
}

type numberExpr float64

func (n numberExpr) eval(*evaluator) []vectorElement {
	return []vectorElement{{value: float64(n)}}
}

type selectorExpr struct {
	name    string
	matches []matchExpr
	window  float64 // >0 → range vector
}

type matchExpr struct {
	label string
	op    string // =, !=, =~, !~
	value string
}

func (s selectorExpr) eval(e *evaluator) []vectorElement {
	var out []vectorElement
	for key, samples := range e.tl {
		name, labels := decodeKey(key)
		if name != s.name {
			continue
		}
		if !matchAll(labels, s.matches) {
			continue
		}
		v, ok := e.valueFor(samples, s.window)
		if !ok {
			continue
		}
		if math.IsNaN(v) {
			continue // instant gap: no series at this instant
		}
		out = append(out, vectorElement{labels: dropName(labels), value: v})
	}
	return out
}

func matchAll(labels map[string]string, ms []matchExpr) bool {
	for _, m := range ms {
		v, ok := labels[m.label]
		if !ok {
			v = ""
		}
		switch m.op {
		case "=":
			if v != m.value {
				return false
			}
		case "!=":
			if v == m.value {
				return false
			}
		case "=~":
			if !matchRegex(m.value, v) {
				return false
			}
		case "!~":
			if matchRegex(m.value, v) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// matchRegex reports whether v fully matches the anchored Prom matcher
// pattern. The rules file's regex matchers use only literals, '.', and
// top-level alternation ("5..", "local|grant"); the engine implements
// exactly that subset — anything else fails the expr-parse check loudly
// rather than silently mis-evaluating.
func matchRegex(pattern, v string) bool {
	for _, alt := range splitTopLevelAlts(pattern) {
		if matchAlt(alt, v) {
			return true
		}
	}
	return false
}

func splitTopLevelAlts(pattern string) []string {
	var alts []string
	start := 0
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == '\\' {
			i++
			continue
		}
		if pattern[i] == '|' {
			alts = append(alts, pattern[start:i])
			start = i + 1
		}
	}
	return append(alts, pattern[start:])
}

// matchAlt matches one fixed-length alternative: literals and '.' (any byte),
// with backslash escapes for literal metacharacters.
func matchAlt(alt, v string) bool {
	i, j := 0, 0
	for i < len(alt) {
		c := alt[i]
		if c == '\\' && i+1 < len(alt) {
			i++
			c = alt[i]
		}
		if j >= len(v) {
			return false
		}
		if c != '.' && c != v[j] {
			return false
		}
		i++
		j++
	}
	return j == len(v)
}

func (e *evaluator) valueFor(samples []sample, window float64) (float64, bool) {
	if len(samples) == 0 {
		return 0, false
	}
	if window <= 0 { // instant vector: last sample at or before e.t
		var last sample
		found := false
		for _, s := range samples {
			if s.t <= e.t {
				last = s
				found = true
			}
		}
		if !found {
			return 0, false
		}
		return last.v, true
	}
	lo, hi := e.t-window, e.t
	var first, last sample
	haveFirst, haveLast := false, false
	for _, s := range samples {
		if s.t > lo && s.t <= hi {
			if !haveFirst {
				first = s
				haveFirst = true
			}
			last = s
			haveLast = true
		}
	}
	if !haveFirst || !haveLast || last.t == first.t {
		return 0, false // fewer than two points: Prometheus returns no series
	}
	avgRate := (last.v - first.v) / (last.t - first.t)
	return avgRate * window, true // increase semantics; rate callers divide by window
}

func rateValue(e *evaluator, s selectorExpr) []vectorElement {
	out := []vectorElement{}
	for key, samples := range e.tl {
		name, labels := decodeKey(key)
		if name != s.name || !matchAll(labels, s.matches) {
			continue
		}
		lo, hi := e.t-s.window, e.t
		var first, last sample
		have := false
		for _, sm := range samples {
			if sm.t > lo && sm.t <= hi {
				if !have {
					first = sm
					have = true
				}
				last = sm
			}
		}
		if !have || last.t == first.t {
			continue
		}
		out = append(out, vectorElement{labels: dropName(labels), value: (last.v - first.v) / (last.t - first.t)})
	}
	return out
}

type rateExpr struct{ sel selectorExpr }

func (r rateExpr) eval(e *evaluator) []vectorElement { return rateValue(e, r.sel) }

type increaseExpr struct{ sel selectorExpr }

func (i increaseExpr) eval(e *evaluator) []vectorElement {
	out := []vectorElement{}
	for _, el := range rateValue(e, i.sel) {
		out = append(out, vectorElement{labels: el.labels, value: el.value * i.sel.window})
	}
	return out
}

type maxOverTimeExpr struct{ sel selectorExpr }

// eval takes the max over the recorded samples of each matching series inside
// the selector's range window. Prometheus returns no series for an empty
// window; the harness mirrors that (unlike instant gauge selectors, which
// return the last sample regardless of age).
func (m maxOverTimeExpr) eval(e *evaluator) []vectorElement {
	out := []vectorElement{}
	for key, samples := range e.tl {
		name, labels := decodeKey(key)
		if name != m.sel.name || !matchAll(labels, m.sel.matches) {
			continue
		}
		lo, hi := e.t-m.sel.window, e.t
		best := math.NaN()
		have := false
		for _, sm := range samples {
			if sm.t > lo && sm.t <= hi && (!have || sm.v > best) {
				best = sm.v
				have = true
			}
		}
		if !have {
			continue
		}
		out = append(out, vectorElement{labels: dropName(labels), value: best})
	}
	return out
}

type aggExpr struct {
	op string   // "sum" or "max"
	by []string // empty for plain aggregation (drops all labels)
	in expr
}

func (a aggExpr) eval(e *evaluator) []vectorElement {
	groups := map[string]*vectorElement{}
	for _, el := range a.in.eval(e) {
		key := groupKey(el.labels, a.by)
		g, ok := groups[key]
		if !ok {
			kept := map[string]string{}
			for _, l := range a.by {
				kept[l] = el.labels[l]
			}
			groups[key] = &vectorElement{labels: kept, value: el.value}
			continue
		}
		switch a.op {
		case "sum":
			g.value += el.value
		case "max":
			if el.value > g.value {
				g.value = el.value
			}
		}
	}
	out := make([]vectorElement, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	return out
}

type histQuantileExpr struct {
	q  numberExpr
	in expr
}

func (h histQuantileExpr) eval(e *evaluator) []vectorElement {
	// group bucket series by all labels except le
	type bucket struct {
		le    float64
		value float64
	}
	groups := map[string][]bucket{}
	groupLabels := map[string]map[string]string{}
	for _, el := range h.in.eval(e) {
		leStr, ok := el.labels["le"]
		if !ok {
			continue
		}
		le, err := parseLE(leStr)
		if err != nil {
			continue
		}
		rest := map[string]string{}
		keyParts := make([]string, 0, len(el.labels))
		for k, v := range el.labels {
			if k == "le" {
				continue
			}
			rest[k] = v
			keyParts = append(keyParts, k+"\x01"+v)
		}
		sort.Strings(keyParts)
		key := strings.Join(keyParts, "\x02")
		groups[key] = append(groups[key], bucket{le: le, value: el.value})
		groupLabels[key] = rest
	}
	out := []vectorElement{}
	for key, buckets := range groups {
		sort.Slice(buckets, func(i, j int) bool { return buckets[i].le < buckets[j].le })
		var total float64
		hasInf := false
		for _, b := range buckets {
			if math.IsInf(b.le, 1) {
				total = b.value
				hasInf = true
			}
		}
		if !hasInf || total <= 0 {
			out = append(out, vectorElement{labels: groupLabels[key], value: math.NaN()})
			continue
		}
		rank := float64(h.q) * total
		value := math.NaN()
		for i, b := range buckets {
			if math.IsInf(b.le, 1) {
				break
			}
			if b.value >= rank {
				var lowerLe, lowerVal float64
				if i == 0 {
					lowerLe, lowerVal = 0, 0
				} else {
					lowerLe, lowerVal = buckets[i-1].le, buckets[i-1].value
				}
				if b.value == lowerVal {
					value = lowerLe
				} else {
					value = b.le - (b.le-lowerLe)*(b.value-rank)/(b.value-lowerVal)
				}
				break
			}
		}
		out = append(out, vectorElement{labels: groupLabels[key], value: value})
	}
	return out
}

func parseLE(s string) (float64, error) {
	if s == "+Inf" {
		return math.Inf(1), nil
	}
	return strconv.ParseFloat(s, 64)
}

type clampMinExpr struct {
	in  expr
	min numberExpr
}

func (c clampMinExpr) eval(e *evaluator) []vectorElement {
	out := []vectorElement{}
	for _, el := range c.in.eval(e) {
		v := el.value
		if !math.IsNaN(v) && v < float64(c.min) {
			v = float64(c.min)
		}
		out = append(out, vectorElement{labels: el.labels, value: v})
	}
	return out
}

type binaryExpr struct {
	op   string // "/" "+" "-" "*"
	l, r expr
}

func (b binaryExpr) eval(e *evaluator) []vectorElement {
	lhs, rhs := b.l.eval(e), b.r.eval(e)
	out := []vectorElement{}
	// Prom vector-vector matching: join on identical label sets (metric name
	// already excluded). Scalar/vector cases fall out because scalar elements
	// carry empty labels.
	for _, l := range lhs {
		for _, r := range rhs {
			if !sameLabels(l.labels, r.labels) {
				continue
			}
			var v float64
			switch b.op {
			case "/":
				v = l.value / r.value
			case "+":
				v = l.value + r.value
			case "-":
				v = l.value - r.value
			case "*":
				v = l.value * r.value
			}
			// keep the left side's labels (Prom: metric name dropped)
			out = append(out, vectorElement{labels: l.labels, value: v})
		}
	}
	return out
}

type compareExpr struct {
	op  string // ">" "<" ">=" "<=" "==" "!="
	l   expr
	rhs float64
}

func (c compareExpr) eval(e *evaluator) []vectorElement {
	out := []vectorElement{}
	for _, el := range c.l.eval(e) {
		v := el.value
		if math.IsNaN(v) || math.IsNaN(c.rhs) {
			continue // NaN comparisons are false in PromQL
		}
		keep := false
		switch c.op {
		case ">":
			keep = v > c.rhs
		case "<":
			keep = v < c.rhs
		case ">=":
			keep = v >= c.rhs
		case "<=":
			keep = v <= c.rhs
		case "==":
			keep = v == c.rhs
		case "!=":
			keep = v != c.rhs
		}
		if keep {
			out = append(out, el)
		}
	}
	return out
}

type andExpr struct {
	l, r expr
	// on is the vector-match label subset after `and`: nil = clause absent
	// (join on the full label set), non-nil (including empty, i.e. `on()`)
	// = join only on the listed labels — `on()` joins every left element
	// with any right element, the many-to-many set-op semantics the spliced
	// LoggerdConsumerStalled expr (sum over consumed vs gauge max) relies on.
	on []string
}

func (a andExpr) eval(e *evaluator) []vectorElement {
	rhs := a.r.eval(e)
	out := []vectorElement{}
	for _, l := range a.l.eval(e) {
		for _, r := range rhs {
			if matchOn(l.labels, r.labels, a.on) && !math.IsNaN(r.value) && r.value > 0 {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// matchOn is the `and` join rule: an absent on() clause requires identical
// full label sets; on(ls) compares only the listed labels (empty ls → every
// pair joins).
func matchOn(l, r map[string]string, on []string) bool {
	if on == nil {
		return sameLabels(l, r)
	}
	for _, k := range on {
		if l[k] != r[k] {
			return false
		}
	}
	return true
}

// --- parser (recursive descent over the subset) ---

func parseExpr(s string) (expr, error) {
	p := &parser{src: s}
	p.skip()
	e, err := p.parseAndChain()
	if err != nil {
		return nil, err
	}
	p.skip()
	if p.pos < len(p.src) {
		return nil, fmt.Errorf("trailing input at %d: %q", p.pos, p.src[p.pos:])
	}
	return e, nil
}

type parser struct {
	src string
	pos int
}

func (p *parser) skip() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			p.pos++
			continue
		}
		break
	}
}

func (p *parser) peekWord(w string) bool {
	p.skip()
	if p.pos+len(w) > len(p.src) {
		return false
	}
	candidate := p.src[p.pos : p.pos+len(w)]
	if candidate != w {
		return false
	}
	// keyword boundary: next char must not be a name character
	if end := p.pos + len(w); end < len(p.src) {
		c := p.src[end]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
			return false
		}
	}
	return true
}

func (p *parser) takeWord(w string) bool {
	if p.peekWord(w) {
		p.pos += len(w)
		return true
	}
	return false
}

// parseAndChain parses `and`-joined comparisons (the only set operator the
// rules use; precedence: `and` binds loosest).
func (p *parser) parseAndChain() (expr, error) {
	l, err := p.parseCompare()
	if err != nil {
		return nil, err
	}
	for p.takeWord("and") {
		on, err := p.parseOnMatcher()
		if err != nil {
			return nil, err
		}
		r, err := p.parseCompare()
		if err != nil {
			return nil, err
		}
		l = andExpr{l: l, r: r, on: on}
	}
	return l, nil
}

// parseOnMatcher parses the optional `on (l1, l2)` vector-match clause that
// may follow a set operator. nil = clause absent (default full-label join).
func (p *parser) parseOnMatcher() ([]string, error) {
	if !p.takeWord("on") {
		return nil, nil
	}
	p.skip()
	if p.pos >= len(p.src) || p.src[p.pos] != '(' {
		return nil, fmt.Errorf("on: missing (")
	}
	p.pos++
	labels := []string{}
	for {
		p.skip()
		if p.pos < len(p.src) && p.src[p.pos] == ')' {
			p.pos++
			return labels, nil
		}
		lbl, ln := scanName(p.src[p.pos:])
		if ln == 0 {
			return nil, fmt.Errorf("on: bad label at %d", p.pos)
		}
		p.pos += ln
		labels = append(labels, lbl)
		p.skip()
		if p.pos < len(p.src) && p.src[p.pos] == ',' {
			p.pos++
			continue
		}
		if p.pos < len(p.src) && p.src[p.pos] == ')' {
			p.pos++
			return labels, nil
		}
		return nil, fmt.Errorf("on: missing ) at %d", p.pos)
	}
}

// parseCompare parses an arithmetic expression optionally compared against a
// scalar literal (the only comparison form the rules use).
func (p *parser) parseCompare() (expr, error) {
	l, err := p.parseArith()
	if err != nil {
		return nil, err
	}
	for {
		p.skip()
		op := ""
		for _, cand := range []string{">=", "<=", "==", "!=", ">", "<"} {
			if p.peekOp(cand) {
				op = cand
				break
			}
		}
		if op == "" {
			return l, nil
		}
		p.pos += len(op)
		r, err := p.parseArith()
		if err != nil {
			return nil, err
		}
		rn, ok := r.(numberExpr)
		if !ok {
			return nil, fmt.Errorf("comparison against non-scalar not supported")
		}
		l = compareExpr{op: op, l: l, rhs: float64(rn)}
	}
}

func (p *parser) peekOp(op string) bool {
	p.skip()
	return strings.HasPrefix(p.src[p.pos:], op)
}

func (p *parser) parseArith() (expr, error) {
	l, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}
	for {
		p.skip()
		op := ""
		switch {
		case strings.HasPrefix(p.src[p.pos:], "/"):
			op = "/"
		case strings.HasPrefix(p.src[p.pos:], "*"):
			op = "*"
		case strings.HasPrefix(p.src[p.pos:], "+"):
			op = "+"
		case strings.HasPrefix(p.src[p.pos:], "-"):
			op = "-"
		}
		if op == "" {
			return l, nil
		}
		p.pos++
		r, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		l = binaryExpr{op: op, l: l, r: r}
	}
}

func (p *parser) parsePrimary() (expr, error) {
	p.skip()
	if p.pos >= len(p.src) {
		return nil, fmt.Errorf("unexpected end of expr")
	}
	if p.src[p.pos] == '(' {
		p.pos++
		e, err := p.parseAndChain()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.pos >= len(p.src) || p.src[p.pos] != ')' {
			return nil, fmt.Errorf("missing ) at %d", p.pos)
		}
		p.pos++
		return e, nil
	}
	// number literal
	if num, n := scanNumber(p.src[p.pos:]); n > 0 {
		p.pos += n
		return numberExpr(num), nil
	}
	// function / aggregation call or selector
	word, n := scanName(p.src[p.pos:])
	if n == 0 {
		return nil, fmt.Errorf("bad token at %d: %q", p.pos, p.src[p.pos:])
	}
	switch word {
	case "rate", "increase", "histogram_quantile", "clamp_min", "sum", "max", "max_over_time":
		p.pos += n
		// each branch below opens its own '(' — sum/max must first accept
		// the optional `by (l1, l2)` group between the name and the paren
		switch word {
		case "rate", "increase", "max_over_time":
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != '(' {
				return nil, fmt.Errorf("%s: missing (", word)
			}
			p.pos++
			sel, err := p.parseSelector(true)
			if err != nil {
				return nil, err
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ')' {
				return nil, fmt.Errorf("%s: missing )", word)
			}
			p.pos++
			switch word {
			case "rate":
				return rateExpr{sel: sel}, nil
			case "increase":
				return increaseExpr{sel: sel}, nil
			default:
				return maxOverTimeExpr{sel: sel}, nil
			}
		case "histogram_quantile":
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != '(' {
				return nil, fmt.Errorf("%s: missing (", word)
			}
			p.pos++
			qe, err := p.parseAndChain()
			if err != nil {
				return nil, err
			}
			qn, ok := qe.(numberExpr)
			if !ok {
				return nil, fmt.Errorf("histogram_quantile: first arg must be a number")
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ',' {
				return nil, fmt.Errorf("histogram_quantile: missing ,")
			}
			p.pos++
			inner, err := p.parseAndChain()
			if err != nil {
				return nil, err
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ')' {
				return nil, fmt.Errorf("histogram_quantile: missing )")
			}
			p.pos++
			return histQuantileExpr{q: qn, in: inner}, nil
		case "clamp_min":
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != '(' {
				return nil, fmt.Errorf("%s: missing (", word)
			}
			p.pos++
			inner, err := p.parseAndChain()
			if err != nil {
				return nil, err
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ',' {
				return nil, fmt.Errorf("clamp_min: missing ,")
			}
			p.pos++
			mine, err := p.parseAndChain()
			if err != nil {
				return nil, err
			}
			mn, ok := mine.(numberExpr)
			if !ok {
				return nil, fmt.Errorf("clamp_min: second arg must be a number")
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ')' {
				return nil, fmt.Errorf("clamp_min: missing )")
			}
			p.pos++
			return clampMinExpr{in: inner, min: mn}, nil
		default: // sum / max, optionally `by (l1, l2)`
			by := []string{}
			p.skip()
			if p.takeWord("by") {
				p.skip()
				if p.pos >= len(p.src) || p.src[p.pos] != '(' {
					return nil, fmt.Errorf("%s by: missing (", word)
				}
				p.pos++
				for {
					lbl, ln := scanName(p.src[p.pos:])
					if ln == 0 {
						return nil, fmt.Errorf("%s by: bad label", word)
					}
					p.pos += ln
					by = append(by, lbl)
					p.skip()
					if p.pos < len(p.src) && p.src[p.pos] == ',' {
						p.pos++
						continue
					}
					break
				}
				if p.pos >= len(p.src) || p.src[p.pos] != ')' {
					return nil, fmt.Errorf("%s by: missing )", word)
				}
				p.pos++
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != '(' {
				return nil, fmt.Errorf("%s: missing (", word)
			}
			p.pos++
			inner, err := p.parseAndChain()
			if err != nil {
				return nil, err
			}
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != ')' {
				return nil, fmt.Errorf("%s: missing )", word)
			}
			p.pos++
			return aggExpr{op: word, by: by, in: inner}, nil
		}
	}
	sel, err := p.parseSelector(false)
	if err != nil {
		return nil, err
	}
	sel.name = word
	return sel, nil
}

func (p *parser) parseSelector(needRange bool) (selectorExpr, error) {
	sel := selectorExpr{}
	// optional leading metric name: rate(<name>{matchers}[range]) puts the
	// name inside the call; the bare-selector path has already consumed it,
	// so this scan sees `{`/`[`/an operator and matches nothing there.
	p.skip()
	if name, n := scanName(p.src[p.pos:]); n > 0 {
		sel.name = name
		p.pos += n
	}
	// matchers
	p.skip()
	if p.pos < len(p.src) && p.src[p.pos] == '{' {
		p.pos++
		for {
			p.skip()
			lbl, ln := scanName(p.src[p.pos:])
			if ln == 0 {
				return sel, fmt.Errorf("selector: bad label at %d", p.pos)
			}
			p.pos += ln
			p.skip()
			op := ""
			for _, cand := range []string{"=~", "!~", "!=", "="} {
				if strings.HasPrefix(p.src[p.pos:], cand) {
					op = cand
					break
				}
			}
			if op == "" {
				return sel, fmt.Errorf("selector: bad matcher op at %d", p.pos)
			}
			p.pos += len(op)
			p.skip()
			if p.pos >= len(p.src) || p.src[p.pos] != '"' {
				return sel, fmt.Errorf("selector: expected quoted value at %d", p.pos)
			}
			p.pos++
			start := p.pos
			for p.pos < len(p.src) && p.src[p.pos] != '"' {
				if p.src[p.pos] == '\\' {
					p.pos++
				}
				p.pos++
			}
			if p.pos >= len(p.src) {
				return sel, fmt.Errorf("selector: unterminated string")
			}
			val := p.src[start:p.pos]
			p.pos++
			val = strings.ReplaceAll(val, `\"`, `"`)
			val = strings.ReplaceAll(val, `\\`, `\`)
			sel.matches = append(sel.matches, matchExpr{label: lbl, op: op, value: val})
			p.skip()
			if p.pos < len(p.src) && p.src[p.pos] == ',' {
				p.pos++
				continue
			}
			break
		}
		if p.pos >= len(p.src) || p.src[p.pos] != '}' {
			return sel, fmt.Errorf("selector: missing }")
		}
		p.pos++
	}
	// range
	p.skip()
	if p.pos < len(p.src) && p.src[p.pos] == '[' {
		p.pos++
		start := p.pos
		for p.pos < len(p.src) && p.src[p.pos] != ']' {
			p.pos++
		}
		if p.pos >= len(p.src) {
			return sel, fmt.Errorf("selector: unterminated range")
		}
		durStr := strings.TrimSpace(p.src[start:p.pos])
		p.pos++
		d, err := parsePromDuration(durStr)
		if err != nil {
			return sel, fmt.Errorf("selector: bad range %q: %v", durStr, err)
		}
		sel.window = d.Seconds()
	} else if needRange {
		return sel, fmt.Errorf("selector: expected [range]")
	}
	return sel, nil
}

func scanNumber(s string) (float64, int) {
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.' || s[i] == 'e' || s[i] == 'E' ||
		(i > 0 && (s[i] == '+' || s[i] == '-') && (s[i-1] == 'e' || s[i-1] == 'E'))) {
		i++
	}
	if i == 0 {
		return 0, 0
	}
	v, err := strconv.ParseFloat(s[:i], 64)
	if err != nil {
		return 0, 0
	}
	return v, i
}

func scanName(s string) (string, int) {
	i := 0
	for i < len(s) && (s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z' || s[i] == '_' || s[i] == ':' ||
		(i > 0 && s[i] >= '0' && s[i] <= '9')) {
		i++
	}
	return s[:i], i
}

func decodeKey(key string) (string, map[string]string) {
	parts := strings.SplitN(key, "\x00", 2)
	labels := map[string]string{}
	if len(parts) == 2 && parts[1] != "" {
		for _, kv := range strings.Split(parts[1], "\x02") {
			pair := strings.SplitN(kv, "\x01", 2)
			if len(pair) == 2 {
				labels[pair[0]] = pair[1]
			}
		}
	}
	return parts[0], labels
}

func dropName(labels map[string]string) map[string]string {
	out := make(map[string]string, len(labels))
	for k, v := range labels {
		if k == "__name__" {
			continue
		}
		out[k] = v
	}
	return out
}

func sameLabels(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func groupKey(labels map[string]string, by []string) string {
	parts := make([]string, 0, len(by))
	for _, l := range by {
		parts = append(parts, l+"\x01"+labels[l])
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x02")
}

// ---------------------------------------------------------------------------
// Registry sampling harness
// ---------------------------------------------------------------------------

type harness struct {
	tl        timeline
	t         float64
	firstTrue map[string]float64         // alert → first tick where expr held true
	firedAt   map[string]float64         // alert → tick where the fire was reported
	firedVec  map[string][]vectorElement // alert → result vector at the fire tick
}

func newHarness() *harness {
	return &harness{
		tl:        timeline{},
		firstTrue: map[string]float64{},
		firedAt:   map[string]float64{},
		firedVec:  map[string][]vectorElement{},
	}
}

// tick samples the REAL default registry into the timeline at time t.
func (h *harness) tick(t float64) error {
	h.t = t
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	for _, mf := range mfs {
		base := mf.GetName()
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			switch {
			case m.GetCounter() != nil:
				h.record(base, labels, t, m.GetCounter().GetValue())
			case m.GetGauge() != nil:
				h.record(base, labels, t, m.GetGauge().GetValue())
			case m.GetHistogram() != nil:
				hist := m.GetHistogram()
				for _, b := range hist.GetBucket() {
					le := strconv.FormatFloat(b.GetUpperBound(), 'g', -1, 64)
					if math.IsInf(b.GetUpperBound(), 1) {
						le = "+Inf" // exposition-format spelling of the top bucket
					}
					ble := map[string]string{"le": le}
					for k, v := range labels {
						ble[k] = v
					}
					h.record(base+"_bucket", ble, t, float64(b.GetCumulativeCount()))
				}
				h.record(base+"_count", labels, t, float64(hist.GetSampleCount()))
				// the dto gather carries only the explicit buckets; the
				// exposition format derives le="+Inf" from the sample count,
				// and histogram_quantile needs it as the window total
				infLabels := map[string]string{"le": "+Inf"}
				for k, v := range labels {
					infLabels[k] = v
				}
				h.record(base+"_bucket", infLabels, t, float64(hist.GetSampleCount()))
			case m.GetSummary() != nil:
				// no summary collectors are referenced by the rules file
			}
		}
	}
	return nil
}

func (h *harness) record(name string, labels map[string]string, t float64, v float64) {
	key := seriesKey(name, labels)
	h.tl[key] = append(h.tl[key], sample{t: t, v: v})
}

// inject records a declared synthetic series (exporter-fed or producer-not-
// linked; see the file header).
func (h *harness) inject(name string, labels map[string]string, t float64, v float64) {
	h.record(name, labels, t, v)
}

func (h *harness) evalRule(r alertRule) (bool, []vectorElement, error) {
	ast, err := parseExpr(r.Expr)
	if err != nil {
		return false, nil, fmt.Errorf("parse %s: %w", r.Alert, err)
	}
	vec := ast.eval(&evaluator{tl: h.tl, t: h.t})
	return len(vec) > 0, vec, nil
}

// tickAndTrack evaluates every rule at time t and records fires honoring the
// rule's for: duration (first-true + sustained state), exactly like the
// Prometheus rules manager over these ticks.
func (h *harness) tickAndTrack(t float64, rf rulesFile) error {
	if err := h.tick(t); err != nil {
		return err
	}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			firing, vec, err := h.evalRule(r)
			if err != nil {
				return err
			}
			forD, err := parsePromDuration(r.For)
			if err != nil {
				return fmt.Errorf("%s: bad for %q: %w", r.Alert, r.For, err)
			}
			if firing {
				if _, seen := h.firstTrue[r.Alert]; !seen {
					h.firstTrue[r.Alert] = t
				}
				if t-h.firstTrue[r.Alert] >= forD.Seconds() {
					if _, already := h.firedAt[r.Alert]; !already {
						h.firedAt[r.Alert] = t
						h.firedVec[r.Alert] = vec
					}
				}
			} else {
				delete(h.firstTrue, r.Alert)
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Real drives
// ---------------------------------------------------------------------------

// driveGatewayTraffic sends real requests with real statuses through the real
// chi router with the real PrometheusMiddleware: the handler writes `status`
// through the wrapped writer (so 5xx series are produced by the entry path
// itself) and sleeps handlerDelay before responding (so duration observations
// land in the latency buckets).
func driveGatewayTraffic(t *testing.T, path string, status int, count int, handlerDelay time.Duration) {
	t.Helper()
	router := chi.NewRouter()
	router.Use(metrics.PrometheusMiddleware())
	router.Get(path, func(w http.ResponseWriter, _ *http.Request) {
		if handlerDelay > 0 {
			time.Sleep(handlerDelay)
		}
		w.WriteHeader(status)
	})
	server := httptest.NewServer(router)
	defer server.Close()
	client := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < count; i++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+path, nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		_ = resp.Body.Close()
	}
}

// scenario is one negative-scenario fire test for a single alert: the steps
// put the real registry into the bad state, and runScenario asserts the rule
// fires (at first-true + its own for:, with the wanted labels) — or never
// fires, for the quiet cases.
type scenario struct {
	alert    string
	steps    []scenarioStep
	wantFire bool
	// wantLabels are series labels expected on the fired vector (subset
	// check; beyond alertname/severity, which come from the rule).
	wantLabels map[string]string
}

type scenarioStep struct {
	dt    time.Duration
	drive func(t *testing.T)
}

// runScenarioCore walks the synthetic clock: baseline tick, then drive+tick
// per step. For wantFire scenarios it extends the clock past first-true +
// the rule's own for: (+1s tick quantum) so the state is observed for the
// rule's pending duration — the for: value itself comes from the file under
// test, so a for: regression moves the fire tick rather than being masked.
func runScenarioCore(t *testing.T, rf rulesFile, sc scenario) *harness {
	t.Helper()
	resetGauges()
	h := newHarness()
	// Prime: run every step drive once BEFORE the baseline tick and leave a
	// warmup sample at t=-1 inside every rate window. Counter/histogram vec
	// children materialize on first use, so without priming the baseline
	// gather would see no series at all and rate() would lack the second
	// point Prometheus normally has (production series are long-lived). The
	// prime increments land before the first in-window sample, so every
	// rate/increase delta stays exactly the scenario drive.
	for _, st := range sc.steps {
		if st.drive != nil {
			st.drive(t)
		}
	}
	if err := h.tick(-1); err != nil {
		t.Fatalf("%s: prime tick: %v", sc.alert, err)
	}
	clock := 0.0
	if err := h.tickAndTrack(clock, rf); err != nil {
		t.Fatalf("%s: initial tick: %v", sc.alert, err)
	}
	for i, st := range sc.steps {
		clock += st.dt.Seconds()
		if st.drive != nil {
			st.drive(t)
		}
		if err := h.tickAndTrack(clock, rf); err != nil {
			t.Fatalf("%s: tick %d: %v", sc.alert, i+1, err)
		}
	}
	if sc.wantFire {
		first, ok := h.firstTrue[sc.alert]
		if !ok {
			t.Fatalf("%s: expr never evaluated true on the driven state", sc.alert)
		}
		rule, found := rf.byAlert(sc.alert)
		if !found {
			t.Fatalf("%s: not in rules file", sc.alert)
		}
		forD, err := parsePromDuration(rule.For)
		if err != nil {
			t.Fatalf("%s: bad for %q: %v", sc.alert, rule.For, err)
		}
		// Sustain: re-drive the scenario steps on 1s ticks (capped at 6) so
		// rate/increase conditions stay populated the way production traffic
		// keeps them true while Prometheus waits out `for:` — without this
		// the samples would age out of the window before the pending
		// duration elapses. The final jump tick below stays exact for the
		// fire-timing assertion.
		sustain := int(math.Min(forD.Seconds(), 6))
		for k := 0; k < sustain; k++ {
			clock++
			for _, st := range sc.steps {
				if st.drive != nil {
					st.drive(t)
				}
			}
			if err := h.tickAndTrack(clock, rf); err != nil {
				t.Fatalf("%s: sustain tick %d: %v", sc.alert, k+1, err)
			}
		}
		target := first + forD.Seconds() + 1
		if target > clock {
			if err := h.tickAndTrack(target, rf); err != nil {
				t.Fatalf("%s: fire tick: %v", sc.alert, err)
			}
		}
	}
	return h
}

// runScenario asserts the fire contract: wantFire alerts fire exactly at
// first-true + for: (the first eligible tick, ±1 tick quantum) with the
// wanted labels; quiet alerts never fire.
func runScenario(t *testing.T, rf rulesFile, sc scenario) {
	t.Helper()
	h := runScenarioCore(t, rf, sc)
	firedAt, ok := h.firedAt[sc.alert]
	if !sc.wantFire {
		if ok {
			t.Fatalf("%s: expected NO fire, fired at %v", sc.alert, firedAt)
		}
		return
	}
	if !ok {
		t.Fatalf("%s: expected fire after sustained state, never fired (fires seen: %v)", sc.alert, h.firedAt)
	}
	rule, found := rf.byAlert(sc.alert)
	if !found {
		t.Fatalf("%s: not in rules file", sc.alert)
	}
	forD, err := parsePromDuration(rule.For)
	if err != nil {
		t.Fatalf("%s: bad for %q: %v", sc.alert, rule.For, err)
	}
	wantAt := h.firstTrue[sc.alert] + forD.Seconds()
	if math.Abs(firedAt-wantAt) > 2 {
		t.Fatalf("%s: fired at %.0fs, expected the first tick at first-true(%.0fs)+for(%s) ≈ %.0fs",
			sc.alert, firedAt, h.firstTrue[sc.alert], rule.For, wantAt)
	}
	for k, v := range sc.wantLabels {
		hit := false
		for _, el := range h.firedVec[sc.alert] {
			if el.labels[k] == v {
				hit = true
				break
			}
		}
		if !hit {
			t.Fatalf("%s: fired vector missing label %s=%q (got %v)",
				sc.alert, k, v, h.firedVec[sc.alert])
		}
	}
}

// runScenarioQuiet is runScenario without the fire assertions, returning the
// fire tick (0 if never), so mutation cells can assert non-firing without
// failing the test.
func runScenarioQuiet(t *testing.T, rf rulesFile, sc scenario) float64 {
	t.Helper()
	h := runScenarioCore(t, rf, sc)
	return h.firedAt[sc.alert]
}

// resetGauges clears the absolute-state gauges the scenarios drive, so the
// battery is order-independent under -shuffle (counters are rate-windowed and
// need no reset).
func resetGauges() {
	metrics.EventsInFlight.Set(0)
	metrics.UpstreamHealthState.Reset()
	metrics.CircuitState.Reset()
	metrics.SettlementLagSeconds.Set(0)
	metrics.BudgetReservedDivergenceMicroUSD.Reset()
	metrics.BudgetWalletInvariantViolations.Set(0)
	metrics.BudgetWalletHeadroomMicroUSD.Set(0)
	metrics.BudgetStrandedMicroUSD.Set(0)
}

// ---------------------------------------------------------------------------
// The battery
// ---------------------------------------------------------------------------

func TestN13P04T05_AlertFiringRegression_AllAlertsFireOnRealState(t *testing.T) {
	rf := loadRules(t)

	// structural pass: 29 alerts, severity + for: double-entry, runbook_url
	// on all, every expr parseable by the battery grammar.
	if err := structuralCheck(rf); err != nil {
		t.Fatalf("structural checks against the real rules file: %v", err)
	}
	if err := severityCheck(rf); err != nil {
		t.Fatalf("severity double-entry: %v", err)
	}
	forCheck(t, rf)

	// One scenario per real-state alert; the three declared-synthetic alerts
	// are covered by TestN13P04T05_SyntheticInjectedAlertsStillFire through
	// the same rule-evaluation path. The partition assertion below makes the
	// "every alert can fire" claim structural.
	scenarios := []scenario{
		{
			// 12 real requests through the real middleware, handler sleeping
			// 250ms → duration observations land in the ≥0.25s buckets.
			alert: "HighGatewayLatencyP99",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					driveGatewayTraffic(t, "/v1/chat", http.StatusOK, 12, 250*time.Millisecond)
				}},
			},
			wantFire: true,
		},
		{
			// real 500s through the wrapped writer: 10/20 → 0.5 > 0.05.
			alert: "HighGatewayErrorRate",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					driveGatewayTraffic(t, "/v1/chat", http.StatusInternalServerError, 10, 0)
					driveGatewayTraffic(t, "/v1/chat", http.StatusOK, 10, 0)
				}},
			},
			wantFire: true,
		},
		{
			alert: "UpstreamDown",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.UpstreamHealthState.WithLabelValues("https://canary-upstream.internal/v1").Set(3)
				}},
			},
			wantFire:   true,
			wantLabels: map[string]string{"host": "https://canary-upstream.internal/v1"},
		},
		{
			alert: "CircuitBreakerOpen",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.CircuitState.WithLabelValues("canary-model-a").Set(1)
				}},
			},
			wantFire:   true,
			wantLabels: map[string]string{"upstream": "canary-model-a"},
		},
		{
			// 10 real 200s through the middleware + 5 fallback increments →
			// 5/10 = 0.5 > 0.2.
			alert: "HighFallbackRate",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					driveGatewayTraffic(t, "/v1/chat", http.StatusOK, 10, 0)
					metrics.FallbackTotal.WithLabelValues("model-a", "model-b", "500").Add(5)
				}},
			},
			wantFire: true,
		},
		{
			alert: "LowClassifierAccuracy",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.ClassifierClassTotal.WithLabelValues("hard", "canary").Add(10)
					metrics.ClassifierClassTotal.WithLabelValues("easy", "canary").Add(2)
				}},
			},
			wantFire: true,
		},
		{
			// rate of skipped deductions with reason=insufficient > 0.5/s.
			alert: "HighDeductionFailureRate",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.CreditDeductionSkippedTotal.WithLabelValues("insufficient").Add(120)
				}},
			},
			wantFire: true,
		},
		{
			// 15 real 500s, no 200s → ratio 1.0 > 0.1.
			alert: "HighGatewayErrorRateV2",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					driveGatewayTraffic(t, "/v1/chat", http.StatusInternalServerError, 15, 0)
				}},
			},
			wantFire: true,
		},
		{
			// shadow error dominance: 10/12 = 0.833 > 0.5, and total rate > 0.
			alert: "ShadowHighErrorRate",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					shadow.RequestsTotal.WithLabelValues("error").Add(10)
					shadow.RequestsTotal.WithLabelValues("success").Add(2)
				}},
			},
			wantFire: true,
		},
		{
			alert: "ShadowBudgetBurn",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					shadow.BudgetExhaustedTotal.Add(2)
				}},
			},
			wantFire: true,
		},
		{
			alert: "CacheWriteDrops",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					cache.CacheWriteQueueDropsTotal.Add(1)
				}},
			},
			wantFire: true,
		},
		{
			// one increment through the CLOSED silent-failure registry (an
			// unregistered pair would panic, so this doubles as a registry
			// liveness check); the alert must fire with the exact place/reason.
			alert: "SilentFailureObserved",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.SilentFailure("apiformat_request_parse", "prompt_cache_key")
				}},
			},
			wantFire:   true,
			wantLabels: map[string]string{"place": "apiformat_request_parse", "reason": "prompt_cache_key"},
		},
		{
			alert: "LeaderFnFailed",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.LeaderFnFailedTotal.Add(1)
				}},
			},
			wantFire: true,
		},
		{
			alert: "RegionCacheInvalidateFailed",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set").Add(1)
				}},
			},
			wantFire:   true,
			wantLabels: map[string]string{"op": "set"},
		},
		{
			alert: "OTelLogsDropped",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					tracing.OTelLogsDroppedTotal.Add(1)
				}},
			},
			wantFire: true,
		},
		{
			// Spliced stall semantics (db99a79d in master @ 23223c57): the
			// occupancy form `in_flight > 0` was replaced by NO PROGRESS —
			// sum(rate(consumed_total[5m])) == 0 AND on()
			// max_over_time(in_flight[5m]) > 0. The drive pins both
			// conjuncts: the in-flight gauge holds at 2, and the consumed
			// counter stays flat (the exported EventsConsumedTotal zero
			// child is materialized so the rate window has the two points a
			// live series always has; its producer services/loggerd/consumer
			// is not linked into this binary — the same declared-stand-in
			// discipline as credit_audit_dropped_total, and a flat counter
			// IS the no-progress condition). Under the pre-splice file this
			// drive would have been gauge-only; that would leave the new
			// lhs without a series and the alert dark.
			alert: "LoggerdConsumerStalled",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.EventsConsumedTotal.WithLabelValues("canary") // flat (0) series
					metrics.EventsInFlight.Set(2)
				}},
			},
			wantFire: true,
		},
		{
			// settlement lag gauge above 1800s: warning tier at for: 5m.
			alert: "BudgetSettlementLagHigh",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.SettlementLagSeconds.Set(3600)
				}},
			},
			wantFire: true,
		},
		{
			// same expr, critical tier at for: 30m — the fire tick must honor
			// the critical pending duration, not the warning one.
			alert: "BudgetSettlementLagHighCritical",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.SettlementLagSeconds.Set(3600)
				}},
			},
			wantFire: true,
		},
		{
			alert: "BudgetScopeReserveDivergence",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues("wallet").Set(150)
				}},
			},
			wantFire:   true,
			wantLabels: map[string]string{"scope_kind": "wallet"},
		},
		{
			alert: "BudgetWalletInvariantBreach",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetWalletInvariantViolations.Set(2)
				}},
			},
			wantFire: true,
		},
		{
			alert: "BudgetWalletHeadroomNegative",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetWalletHeadroomMicroUSD.Set(-500)
				}},
			},
			wantFire: true,
		},
		{
			// stranded capacity gauge above the 10 000 000 µUSD threshold.
			alert: "BudgetStrandedCapacityHigh",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetStrandedMicroUSD.Set(2e7)
				}},
			},
			wantFire: true,
		},
		{
			// 11 expired_safety_window releases inside the 1h window > 10.
			alert: "BudgetExpiredReleaseSpike",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetAllowanceReleasedTotal.WithLabelValues("expired_safety_window").Add(11)
				}},
			},
			wantFire: true,
		},
		{
			// bound violations vs funded admissions: 2 violations / 100 admits
			// (clamp_min floor) = 0.02 > 0.001 over the 7d window.
			alert: "BoundViolationRateHigh",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetBoundViolationTotal.WithLabelValues("wallet").Add(2)
					metrics.BudgetLocalAdmitTotal.WithLabelValues("local").Add(100)
				}},
			},
			wantFire: true,
		},
		{
			// 10 admissions at 10ms → p95 ≈ 0.0075s > 0.005 (D17 gate).
			alert: "AdmissionOverheadP95High",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					for i := 0; i < 10; i++ {
						metrics.BudgetAdmissionOverheadSeconds.Observe(0.01)
					}
				}},
			},
			wantFire: true,
		},
		{
			alert: "ReservationGrantErrors",
			steps: []scenarioStep{
				{dt: 1 * time.Second, drive: func(t *testing.T) {
					t.Helper()
					metrics.BudgetGrantsTotal.WithLabelValues("wallet", "error").Add(1)
				}},
			},
			wantFire: true,
		},
	}

	// partition assertion: scenarios ∪ synthetic list == every alert in the
	// double-entry table, with no overlaps and no duplicates.
	covered := map[string]bool{}
	synthetic := map[string]bool{}
	for _, a := range syntheticCoveredAlerts {
		if synthetic[a] {
			t.Errorf("synthetic list duplicates %s", a)
		}
		synthetic[a] = true
	}
	for _, sc := range scenarios {
		if covered[sc.alert] {
			t.Errorf("duplicate firing scenario for %s", sc.alert)
		}
		covered[sc.alert] = true
	}
	for alert := range expectedSeverity {
		if covered[alert] && synthetic[alert] {
			t.Errorf("alert %s is covered by both a scenario and the synthetic list", alert)
		}
		if !covered[alert] && !synthetic[alert] {
			t.Errorf("alert %s has no firing scenario (main battery or synthetic)", alert)
		}
	}
	if len(expectedSeverity) != 29 {
		t.Errorf("double-entry tables have %d rows, expected 29", len(expectedSeverity))
	}

	for _, sc := range scenarios {
		t.Run(sc.alert, func(t *testing.T) {
			runScenario(t, rf, sc)
			resetGauges()
		})
	}
}

// synthetic drives: exporter-fed / producer-not-linked series (see header).

var nodeDiskLowDrive = driveSet{
	{name: "node_filesystem_avail_bytes", labels: map[string]string{"device": "canary", "mountpoint": "/canary"}, v: 5e9},
	{name: "node_filesystem_size_bytes", labels: map[string]string{"device": "canary", "mountpoint": "/canary"}, v: 1e11},
}

var upZeroDrive = driveSet{
	{name: "up", labels: map[string]string{"instance": "canary-instance:9090", "job": "canary"}, v: 0},
}

var creditAuditDropDrive = driveSet{
	{name: "credit_audit_dropped_total", labels: map[string]string{}, v: 1},
}

type driveEntry struct {
	name   string
	labels map[string]string
	v      float64
}

type driveSet []driveEntry

func TestN13P04T05_HealthyState_FiresNothing(t *testing.T) {
	rf := loadRules(t)
	resetGauges() // earlier tests may have left firing gauge states (shuffle)
	h := newHarness()
	// no drives at all: two quiet ticks with only healthy synthetic states
	h.inject("node_filesystem_avail_bytes", map[string]string{"device": "canary"}, 0, 5e10)
	h.inject("node_filesystem_size_bytes", map[string]string{"device": "canary"}, 0, 1e11)
	h.inject("up", map[string]string{"instance": "canary-instance:9090", "job": "canary"}, 0, 1)
	if err := h.tickAndTrack(0, rf); err != nil {
		t.Fatalf("tick 0: %v", err)
	}
	h.inject("node_filesystem_avail_bytes", map[string]string{"device": "canary"}, 3600, 5e10)
	h.inject("node_filesystem_size_bytes", map[string]string{"device": "canary"}, 3600, 1e11)
	h.inject("up", map[string]string{"instance": "canary-instance:9090", "job": "canary"}, 3600, 1)
	if err := h.tickAndTrack(3600, rf); err != nil {
		t.Fatalf("tick 1: %v", err)
	}
	if len(h.firedAt) != 0 {
		t.Errorf("healthy state fired %d alerts (expected 0): %v", len(h.firedAt), h.firedAt)
	}
}

func TestN13P04T05_SyntheticInjectedAlertsStillFire(t *testing.T) {
	// the three declared-synthetic alerts must fire through the same rule
	// evaluation path; injected values ride every tick (the driveSet marks
	// the active series; here we inject around ticks directly).
	rf := loadRules(t)
	for _, tc := range []struct {
		alert string
		set   driveSet
	}{
		{"DiskSpaceLow", nodeDiskLowDrive},
		{"ServiceDown", upZeroDrive},
		{"CreditAuditDropped", creditAuditDropDrive},
	} {
		t.Run(tc.alert, func(t *testing.T) {
			rule, ok := rf.byAlert(tc.alert)
			if !ok {
				t.Fatalf("%s not in rules file", tc.alert)
			}
			h := newHarness()
			for _, e := range tc.set {
				h.inject(e.name, e.labels, 0, 0)
			}
			if err := h.tickAndTrack(0, rf); err != nil {
				t.Fatalf("tick 0: %v", err)
			}
			for _, e := range tc.set {
				h.inject(e.name, e.labels, 1, e.v)
			}
			if err := h.tickAndTrack(1, rf); err != nil {
				t.Fatalf("tick 1: %v", err)
			}
			forD, err := parsePromDuration(rule.For)
			if err != nil {
				t.Fatalf("for: %v", err)
			}
			at := 1 + forD.Seconds()
			for _, e := range tc.set {
				h.inject(e.name, e.labels, at, e.v)
			}
			if err := h.tickAndTrack(at, rf); err != nil {
				t.Fatalf("tick fire: %v", err)
			}
			if _, fired := h.firedAt[tc.alert]; !fired {
				t.Fatalf("%s: synthetic-series fire expected, got none (fires: %v)", tc.alert, h.firedAt)
			}
		})
	}
}

func TestN13P04T05_ExprMetricsExistInRealRegistry(t *testing.T) {
	rf := loadRules(t)
	families, err := declFamilies()
	if err != nil {
		t.Fatalf("decl families: %v", err)
	}
	// Exporter-fed or producer-not-linked series (declared synthetic; see the
	// battery header for the per-series justification).
	synthetic := map[string]bool{
		"node_filesystem_avail_bytes": true,
		"node_filesystem_size_bytes":  true,
		"up":                          true,
		"credit_audit_dropped_total":  true,
	}
	seen := map[string]bool{}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			for name := range exprMetrics(r.Expr) {
				seen[name] = true
				if synthetic[name] {
					continue
				}
				if families[name] {
					continue
				}
				// histogram bucket/count/sum selectors map to the base family
				base := strings.TrimSuffix(name, "_bucket")
				base = strings.TrimSuffix(base, "_count")
				base = strings.TrimSuffix(base, "_sum")
				if families[base] {
					continue
				}
				t.Errorf("%s: expr references metric %q with no family in the real registry", r.Alert, name)
			}
		}
	}
	if len(seen) < 15 {
		t.Errorf("declaration scan saw only %d distinct metrics; expected the full rules surface", len(seen))
	}
}

// exprMetrics extracts the metric names an expr references, for the
// declaration check. It must skip the non-metric identifiers of the grammar:
// function keywords, the label lists after `by (...)`, and the matcher blocks
// `{...}` after a selector (label names like status/reason are not metrics).
func exprMetrics(expr string) map[string]bool {
	out := map[string]bool{}
	rest := expr
	for {
		i := strings.IndexFunc(rest, func(c rune) bool {
			return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
		})
		if i < 0 {
			break
		}
		if i > 0 {
			// letters inside number literals (1e9, 0.5e3) are not metrics
			if prev := rest[i-1]; prev >= '0' && prev <= '9' || prev == '.' {
				rest = rest[i+1:]
				continue
			}
		}
		rest = rest[i:]
		name, n := scanName(rest)
		if n == 0 {
			rest = rest[1:]
			continue
		}
		switch name {
		case "rate", "increase", "histogram_quantile", "clamp_min", "sum", "max", "and", "max_over_time":
			rest = rest[n:]
			continue
		case "on":
			// vector-match clause after a set operator: skip the label list
			// up to its closing paren (label names are not metrics)
			rest = rest[n:]
			if j := strings.IndexByte(rest, ')'); j >= 0 {
				rest = rest[j+1:]
			}
			continue
		case "by":
			// skip the aggregation label list up to its closing paren
			rest = rest[n:]
			if j := strings.IndexByte(rest, ')'); j >= 0 {
				rest = rest[j+1:]
			}
			continue
		}
		out[name] = true
		rest = rest[n:]
		// skip the selector's matcher block, if any (label names are not
		// metrics), then the range suffix ([5m] — "m" is not a metric)
		if strings.HasPrefix(rest, "{") {
			if j := strings.IndexByte(rest, '}'); j >= 0 {
				rest = rest[j+1:]
			}
		}
		if strings.HasPrefix(rest, "[") {
			if j := strings.IndexByte(rest, ']'); j >= 0 {
				rest = rest[j+1:]
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Mutation teeth: each cell mutates the rules/spec and asserts the battery's
// checks go RED, then proves the original is green.
// ---------------------------------------------------------------------------

func TestN13P04T05_MutationTeeth(t *testing.T) {
	rf := loadRules(t)

	t.Run("threshold flip is caught", func(t *testing.T) {
		mutated := rulesWithExpr(t, rf, "HighGatewayErrorRate", strings.Replace(
			rf.mustExpr(t, "HighGatewayErrorRate"), "> 0.05", "> 0.9", 1))
		// real drive state is a 0.5 ratio: original fires, mutated must not
		drive := func(t *testing.T) {
			t.Helper()
			t.Helper()
			driveGatewayTraffic(t, "/v1/chat", http.StatusInternalServerError, 10, 0)
			driveGatewayTraffic(t, "/v1/chat", http.StatusOK, 10, 0)
		}
		if fired := runScenarioQuiet(t, mutated, scenario{alert: "HighGatewayErrorRate", steps: []scenarioStep{
			{dt: 1 * time.Second, drive: drive},
		}}); fired != 0 {
			t.Fatalf("tooth broken: mutated threshold (>0.9) still fired at ratio 0.5")
		}
		runScenario(t, rf, scenario{alert: "HighGatewayErrorRate", wantFire: true, steps: []scenarioStep{
			{dt: 1 * time.Second, drive: drive},
		}})
		resetGauges()
	})

	t.Run("severity drift is caught", func(t *testing.T) {
		mutated := deepCopyRules(rf)
		for gi := range mutated.Groups {
			for ri := range mutated.Groups[gi].Rules {
				if mutated.Groups[gi].Rules[ri].Alert == "HighGatewayErrorRate" {
					mutated.Groups[gi].Rules[ri].Labels["severity"] = "warning"
				}
			}
		}
		if err := severityCheck(mutated); err == nil {
			t.Fatalf("tooth broken: severity mutation not caught by the double-entry check")
		}
		if err := severityCheck(rf); err != nil {
			t.Fatalf("original rules must pass severity check: %v", err)
		}
	})

	t.Run("for: drift is caught", func(t *testing.T) {
		mutated := deepCopyRules(rf)
		for gi := range mutated.Groups {
			for ri := range mutated.Groups[gi].Rules {
				if mutated.Groups[gi].Rules[ri].Alert == "CircuitBreakerOpen" {
					mutated.Groups[gi].Rules[ri].For = "5m" // file says 30s
				}
			}
		}
		if err := forCheckErr(mutated); err == nil {
			t.Fatalf("tooth broken: for: drift not caught by the double-entry check")
		}
		if err := forCheckErr(rf); err != nil {
			t.Fatalf("original rules must pass for: check: %v", err)
		}
	})

	t.Run("phantom metric is caught", func(t *testing.T) {
		mutated := rulesWithExpr(t, rf, "HighFallbackRate", strings.Replace(
			rf.mustExpr(t, "HighFallbackRate"), "gateway_fallback_total", "gateway_fallback_renamed_total", 1))
		if err := declarationCheck(mutated); err == nil {
			t.Fatalf("tooth broken: renamed metric not caught by the declaration check")
		}
		if err := declarationCheck(rf); err != nil {
			t.Fatalf("original rules must pass declaration check: %v", err)
		}
	})

	t.Run("missing for: is caught", func(t *testing.T) {
		mutated := deepCopyRules(rf)
		for gi := range mutated.Groups {
			for ri := range mutated.Groups[gi].Rules {
				if mutated.Groups[gi].Rules[ri].Alert == "CircuitBreakerOpen" {
					mutated.Groups[gi].Rules[ri].For = ""
				}
			}
		}
		if err := structuralCheck(mutated); err == nil {
			t.Fatalf("tooth broken: missing for: not caught")
		}
		if err := structuralCheck(rf); err != nil {
			t.Fatalf("original rules must pass structural check: %v", err)
		}
	})

	t.Run("occupancy-form revert is caught", func(t *testing.T) {
		// The splice (db99a79d) replaced the occupancy condition with the
		// no-progress AND in-flight form. A rules-file revert to the dropped
		// occupancy expr must turn the battery RED: on a consuming-but-busy
		// timeline (counter advancing, gauge above zero) the occupancy form
		// fires — the healthy-load false-page class AUDIT-P2-08 removed —
		// while the real file must stay pending-free and silent across a
		// clock spanning past its for:. Counter state is restored afterwards
		// so -shuffle keeps the battery order-independent.
		mutated := rulesWithExpr(t, rf, "LoggerdConsumerStalled", "gateway_loggerd_events_in_flight > 0")
		drive := func(t *testing.T) {
			t.Helper()
			metrics.EventsConsumedTotal.WithLabelValues("canary").Add(1)
			metrics.EventsInFlight.Set(2)
		}
		if fired := runScenarioQuiet(t, mutated, scenario{alert: "LoggerdConsumerStalled", wantFire: true, steps: []scenarioStep{
			{dt: 1 * time.Second, drive: drive},
		}}); fired == 0 {
			t.Fatalf("tooth broken: occupancy-form revert did not fire on consuming+in-flight state")
		}
		// The real expr must never hold on this timeline, so the fire-
		// extension scaffolding (which fatals when the expr never turns
		// true) does not apply; run the core quiet and inspect the tracked
		// state directly. A tick at t=0 sees rate 0 between the two equal
		// prime/baseline samples (harness quantization) — the state must
		// clear on the first consuming tick and never return.
		hReal := runScenarioCore(t, rf, scenario{alert: "LoggerdConsumerStalled", wantFire: false, steps: []scenarioStep{
			{dt: 150 * time.Second, drive: drive},
			{dt: 151 * time.Second, drive: drive},
			{dt: 5 * time.Second, drive: drive},
		}})
		if fired := hReal.firedAt["LoggerdConsumerStalled"]; fired != 0 {
			t.Fatalf("spliced no-progress expr fired on a consuming timeline at %vs — the false-page class the splice removed", fired)
		}
		if _, pending := hReal.firstTrue["LoggerdConsumerStalled"]; pending {
			t.Fatalf("spliced no-progress expr still pending on a consuming timeline")
		}
		metrics.EventsConsumedTotal.Reset()
		metrics.EventsConsumedTotal.WithLabelValues("canary") // flat 0 series again
		metrics.EventsInFlight.Set(0)
	})
}

func (rf rulesFile) mustExpr(t *testing.T, alert string) string {
	t.Helper()
	r, ok := rf.byAlert(alert)
	if !ok {
		t.Fatalf("alert %s not found", alert)
	}
	return r.Expr
}

func deepCopyRules(rf rulesFile) rulesFile {
	out := rf
	out.Groups = make([]ruleGroup, len(rf.Groups))
	for gi, g := range rf.Groups {
		ng := g
		ng.Rules = make([]alertRule, len(g.Rules))
		for ri, r := range g.Rules {
			nr := r
			nr.Labels = copyMap(r.Labels)
			nr.Annotations = copyMap(r.Annotations)
			ng.Rules[ri] = nr
		}
		out.Groups[gi] = ng
	}
	return out
}

func copyMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func rulesWithExpr(t *testing.T, rf rulesFile, alert, expr string) rulesFile {
	t.Helper()
	out := deepCopyRules(rf)
	for gi := range out.Groups {
		for ri := range out.Groups[gi].Rules {
			if out.Groups[gi].Rules[ri].Alert == alert {
				out.Groups[gi].Rules[ri].Expr = expr
				return out
			}
		}
	}
	t.Fatalf("alert %s not found", alert)
	return out
}

// severityCheck / structuralCheck / forCheck / declarationCheck are the same
// checks the main battery runs, factored so mutation cells can aim them at
// mutated files.

func severityCheck(rf rulesFile) error {
	counts := map[string]int{}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			counts[r.Labels["severity"]]++
			want, ok := expectedSeverity[r.Alert]
			if !ok {
				return fmt.Errorf("no expected severity row for %s", r.Alert)
			}
			if got := r.Labels["severity"]; got != want {
				return fmt.Errorf("%s: severity %q, expected %q", r.Alert, got, want)
			}
		}
	}
	if counts["warning"] != 21 || counts["critical"] != 7 || counts["info"] != 1 {
		return fmt.Errorf("severity totals %v, expected 21w/7c/1i", counts)
	}
	return nil
}

func structuralCheck(rf rulesFile) error {
	total := 0
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			total++
			if r.For == "" {
				return fmt.Errorf("%s: missing for:", r.Alert)
			}
			if _, err := parsePromDuration(r.For); err != nil {
				return fmt.Errorf("%s: for %q: %v", r.Alert, r.For, err)
			}
			if r.Annotations["runbook_url"] == "" {
				return fmt.Errorf("%s: missing runbook_url", r.Alert)
			}
			if _, err := parseExpr(r.Expr); err != nil {
				return fmt.Errorf("%s: expr: %v", r.Alert, err)
			}
		}
	}
	if total != 29 {
		return fmt.Errorf("total alerts %d, expected 29", total)
	}
	return nil
}

// forCheck is the for: double-entry check in test-fatal form.
func forCheck(t *testing.T, rf rulesFile) {
	t.Helper()
	if err := forCheckErr(rf); err != nil {
		t.Fatal(err)
	}
}

func forCheckErr(rf rulesFile) error {
	seen := map[string]bool{}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			want, ok := expectedFor[r.Alert]
			if !ok {
				return fmt.Errorf("no expected-for row for %s", r.Alert)
			}
			if r.For != want {
				return fmt.Errorf("%s: for %q, expected %q", r.Alert, r.For, want)
			}
			seen[r.Alert] = true
		}
	}
	for alert := range expectedFor {
		if !seen[alert] {
			return fmt.Errorf("expected-for row %s has no rule in the file", alert)
		}
	}
	return nil
}

// declFamilies maps the metric family names the rules may reference, built
// from a fresh registry that holds the real product collectors. A fresh
// process gathers NOTHING for Counter/Gauge/Histogram vecs that have no
// child series yet, so every vec gets one zero-value child before the
// gather. The added series carry no observations and never influence any
// rate, ratio or threshold the battery evaluates; the gauge children are
// removed again by resetGauges (Reset), counter children stay at zero.
var declFamilies = sync.OnceValues(func() (map[string]bool, error) {
	reg := prometheus.NewRegistry()
	for _, c := range []prometheus.Collector{
		metrics.RequestsTotal, metrics.RequestDurationSeconds,
		metrics.FallbackTotal, metrics.ClassifierClassTotal,
		metrics.CreditDeductionSkippedTotal, metrics.SilentFailuresTotal,
		metrics.RegionCacheInvalidateFailedTotal, metrics.LeaderFnFailedTotal,
		metrics.UpstreamHealthState, metrics.CircuitState,
		metrics.EventsInFlight, metrics.EventsConsumedTotal, metrics.SettlementLagSeconds,
		metrics.BudgetReservedDivergenceMicroUSD,
		metrics.BudgetWalletInvariantViolations, metrics.BudgetWalletHeadroomMicroUSD,
		metrics.BudgetStrandedMicroUSD, metrics.BudgetAllowanceReleasedTotal,
		metrics.BudgetGrantsTotal, metrics.BudgetLocalAdmitTotal,
		metrics.BudgetAdmissionOverheadSeconds, metrics.BudgetBoundViolationTotal,
		cache.CacheWriteQueueDropsTotal, shadow.RequestsTotal,
		shadow.BudgetExhaustedTotal, tracing.OTelLogsDroppedTotal,
	} {
		reg.MustRegister(c)
	}
	// zero-value children so vec families appear in the gather; the label
	// values are placeholders that match no battery drive series (the
	// SilentFailures pair must come from the closed registry)
	for _, touch := range []func(){
		func() { metrics.RequestsTotal.WithLabelValues("GET", "/decl", "200") },
		func() { metrics.RequestDurationSeconds.WithLabelValues("GET", "/decl") },
		func() { metrics.FallbackTotal.WithLabelValues("a", "b", "decl") },
		func() { metrics.ClassifierClassTotal.WithLabelValues("hard", "decl") },
		func() { metrics.CreditDeductionSkippedTotal.WithLabelValues("decl") },
		func() { metrics.SilentFailuresTotal.WithLabelValues("apiformat_request_parse", "prompt_cache_key") },
		func() { metrics.RegionCacheInvalidateFailedTotal.WithLabelValues("set") },
		func() { metrics.UpstreamHealthState.WithLabelValues("http://decl") },
		func() { metrics.CircuitState.WithLabelValues("http://decl") },
		func() { metrics.EventsConsumedTotal.WithLabelValues("decl") },
		func() { metrics.BudgetReservedDivergenceMicroUSD.WithLabelValues("decl") },
		func() { metrics.BudgetAllowanceReleasedTotal.WithLabelValues("decl") },
		func() { metrics.BudgetGrantsTotal.WithLabelValues("local", "ok") },
		func() { metrics.BudgetLocalAdmitTotal.WithLabelValues("ok") },
		func() { metrics.BudgetBoundViolationTotal.WithLabelValues("local") },
		func() { shadow.RequestsTotal.WithLabelValues("ok") },
	} {
		touch()
	}
	mfs, err := reg.Gather()
	if err != nil {
		return nil, fmt.Errorf("gather decl families: %w", err)
	}
	out := make(map[string]bool, len(mfs))
	for _, mf := range mfs {
		out[mf.GetName()] = true
	}
	return out, nil
})

func declarationCheck(rf rulesFile) error {
	families, err := declFamilies()
	if err != nil {
		return fmt.Errorf("decl families: %w", err)
	}
	synthetic := map[string]bool{
		"node_filesystem_avail_bytes": true,
		"node_filesystem_size_bytes":  true,
		"up":                          true,
		"credit_audit_dropped_total":  true,
	}
	for _, g := range rf.Groups {
		for _, r := range g.Rules {
			for name := range exprMetrics(r.Expr) {
				if synthetic[name] || families[name] {
					continue
				}
				base := strings.TrimSuffix(name, "_bucket")
				base = strings.TrimSuffix(base, "_count")
				base = strings.TrimSuffix(base, "_sum")
				if families[base] {
					continue
				}
				return fmt.Errorf("%s: metric %q not in the real registry", r.Alert, name)
			}
		}
	}
	return nil
}
