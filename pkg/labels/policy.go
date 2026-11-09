package labels

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Source is one label layer. Later sources override earlier ones unless Locked.
type Source struct {
	Name   string
	Labels Set
	Locked bool
}

// SecretFunc reports whether a value looks like a secret.
// A nil function skips the check.
type SecretFunc func(value string) bool

// DeriveRule fills a missing key from another label.
type DeriveRule struct {
	From     string `json:"from"`
	Regex    string `json:"regex"`
	To       string `json:"to"`
	Template string `json:"template"`
}

// Policy is an organization label policy.
type Policy struct {
	AllowedKeys  []string          `json:"allowed_keys"`
	DeniedKeys   []string          `json:"denied_keys"`
	RequiredKeys []string          `json:"required_keys"`
	OnInvalid    string            `json:"on_invalid"`
	OnMissing    string            `json:"on_missing"`
	Aliases      map[string]string `json:"aliases"`
	Derive       []DeriveRule      `json:"derive"`
	RollupKeys   []string          `json:"rollup_keys"`
	MaxLabels    int               `json:"max_labels"`
	ValueMaxLen  int               `json:"value_max_len"`
}

// Compiled is a policy with patterns and derive expressions ready to run.
type Compiled struct {
	onInvalid   string
	onMissing   string
	maxLabels   int
	valueMaxLen int
	allowed     []keyPattern
	denied      []keyPattern
	required    []string
	aliases     map[string]string
	derive      []compiledDerive
	rollup      []string
}

type compiledDerive struct {
	from     string
	to       string
	template string
	re       *regexp.Regexp
}

type keyPattern struct {
	kind   string
	exact  string
	prefix string
}

const defaultPolicyJSON = `{
  "allowed_keys": ["*"],
  "denied_keys": [],
  "required_keys": [],
  "on_invalid": "drop",
  "on_missing": "allow",
  "aliases": {"jira.issue": "issue", "jira.project": "issue.project"},
  "derive": [
    {"from": "git.ref", "regex": "\\b([A-Z][A-Z0-9]{1,9}-\\d{1,7})\\b", "to": "issue", "template": "$1"},
    {"from": "issue", "regex": "^([A-Z][A-Z0-9]{1,9})-\\d{1,7}$", "to": "issue.project", "template": "$1"}
  ],
  "rollup_keys": ["task", "issue", "issue.project", "ci.pipeline", "ci.job_name", "ci.trigger",
                   "git.repo", "git.mr", "team", "cost_center", "env", "service"],
  "max_labels": 32,
  "value_max_len": 128
}`

// DefaultPolicy is the policy used when an organization has none stored.
func DefaultPolicy() Policy {
	var policy Policy
	if err := json.Unmarshal([]byte(defaultPolicyJSON), &policy); err != nil {
		panic("default label policy: " + err.Error())
	}
	return policy
}

// Compile checks the policy and prepares matchers.
func (p Policy) Compile() (*Compiled, error) {
	onInvalid := p.OnInvalid
	if onInvalid == "" {
		onInvalid = "drop"
	}
	if onInvalid != "drop" && onInvalid != "reject" {
		return nil, fmt.Errorf("on_invalid: %q", p.OnInvalid)
	}
	onMissing := p.OnMissing
	if onMissing == "" {
		onMissing = "allow"
	}
	if onMissing != "allow" && onMissing != "warn" && onMissing != "reject" {
		return nil, fmt.Errorf("on_missing: %q", p.OnMissing)
	}
	if len(p.RollupKeys) > 40 {
		return nil, fmt.Errorf("rollup_keys: %d exceeds 40", len(p.RollupKeys))
	}
	compiled := &Compiled{
		onInvalid:   onInvalid,
		onMissing:   onMissing,
		maxLabels:   p.MaxLabels,
		valueMaxLen: p.ValueMaxLen,
		aliases:     map[string]string{},
		rollup:      append([]string(nil), p.RollupKeys...),
	}
	if compiled.maxLabels <= 0 {
		compiled.maxLabels = MaxEffective
	}
	if compiled.valueMaxLen <= 0 {
		compiled.valueMaxLen = MaxValueLen
	}
	var err error
	if compiled.allowed, err = compilePatterns(p.AllowedKeys); err != nil {
		return nil, err
	}
	if compiled.denied, err = compilePatterns(p.DeniedKeys); err != nil {
		return nil, err
	}
	for _, key := range p.RequiredKeys {
		norm, ok := NormalizeKey(key)
		if !ok {
			return nil, fmt.Errorf("required_keys: %q", key)
		}
		compiled.required = append(compiled.required, norm)
	}
	for from, to := range p.Aliases {
		src, srcOK := NormalizeKey(from)
		dst, dstOK := NormalizeKey(to)
		if !srcOK || !dstOK {
			return nil, fmt.Errorf("aliases: %q -> %q", from, to)
		}
		compiled.aliases[src] = dst
	}
	for _, rule := range p.Derive {
		if len(rule.Regex) > 256 {
			return nil, fmt.Errorf("derive regex longer than 256")
		}
		from, fromOK := NormalizeKey(rule.From)
		to, toOK := NormalizeKey(rule.To)
		if !fromOK || !toOK {
			return nil, fmt.Errorf("derive keys: %q -> %q", rule.From, rule.To)
		}
		re, err := regexp.Compile(rule.Regex)
		if err != nil {
			return nil, fmt.Errorf("derive regex: %w", err)
		}
		compiled.derive = append(compiled.derive, compiledDerive{from: from, to: to, template: rule.Template, re: re})
	}
	return compiled, nil
}

func compilePatterns(raw []string) ([]keyPattern, error) {
	out := make([]keyPattern, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item == "*" {
			out = append(out, keyPattern{kind: "star"})
			continue
		}
		if strings.HasSuffix(item, ".*") {
			prefix, ok := NormalizeKey(strings.TrimSuffix(item, ".*"))
			if !ok {
				return nil, fmt.Errorf("key pattern: %q", item)
			}
			out = append(out, keyPattern{kind: "prefix", prefix: prefix})
			continue
		}
		exact, ok := NormalizeKey(item)
		if !ok {
			return nil, fmt.Errorf("key pattern: %q", item)
		}
		out = append(out, keyPattern{kind: "exact", exact: exact})
	}
	return out, nil
}

func (p keyPattern) match(key string) bool {
	switch p.kind {
	case "star":
		return !reservedKey(key)
	case "prefix":
		return key == p.prefix || strings.HasPrefix(key, p.prefix+".")
	default:
		return key == p.exact
	}
}

// OnMissing reports allow, warn, or reject.
func (c *Compiled) OnMissing() string {
	if c == nil {
		return "allow"
	}
	return c.onMissing
}

func matchesAny(patterns []keyPattern, key string) bool {
	for _, pattern := range patterns {
		if pattern.match(key) {
			return true
		}
	}
	return false
}
