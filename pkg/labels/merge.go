package labels

import "sort"

// Result is the effective label set after policy.
type Result struct {
	Labels     Set
	Dropped    []Dropped
	Missing    []string
	Rejected   bool
	RejectCode string
}

type tagged struct {
	value  string
	origin string
	locked bool
}

// Resolve merges sources and applies the compiled policy.
// sources are ordered from weakest to strongest.
func Resolve(c *Compiled, sources []Source, secret SecretFunc) Result {
	if c == nil {
		c, _ = DefaultPolicy().Compile()
	}
	var result Result
	result.Labels = Set{}
	effective := map[string]tagged{}
	invalid := false

	for _, source := range sources {
		aliased := applyAliases(source.Labels, c.aliases)
		for key, value := range aliased {
			norm, ok := NormalizeKey(key)
			if !ok {
				result.Dropped = append(result.Dropped, Dropped{Key: key, Reason: DropInvalidKey})
				invalid = true
				continue
			}
			if reservedKey(norm) {
				result.Dropped = append(result.Dropped, Dropped{Key: norm, Reason: DropReserved})
				invalid = true
				continue
			}
			if prev, exists := effective[norm]; exists && prev.locked && prev.value != value {
				result.Dropped = append(result.Dropped, Dropped{Key: norm, Reason: DropLocked})
				continue
			}
			checked, reason := acceptValue(value, c.valueMaxLen, secret)
			if reason != "" {
				result.Dropped = append(result.Dropped, Dropped{Key: norm, Reason: reason})
				if reason != DropSecretLike {
					invalid = true
				}
				continue
			}
			origin := source.Name
			if origin == "" {
				origin = "request"
			}
			effective[norm] = tagged{value: checked, origin: origin, locked: source.Locked}
		}
	}

	for _, rule := range c.derive {
		if _, exists := effective[rule.to]; exists {
			continue
		}
		from, ok := effective[rule.from]
		if !ok {
			continue
		}
		match := rule.re.FindStringSubmatchIndex(from.value)
		if match == nil {
			continue
		}
		derived := string(rule.re.ExpandString(nil, rule.template, from.value, match))
		checked, reason := acceptValue(derived, c.valueMaxLen, secret)
		if reason != "" {
			result.Dropped = append(result.Dropped, Dropped{Key: rule.to, Reason: reason})
			if reason != DropSecretLike {
				invalid = true
			}
			continue
		}
		if _, keyOK := NormalizeKey(rule.to); !keyOK || reservedKey(rule.to) {
			continue
		}
		effective[rule.to] = tagged{value: checked, origin: "derive"}
	}

	for key := range effective {
		if matchesAny(c.denied, key) || (len(c.allowed) > 0 && !matchesAny(c.allowed, key)) {
			result.Dropped = append(result.Dropped, Dropped{Key: key, Reason: DropNotAllowed})
			delete(effective, key)
		}
	}

	trimToMax(effective, c.maxLabels, &result)
	for key, item := range effective {
		result.Labels[key] = item.value
	}
	for _, key := range c.required {
		if _, ok := result.Labels[key]; !ok {
			result.Missing = append(result.Missing, key)
		}
	}
	sort.Strings(result.Missing)
	if invalid && c.onInvalid == "reject" {
		result.Rejected = true
		result.RejectCode = "invalid_labels"
	}
	if len(result.Missing) > 0 && c.onMissing == "reject" && !result.Rejected {
		result.Rejected = true
		result.RejectCode = "missing_required_labels"
	}
	return result
}

func applyAliases(labels Set, aliases map[string]string) Set {
	if len(labels) == 0 {
		return Set{}
	}
	out := Set{}
	for key, value := range labels {
		out[key] = value
	}
	for from, to := range aliases {
		alias, ok := out[from]
		if !ok {
			continue
		}
		if _, canonical := out[to]; !canonical {
			out[to] = alias
		}
		delete(out, from)
	}
	return out
}

func acceptValue(value string, maxLen int, secret SecretFunc) (string, DropReason) {
	checked, reason := NormalizeValue(value)
	if reason != "" {
		return "", reason
	}
	if maxLen > 0 && len(checked) > maxLen {
		return "", DropValueTooLong
	}
	if secret != nil && secret(checked) {
		return "", DropSecretLike
	}
	return checked, ""
}

func trimToMax(effective map[string]tagged, max int, result *Result) {
	if len(effective) <= max {
		return
	}
	dropOrigin := func(origin string) {
		var keys []string
		for key, item := range effective {
			if item.origin == origin {
				keys = append(keys, key)
			}
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		for _, key := range keys {
			if len(effective) <= max {
				return
			}
			delete(effective, key)
			result.Dropped = append(result.Dropped, Dropped{Key: key, Reason: DropTooMany})
		}
	}
	dropOrigin("derive")
	dropOrigin("request")
}
