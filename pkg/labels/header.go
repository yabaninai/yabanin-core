package labels

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ParseHeaderValues parses one or more X-Yabanin-Labels field values.
func ParseHeaderValues(values []string) (Set, []Dropped) {
	total := 0
	for _, value := range values {
		total += len(value)
	}
	if total > MaxHeaderBytes {
		return Set{}, []Dropped{{Key: "*", Reason: DropHeaderTooLong}}
	}
	out := Set{}
	var dropped []Dropped
	for _, value := range values {
		for _, element := range strings.Split(value, ",") {
			element = strings.TrimSpace(element)
			if element == "" {
				continue
			}
			if cut := strings.IndexByte(element, ';'); cut >= 0 {
				element = strings.TrimSpace(element[:cut])
			}
			if element == "" {
				continue
			}
			keyRaw, valRaw, ok := strings.Cut(element, "=")
			if !ok {
				dropped = append(dropped, Dropped{Key: strings.TrimSpace(keyRaw), Reason: DropInvalidKey})
				continue
			}
			key, keyOK := NormalizeKey(keyRaw)
			if !keyOK {
				dropped = append(dropped, Dropped{Key: strings.TrimSpace(keyRaw), Reason: DropInvalidKey})
				continue
			}
			if reservedKey(key) {
				dropped = append(dropped, Dropped{Key: key, Reason: DropReserved})
				continue
			}
			val, reason := NormalizeValue(valRaw)
			if reason != "" {
				dropped = append(dropped, Dropped{Key: key, Reason: reason})
				continue
			}
			if _, exists := out[key]; !exists && len(out) >= MaxPerSource {
				dropped = append(dropped, Dropped{Key: key, Reason: DropTooMany})
				continue
			}
			out[key] = val
		}
	}
	return out, dropped
}

// ParsePerKey reads X-Yabanin-Label-<key> headers. They override the list header.
func ParsePerKey(h http.Header) (Set, []Dropped) {
	if h == nil {
		return Set{}, nil
	}
	prefix := http.CanonicalHeaderKey(PerKeyPrefix)
	out := Set{}
	var dropped []Dropped
	keys := make([]string, 0, len(h))
	for key := range h {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, headerKey := range keys {
		if !strings.HasPrefix(headerKey, prefix) {
			continue
		}
		rawKey := strings.ToLower(strings.TrimPrefix(headerKey, prefix))
		key, ok := NormalizeKey(rawKey)
		if !ok {
			dropped = append(dropped, Dropped{Key: rawKey, Reason: DropInvalidKey})
			continue
		}
		if reservedKey(key) {
			dropped = append(dropped, Dropped{Key: key, Reason: DropReserved})
			continue
		}
		values := h.Values(headerKey)
		if len(values) == 0 {
			continue
		}
		raw := values[len(values)-1]
		val, reason := NormalizeValue(raw)
		if reason != "" {
			dropped = append(dropped, Dropped{Key: key, Reason: reason})
			continue
		}
		if _, exists := out[key]; !exists && len(out) >= MaxPerSource {
			dropped = append(dropped, Dropped{Key: key, Reason: DropTooMany})
			continue
		}
		out[key] = val
	}
	return out, dropped
}

// FromRequest combines the list header and the per-key headers.
// Per-key headers win. The 20-label cap applies to the combined request source.
func FromRequest(h http.Header) (Set, []Dropped) {
	if h == nil {
		return Set{}, nil
	}
	set, dropped := ParseHeaderValues(h.Values(HeaderName))
	per, perDropped := ParsePerKey(h)
	dropped = append(dropped, perDropped...)
	for key, value := range per {
		if _, exists := set[key]; !exists && len(set) >= MaxPerSource {
			dropped = append(dropped, Dropped{Key: key, Reason: DropTooMany})
			continue
		}
		set[key] = value
	}
	return set, dropped
}

// Encode serializes a set in canonical form: sorted keys, percent-encoded values.
func Encode(s Set) string {
	if len(s) == 0 {
		return ""
	}
	keys := make([]string, 0, len(s))
	for key := range s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(key)
		b.WriteByte('=')
		b.WriteString(url.PathEscape(s[key]))
	}
	return b.String()
}
