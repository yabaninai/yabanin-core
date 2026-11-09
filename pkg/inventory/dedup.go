package inventory

// E02-P01 W05-C01: the deduplication rules — how one real-world object
// maps onto exactly one (asset_key, kind) pair no matter which plane
// (import or observation) saw it and in which order. Three rule
// families:
//
//  1. STABILITY — keys emitted by the reviewed import/observation planes
//     keep their documented formats verbatim (the W01 §4 promise: dedup
//     converges WITHOUT key migration): mcp_server:<name>,
//     mcp_tool:<server>/<tool>, provider:<name>, model:<provider>/<model>,
//     agent:<id>. This file adds no second spelling of an existing key.
//
//  2. NORMALIZATION (service) — an observed upstream URL is normalized
//     with the same treatment the mcpagg SSRF guard applies to server
//     URLs (pkg/mcpagg/validate.go validateServerURL: parseable URL,
//     http(s) scheme, non-empty host, NO embedded userinfo) plus the
//     canonical spelling of the surviving components: lowercase scheme
//     and host, default port dropped, empty path becomes "/". Path and
//     query are kept verbatim (they can distinguish deployments); the
//     fragment (never sent on the wire) is dropped. A URL that fails the
//     guard treatment has no stable identity and yields no key — the
//     caller drops that one identity, never the whole event (the
//     validKeyPart precedent). Rows written by the W04 observation plane
//     before this card are NOT rewritten: the registry never deletes,
//     and convergence is forward-looking (W01 law).
//
//  3. CONVERGENCE (model) — a wire model name carries no provider
//     (eventpublisher ModelRequested/ModelUsed). When the reference
//     catalog resolves the name to EXACTLY ONE (provider, canonical
//     model) pair — the name equals the entry's Model or is one of its
//     Aliases — the observation lands on the canonical import key
//     ModelKey(provider, model) and therefore converges with the import
//     plane on one asset. Zero matches (unknown name) or MORE than one
//     distinct match (the same alias in two providers, or a name that is
//     a model of one provider and an alias of another) keep the
//     provider-less model:<name> key: the 0-or->1 ⇒ NO attribution
//     invariant (attribution requires a confirmed unique match; anything
//     else stays unattributed). Matching
//     is on IDENTITY (exact name/alias membership), not lifecycle
//     status: a pending or retired pair still owns its alias — status is
//     payload, not identity.
//
// Collision analysis (pinned by TestDedupDocumentedCollisionModelKey):
//
//   - agent:<id> — agent ids are unique per org in agent_keys; the PK
//     (org_id, asset_key, kind) isolates orgs. Injective.
//   - mcp_server:<name> and mcp_tool:<server>/<tool> — server names
//     reject "/" (mcpagg.ValidateServerName), so the first "/" after the
//     server segment is unambiguous; a tool name containing "/" stays
//     verbatim and stays injective within its server. Two different
//     servers cannot forge one tool key without a "/" in a server name.
//   - model:<provider>/<model> vs provider-less model:<name> — THE
//     documented collision: provider-less keys are not syntactically
//     namespaced, so a wire name that literally contains "/" and does
//     not resolve through the catalog can coincide with the canonical
//     key of a DIFFERENT real pair (provider "p", model "a/b" ⇐ observed
//     wire name "p/a/b"). The test pins the merge behavior (one row, the
//     authoritative plane wins payload, first_seen keeps the earliest)
//     instead of hiding it. Exposure requires "/" inside a model name
//     AND an unresolved provider-less observation; catalog-wired
//     deployments resolve such names through rule 3 first whenever the
//     catalog knows the pair.

import (
	"net"
	"net/url"
	"strings"

	"github.com/reireirei/yabanin/pkg/provider"
)

// NormalizeServiceURL applies the SSRF-guard treatment (parseable URL,
// http(s) only, non-empty host, no userinfo — the pkg/mcpagg
// validateServerURL rules) and canonicalizes the survivors: lowercase
// scheme and host, default port (443/https, 80/http) dropped, empty path
// becomes "/", fragment dropped, path and query kept verbatim. ok=false
// marks a URL with no stable service identity.
func NormalizeServiceURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	host := u.Hostname()
	if host == "" || u.User != nil {
		return "", false
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	hostPart := strings.ToLower(host)
	if port != "" {
		hostPart = net.JoinHostPort(hostPart, port)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	out := scheme + "://" + hostPart + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out, true
}

// ServiceKeyOf derives the canonical asset key of an observed service
// URL. ok=false: the URL has no stable identity — the caller drops this
// one identity, never the whole event.
func ServiceKeyOf(raw string) (string, bool) {
	norm, ok := NormalizeServiceURL(raw)
	if !ok {
		return "", false
	}
	key := ServiceKey(norm)
	if validKeyPart("asset_key", key) != nil {
		return "", false
	}
	return key, true
}

// ResolveModelKey maps a wire model name onto its canonical asset key:
// exactly one catalog pair ⇒ ModelKey(provider, canonical) — converging
// with the import plane on one asset; zero matches or an ambiguous name
// (more than one distinct pair) ⇒ the provider-less observation key
// (the 0-or->1 ⇒ NO attribution invariant). A nil catalog always yields
// the provider-less key (no reference plane installed).
func ResolveModelKey(name string, catalog ModelCatalogSource) string {
	if catalog == nil || name == "" {
		return observedModelKey(name)
	}
	var (
		found    pairKey
		distinct int
	)
	matched := map[pairKey]bool{}
	for _, e := range catalog.Entries() {
		if !catalogEntryMatches(e, name) {
			continue
		}
		k := pairKey{provider: e.Provider, model: e.Model}
		if matched[k] {
			continue // the same pair listed twice
		}
		matched[k] = true
		found = k
		distinct++
	}
	if distinct != 1 {
		// Zero matches (unknown name) or an ambiguous name: no
		// attribution — the provider-less key stays.
		return observedModelKey(name)
	}
	return ModelKey(found.provider, found.model)
}

// catalogEntryMatches reports whether the wire name addresses the entry:
// exactly its canonical model name or one of its aliases (identity, not
// lifecycle status — see the package comment, rule 3).
func catalogEntryMatches(e provider.ModelCatalogEntry, name string) bool {
	if e.Model == name {
		return true
	}
	for _, a := range e.Aliases {
		if a == name {
			return true
		}
	}
	return false
}
