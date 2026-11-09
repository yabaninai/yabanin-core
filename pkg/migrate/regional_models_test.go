package migrate

import (
	"strings"
	"testing"
)

// I18N-14: regional model entries with availability honesty. The integration
// test (migrate_integration_test.go) needs Postgres; this test asserts the
// structural half against the embedded SQL so the invariant is enforced in the
// normal gate: the four regional models exist, are registry-only (enabled
// false / no phantom upstream) where there is no public hosted API, and the
// Z.AI Coding Plan allowlist is untouched.

// TestRegionalModelsMigration_PresentAndHonest pins the I18N-14 seed.
func TestRegionalModelsMigration_PresentAndHonest(t *testing.T) {
	// The regional-model seeds originally landed in migration 0003; the
	// migrations are squashed into the 0001_init baseline, so the invariants
	// are pinned against the baseline. (The old 0003-specific "down deletes
	// ids 26..29" check is obsolete: the baseline down drops the whole
	// models_registry table.)
	up, err := migrationsFS.ReadFile("migrations/0001_init.up.sql")
	if err != nil {
		t.Fatalf("read baseline up: %v", err)
	}
	text := string(up)

	// The four regional models must be present.
	for _, model := range []string{"taide-large", "allam-7b", "fpt-llm-45b", "apertus-7b"} {
		if !strings.Contains(text, model) {
			t.Errorf("baseline up missing regional model %q", model)
		}
	}

	// Availability honesty:
	//  - open-weights, no hosted API → enabled=false and upstream_url NULL.
	//    (TAIDE, ALLaM, Apertus.)
	//  - public API exists (FPT) → upstream_url set, but still enabled=false
	//    until an operator wires a key (no dedicated factory adapter).
	for _, model := range []string{"taide-large", "allam-7b", "apertus-7b"} {
		if !hasRegistryOnlyRow(t, text, model) {
			t.Errorf("%s must be registry-only (enabled=false, upstream_url NULL)", model)
		}
	}
	if !hasUpstreamRow(t, text, "fpt-llm-45b", "https://api.fpt.ai/llm") {
		t.Errorf("fpt-llm-45b must carry its public upstream_url")
	}

	// Every new row is unavailable (enabled=false) — the gateway must not route
	// to a model with no reachable upstream.
	for _, model := range []string{"taide-large", "allam-7b", "fpt-llm-45b", "apertus-7b"} {
		if !hasDisabledFlag(t, text, model) {
			t.Errorf("%s must be enabled=false (unavailable until wired)", model)
		}
	}

	// Z.AI Coding Plan allowlist is a separate provider concern and must not
	// appear in the regional seed rows (the allowlist lives in gateway
	// config, not the registry seeds).
	for _, model := range []string{"taide-large", "allam-7b", "fpt-llm-45b", "apertus-7b"} {
		row := rowFor(t, text, model)
		if strings.Contains(row, "zai") {
			t.Errorf("regional seed row for %s must not touch the Z.AI allowlist", model)
		}
	}
}

// rowFor extracts the VALUES tuple text for a model name (the parenthesised
// group that mentions it).
func rowFor(t *testing.T, text, model string) string {
	t.Helper()
	i := strings.Index(text, "'"+model+"'")
	if i < 0 {
		t.Fatalf("model %q not found in the baseline up", model)
	}
	// The squashed baseline is a pg_dump --inserts dump: one INSERT per
	// line, so the tuple is the whole line containing the model name.
	start := strings.LastIndex(text[:i], "\n") + 1
	end := strings.Index(text[start:], "\n")
	if end < 0 {
		end = len(text) - start
	}
	return text[start : start+end]
}

// hasRegistryOnlyRow asserts a model row has upstream_url NULL (no hosted API).
func hasRegistryOnlyRow(t *testing.T, text, model string) bool {
	t.Helper()
	row := rowFor(t, text, model)
	// The tuple's 5th column is upstream_url; for registry-only it is NULL.
	return strings.Contains(row, "NULL, NULL, false")
}

// hasUpstreamRow asserts a model row carries the given upstream_url.
func hasUpstreamRow(t *testing.T, text, model, url string) bool {
	t.Helper()
	row := rowFor(t, text, model)
	return strings.Contains(row, url)
}

// hasDisabledFlag asserts a model row is enabled=false (the boolean right after
// upstream_url / upstream_api_key).
func hasDisabledFlag(t *testing.T, text, model string) bool {
	t.Helper()
	row := rowFor(t, text, model)
	// Each tuple has "false," for enabled (and possibly upstream_api_key NULL).
	return strings.Contains(row, "false,")
}
