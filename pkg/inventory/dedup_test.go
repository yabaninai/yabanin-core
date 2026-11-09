package inventory

// E02-P01 W05-C01: the dedup rules — URL normalization (the SSRF-guard
// treatment plus canonical spelling), model-key convergence (exactly one
// catalog pair ⇒ the canonical import key), one-object-one-key at any
// fold order across both planes, and the documented provider-less vs
// canonical model-key collision pinned as a merge (not hidden).

import (
	"context"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dedupCatalog is a minimal ModelCatalogSource fixture (the
// adversarialCatalog pattern from W03-C03, kept tiny: the convergence
// rule reads only Entries()).
type dedupCatalog struct{ entries []provider.ModelCatalogEntry }

func (c *dedupCatalog) Meta() CatalogMeta                     { return CatalogMeta{} }
func (c *dedupCatalog) Entries() []provider.ModelCatalogEntry { return c.entries }
func (c *dedupCatalog) Withdrawals() []provider.Withdrawal    { return nil }

func (c *dedupCatalog) ResolveAlias(providerName, alias string, at time.Time) (string, provider.ModelStatus) {
	for _, e := range c.entries {
		if e.Provider != providerName {
			continue
		}
		if e.Model == alias {
			return e.Model, provider.StatusActive
		}
		for _, a := range e.Aliases {
			if a == alias {
				return e.Model, provider.StatusActive
			}
		}
	}
	return "", provider.StatusUnknown
}

// TestNormalizeServiceURL: the guard treatment (parse, http(s), host,
// no userinfo) plus the canonical spelling of the survivors — and only
// those: path/query distinguish deployments, fragments never travel.
func TestNormalizeServiceURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"already canonical", "https://api.example.com/v1", "https://api.example.com/v1", true},
		{"uppercase scheme and host", "HTTPS://API.Example.COM/v1", "https://api.example.com/v1", true},
		{"default https port dropped", "https://example.com:443/x", "https://example.com/x", true},
		{"default http port dropped", "http://example.com:80/x", "http://example.com/x", true},
		{"non-default port kept", "https://example.com:8443/x", "https://example.com:8443/x", true},
		{"empty path becomes root", "https://example.com", "https://example.com/", true},
		{"query kept verbatim", "https://example.com/v1?api_key=x&z=1", "https://example.com/v1?api_key=x&z=1", true},
		{"fragment dropped", "https://example.com/v1#frag", "https://example.com/v1", true},
		{"userinfo rejected", "https://user:pw@example.com/v1", "", false},
		{"hostless rejected", "https:///v1", "", false},
		{"non-http scheme rejected", "ftp://example.com/f", "", false},
		{"schemeless rejected", "example.com/v1", "", false},
		{"unparseable rejected", "https://[::1", "", false},
		{"whitespace host has no key", "https://ex ample.com/v1", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := NormalizeServiceURL(tc.raw)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
			// The identity and the key agree: whatever normalizes is
			// keyable, whatever does not yields no key at all.
			key, keyOK := ServiceKeyOf(tc.raw)
			assert.Equal(t, tc.ok, keyOK)
			if tc.ok {
				assert.Equal(t, ServiceKey(tc.want), key)
			}
		})
	}
}

// TestResolveModelKey: exactly one catalog pair ⇒ the canonical import
// key; unknown or ambiguous names ⇒ the provider-less key (the
// 0-or->1 ⇒ NO attribution invariant); identity matching ignores
// lifecycle status; a nil catalog is always provider-less.
func TestResolveModelKey(t *testing.T) {
	cat := &dedupCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"gpt5", "o5"}},
		{Provider: "anthropic", Model: "claude-x", Aliases: []string{"gpt5"}},
		// Same pair listed twice (duplicate snapshot rows): ONE match.
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"gpt5"}},
	}}
	cases := []struct {
		name string
		cat  ModelCatalogSource
		in   string
		want string
	}{
		{"canonical name", cat, "gpt-5", ModelKey("openai", "gpt-5")},
		{"alias resolves", cat, "o5", ModelKey("openai", "gpt-5")},
		{"unknown name stays provider-less", cat, "llama-9", observedModelKey("llama-9")},
		{"ambiguous alias stays provider-less", cat, "gpt5", observedModelKey("gpt5")},
		{"nil catalog stays provider-less", nil, "gpt-5", observedModelKey("gpt-5")},
		{"empty name", cat, "", observedModelKey("")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ResolveModelKey(tc.in, tc.cat))
		})
	}

	// Identity, not lifecycle: a pair outside its sell window still owns
	// its alias (status is payload, not identity — see dedup.go rule 3).
	retired := &dedupCatalog{entries: []provider.ModelCatalogEntry{{
		Provider: "openai", Model: "gpt-old", Aliases: []string{"legacy"},
		EffectiveFrom: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		EffectiveTo:   time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
	}}}
	assert.Equal(t, ModelKey("openai", "gpt-old"), ResolveModelKey("legacy", retired),
		"a retired pair still owns its alias")
}

func dedupEvent(requestID, model string) *eventpublisher.Event {
	return dedupEventAt(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), requestID, model)
}

func dedupEventAt(ts time.Time, requestID, model string) *eventpublisher.Event {
	return &eventpublisher.Event{
		TS:             ts.UnixMilli(),
		RequestID:      requestID,
		AgentID:        "agent-d1",
		ModelRequested: model,
		ModelUsed:      model,
		UpstreamURL:    "https://api.example.com/v1",
		StatusCode:     200,
	}
}

func dedupImportModel(t *testing.T, org, providerName, model string, seen time.Time) Asset {
	t.Helper()
	return Asset{
		OrgID: org, AssetKey: ModelKey(providerName, model), Kind: KindModel,
		Payload: []byte(`{"imported":true}`), Source: SourceModelsRegistry,
		Confidence: ConfidenceHigh, FirstSeen: seen, LastSeen: seen,
	}
}

// TestDedupOneObjectOneKeyAnyOrder: the acceptance criterion — one real
// object lands on exactly one (asset_key, kind) row regardless of which
// plane saw it first. Import wins payload/source (authoritative plane,
// upsert contract); first_seen keeps the earliest observation. Subtests
// share the test database (one container per parent test), so each owns
// a distinct org.
func TestDedupOneObjectOneKeyAnyOrder(t *testing.T) {
	cat := &dedupCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"o5"}},
	}}
	t1 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 11, 8, 15, 0, 0, 0, time.UTC)

	t.Run("import first, observation converges", func(t *testing.T) {
		org := "org-dd1a"
		s := newTestStore(t)
		ctx := context.Background()
		_, err := s.UpsertAssets(ctx, []Asset{dedupImportModel(t, org, "openai", "gpt-5", t2)})
		require.NoError(t, err)

		o, err := NewObserver(s)
		require.NoError(t, err)
		o.SetCatalog(cat)
		// The wire name is the ALIAS: convergence must land on the
		// canonical key, not a second provider-less row.
		rep, err := o.ObserveEvent(ctx, org, dedupEventAt(t3, "req-a", "o5"))
		require.NoError(t, err)
		// Batch = agent + converged model + service; the model hit the
		// existing canonical row and is classified updated, not created.
		assert.Equal(t, 2, rep.Counts.Created, "%+v", rep.Counts)
		assert.Equal(t, 1, rep.Counts.Updated, "%+v", rep.Counts)

		row, ok, err := s.GetAsset(ctx, org, KindModel, ModelKey("openai", "gpt-5"))
		require.NoError(t, err)
		require.True(t, ok, "canonical key must exist")
		assert.Equal(t, SourceModelsRegistry, row.Source, "import stays authoritative")
		assert.True(t, row.FirstSeen.Equal(t2))
		assert.True(t, row.LastSeen.Equal(t3), "later observation advances last_seen")

		rows, _, err := s.ListAssets(ctx, org, ListParams{})
		require.NoError(t, err)
		models := 0
		for _, r := range rows {
			if r.Kind == KindModel {
				models++
			}
		}
		assert.Equal(t, 1, models, "one object, one model row")
		// The provider-less spelling never existed.
		_, ok, _ = s.GetAsset(ctx, org, KindModel, observedModelKey("o5"))
		assert.False(t, ok, "no provider-less twin row")
	})

	t.Run("observation first, import converges onto it", func(t *testing.T) {
		org := "org-dd1b"
		s := newTestStore(t)
		ctx := context.Background()
		o, err := NewObserver(s)
		require.NoError(t, err)
		o.SetCatalog(cat)
		rep, err := o.ObserveEvent(ctx, org, dedupEventAt(t1, "req-b", "gpt-5"))
		require.NoError(t, err)
		assert.Equal(t, 3, rep.Counts.Created, "agent + canonical model + service")

		// Canonical import lands on the SAME key: one row, payload/source
		// become the import's, first_seen keeps the observation's.
		_, err = s.UpsertAssets(ctx, []Asset{dedupImportModel(t, org, "openai", "gpt-5", t2)})
		require.NoError(t, err)

		rows, _, err := s.ListAssets(ctx, org, ListParams{})
		require.NoError(t, err)
		models := 0
		for _, r := range rows {
			if r.Kind == KindModel {
				models++
				assert.Equal(t, SourceModelsRegistry, r.Source)
				assert.True(t, r.FirstSeen.Equal(t1), "earliest first_seen survives")
			}
		}
		assert.Equal(t, 1, models, "one object, one model row")
	})

	t.Run("two url spellings, one service asset", func(t *testing.T) {
		org := "org-dd1c"
		s := newTestStore(t)
		ctx := context.Background()
		o, err := NewObserver(s)
		require.NoError(t, err)

		e1 := dedupEvent("req-c", "gpt-5")
		e1.UpstreamURL = "HTTPS://API.Example.COM:443/v1"
		_, err = o.ObserveEvent(ctx, org, e1)
		require.NoError(t, err)
		e2 := dedupEvent("req-d", "gpt-5")
		e2.UpstreamURL = "https://api.example.com/v1"
		rep, err := o.ObserveEvent(ctx, org, e2)
		require.NoError(t, err)

		svc, ok, err := s.GetAsset(ctx, org, KindService, ServiceKey("https://api.example.com/v1"))
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, SourceObservation, svc.Source)
		assert.False(t, rep.Deduped, "different requests fold both")

		rows, _, err := s.ListAssets(ctx, org, ListParams{})
		require.NoError(t, err)
		services := 0
		for _, r := range rows {
			if r.Kind == KindService {
				services++
			}
		}
		assert.Equal(t, 1, services, "both spellings, one service row")
		// The raw uppercase spelling never existed as its own row.
		_, ok, _ = s.GetAsset(ctx, org, KindService, ServiceKey("HTTPS://API.Example.COM:443/v1"))
		assert.False(t, ok)
	})

	t.Run("two observations, one agent asset", func(t *testing.T) {
		org := "org-dd1d"
		s := newTestStore(t)
		ctx := context.Background()
		o, err := NewObserver(s)
		require.NoError(t, err)
		_, err = o.ObserveEvent(ctx, org, dedupEvent("req-e", "gpt-5"))
		require.NoError(t, err)
		_, err = o.ObserveEvent(ctx, org, dedupEvent("req-f", "gpt-5"))
		require.NoError(t, err)

		_, ok, err := s.GetAsset(ctx, org, KindAgent, AgentKey("agent-d1"))
		require.NoError(t, err)
		require.True(t, ok)
		rows, _, err := s.ListAssets(ctx, org, ListParams{})
		require.NoError(t, err)
		agents := 0
		for _, r := range rows {
			if r.Kind == KindAgent {
				agents++
			}
		}
		assert.Equal(t, 1, agents)
	})

	t.Run("url without identity drops only the service", func(t *testing.T) {
		org := "org-dd1e"
		s := newTestStore(t)
		ctx := context.Background()
		o, err := NewObserver(s)
		require.NoError(t, err)
		e := dedupEvent("req-g", "gpt-5")
		e.UpstreamURL = "https://user:pw@example.com/v1"
		rep, err := o.ObserveEvent(ctx, org, e)
		require.NoError(t, err)
		assert.Equal(t, 2, rep.Counts.Created, "agent+model fold, service identity dropped")

		rows, _, err := s.ListAssets(ctx, org, ListParams{})
		require.NoError(t, err)
		for _, r := range rows {
			assert.NotEqual(t, KindService, r.Kind, "no service row from a guard-rejected url")
		}
	})
}

// TestDedupDocumentedCollisionModelKey pins the one analyzed collision
// (dedup.go): a provider-less observation of the wire name "p/a/b" is
// spelled exactly like the canonical key of the real pair (p, "a/b").
// Without a catalog the two objects share one row — the merge behavior
// is the contract here, not a bug to hide: the authoritative plane wins
// the payload and first_seen keeps the earliest. This test documents
// WHY catalog wiring (the wiring card) is the deployment answer.
func TestDedupDocumentedCollisionModelKey(t *testing.T) {
	org := "org-dd2"
	s := newTestStore(t)
	ctx := context.Background()
	t1 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)

	// Provider-less observation, no catalog: model:p/a/b.
	o, err := NewObserver(s)
	require.NoError(t, err)
	e := dedupEvent("req-x", "p/a/b")
	e.TS = t1.UnixMilli()
	_, err = o.ObserveEvent(ctx, org, e)
	require.NoError(t, err)
	_, ok, err := s.GetAsset(ctx, org, KindModel, observedModelKey("p/a/b"))
	require.NoError(t, err)
	require.True(t, ok)

	// The real pair's canonical key is the SAME string.
	require.Equal(t, observedModelKey("p/a/b"), ModelKey("p", "a/b"),
		"the collision is real: identical key spellings")

	// The import lands on that one row: merge, not a second asset.
	_, err = s.UpsertAssets(ctx, []Asset{dedupImportModel(t, org, "p", "a/b", t2)})
	require.NoError(t, err)

	rows, _, err := s.ListAssets(ctx, org, ListParams{})
	require.NoError(t, err)
	models := 0
	for _, r := range rows {
		if r.Kind == KindModel {
			models++
			assert.Equal(t, SourceModelsRegistry, r.Source, "authoritative plane wins payload")
			assert.True(t, r.FirstSeen.Equal(t1), "earliest first_seen survives the merge")
		}
	}
	require.Equal(t, 1, models, "documented collision merges into one row")
}
