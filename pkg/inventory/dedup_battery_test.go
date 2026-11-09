package inventory

// E02-P01 W05-C02: the dedup battery — every rule family of dedup.go
// pinned end-to-end over the real store (testcontainers Postgres, the
// full production migration set): re-registration, alias/direct model
// convergence in BOTH orders, the adapter-contract tool-rename
// lifecycle (tombstone ⇒ resurrect), cross-plane convergence with the
// authoritativeness and first_seen/last_seen laws, provider-less
// fallbacks, idempotent repeats, request dedup with its restart
// complement (SQL write-once), URL normalization in both orders, and
// guard-rejected identities dropping only themselves.
//
// Battery rows share the test database (one container per test
// function), so every row owns a distinct org.

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/reireirei/yabanin/pkg/provider"
	"github.com/reireirei/yabanin/pkg/secevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingDB is the P2 failure seam: while armed it fails every
// transaction open; disarmed it delegates to the wrapped pool. It exists
// so the battery can prove that a failed write leaves the delivery
// unmarked (review2 §3) without depending on a real outage.
type failingDB struct {
	DB
	fail bool
}

func (d *failingDB) Begin(ctx context.Context) (pgx.Tx, error) {
	if d.fail {
		return nil, errors.New("inventory: injected begin failure")
	}
	return d.DB.Begin(ctx)
}

type dedupBatteryRow struct {
	name string
	run  func(t *testing.T, s *Store)
}

// dedupBatteryRows is the table W05-C02 mandates (≥10 rows). Add rows
// here; do not weaken existing ones.
var dedupBatteryRows = []dedupBatteryRow{
	{
		name: "server re-registered under a new uuid and config version stays one asset",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org, at := "org-bat1", time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			first := Asset{OrgID: org, AssetKey: MCPServerKey("fs"), Kind: KindMCPServer,
				Payload: []byte(`{"name":"fs","server_uuid":"uuid-1","config_version":1}`),
				Source:  SourceMCPRegistry, Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at}
			c, err := s.UpsertAssets(ctx, []Asset{first})
			require.NoError(t, err)
			require.Equal(t, ImportCounts{Created: 1}, c)

			reg := first
			at2 := at.Add(time.Hour)
			reg.Payload = []byte(`{"name":"fs","server_uuid":"uuid-2","config_version":2}`)
			reg.FirstSeen, reg.LastSeen = at2, at2
			c, err = s.UpsertAssets(ctx, []Asset{reg})
			require.NoError(t, err)
			assert.Equal(t, ImportCounts{Updated: 1}, c, "re-registration updates, never duplicates")

			row, ok, err := s.GetAsset(ctx, org, KindMCPServer, MCPServerKey("fs"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.Contains(t, string(row.Payload), "uuid-2")
			assert.True(t, row.FirstSeen.Equal(at), "first_seen keeps the first registration")
			assert.True(t, row.LastSeen.Equal(at2), "last_seen advances to the re-registration")

			rows, _, err := s.ListAssets(ctx, org, ListParams{})
			require.NoError(t, err)
			assert.Len(t, rows, 1, "one server, one row")
		},
	},
	{
		name: "model alias then direct observation is one canonical asset",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			dedupBatteryOneModelAsset(t, s, "org-bat2", "alias-then-direct", "o5")
			dedupBatteryOneModelAsset(t, s, "org-bat3", "direct-then-alias", "gpt-5")
		},
	},
	{
		name: "tool rename tombstones the old name and resurrection undoes it (adapter contract)",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org, at := "org-bat4", time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			mkTool := func(tool, uuid string, ts time.Time) Asset {
				return Asset{OrgID: org, AssetKey: MCPToolKey("srv", tool), Kind: KindTool,
					Payload: []byte(`{"tool":"` + tool + `","uuid":"` + uuid + `"}`),
					Source:  SourceMCPRegistry, Confidence: ConfidenceHigh, FirstSeen: ts, LastSeen: ts}
			}
			// Import listing advertises the old tool.
			_, err := s.UpsertAssets(ctx, []Asset{mkTool("old_tool", "u1", at)})
			require.NoError(t, err)

			// Next listing advertises the RENAMED tool; the import adapter
			// reports the missing old name through the explicit tombstone
			// signal (the runner never auto-tombstones — W02 law).
			at2 := at.Add(time.Hour)
			_, err = s.UpsertAssets(ctx, []Asset{mkTool("new_tool", "u2", at2)})
			require.NoError(t, err)
			n, err := s.TombstoneAssets(ctx, org, KindTool, at2, []string{MCPToolKey("srv", "old_tool")})
			require.NoError(t, err)
			require.Equal(t, 1, n)

			old, ok, err := s.GetAsset(ctx, org, KindTool, MCPToolKey("srv", "old_tool"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.True(t, old.Tombstone, "renamed-away tool is tombstoned, not deleted")

			// A later listing advertising BOTH names resurrects the old
			// row (the registry never deletes: resurrection is an upsert).
			at3 := at2.Add(time.Hour)
			_, err = s.UpsertAssets(ctx, []Asset{mkTool("old_tool", "u1", at3), mkTool("new_tool", "u2", at3)})
			require.NoError(t, err)
			old, ok, err = s.GetAsset(ctx, org, KindTool, MCPToolKey("srv", "old_tool"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.False(t, old.Tombstone, "re-advertised tool resurrects")

			rows, _, err := s.ListAssets(ctx, org, ListParams{})
			require.NoError(t, err)
			assert.Len(t, rows, 2, "two tools, two rows")
		},
	},
	{
		name: "import and observation converge across planes in both orders",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			dedupBatteryCrossPlane(t, s, "org-bat5", "import-first")
			dedupBatteryCrossPlane(t, s, "org-bat6", "observation-first")
		},
	},
	{
		name: "provider-less shape pinned: unknown and ambiguous names never attribute",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat7"
			cat := &dedupCatalog{entries: dedupBatteryCatalog()}
			o, err := NewObserver(s)
			require.NoError(t, err)
			o.SetCatalog(cat)

			_, err = o.ObserveEvent(ctx, org, dedupEventAt(
				time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), "bat-u", "totally-unknown"))
			require.NoError(t, err)
			_, ok, err := s.GetAsset(ctx, org, KindModel, observedModelKey("totally-unknown"))
			require.NoError(t, err)
			require.True(t, ok, "unknown name keeps the provider-less key")

			_, err = o.ObserveEvent(ctx, org, dedupEventAt(
				time.Date(2026, 11, 8, 10, 1, 0, 0, time.UTC), "bat-a", "shared-alias"))
			require.NoError(t, err)
			_, ok, err = s.GetAsset(ctx, org, KindModel, observedModelKey("shared-alias"))
			require.NoError(t, err)
			require.True(t, ok, "ambiguous alias keeps the provider-less key (0-or->1 ⇒ NO attribution)")
		},
	},
	{
		name: "idempotent import repeat is pure unchanged",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org, at := "org-bat8", time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			row := Asset{OrgID: org, AssetKey: ProviderKey("openai"), Kind: KindProvider,
				Payload: []byte(`{"provider":"openai"}`), Source: SourceModelsRegistry,
				Confidence: ConfidenceHigh, FirstSeen: at, LastSeen: at}
			_, err := s.UpsertAssets(ctx, []Asset{row})
			require.NoError(t, err)
			c, err := s.UpsertAssets(ctx, []Asset{row})
			require.NoError(t, err)
			assert.Equal(t, ImportCounts{Unchanged: 1}, c, "identical re-import writes nothing")

			got, ok, err := s.GetAsset(ctx, org, KindProvider, ProviderKey("openai"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.True(t, got.LastSeen.Equal(at), "no phantom last_seen churn")
		},
	},
	{
		name: "same request id redelivery: in-memory dedup now, sql write-once after restart",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat9"
			o, err := NewObserver(s)
			require.NoError(t, err)
			at := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			_, err = o.ObserveEvent(ctx, org, dedupEventAt(at, "bat-dup", "gpt-5"))
			require.NoError(t, err)
			rep, err := o.ObserveEvent(ctx, org, dedupEventAt(at.Add(time.Hour), "bat-dup", "gpt-5"))
			require.NoError(t, err)
			assert.True(t, rep.Deduped, "the observer dedups the redelivery in memory")

			// A restarted observer (new process, empty seen map) re-folds
			// the same delivery with a LATER timestamp: the row survives,
			// last_seen advances (max semantics) — and the payload is
			// write-once: only the touch arm fires, so the ORIGINAL
			// observation content (including its ObservedAt) is what
			// stays, even though the redelivery carries StatusCode 500.
			o2, err := NewObserver(s)
			require.NoError(t, err)
			later := dedupEventAt(at.Add(2*time.Hour), "bat-dup", "gpt-5")
			later.StatusCode = 500
			rep, err = o2.ObserveEvent(ctx, org, later)
			require.NoError(t, err)
			assert.False(t, rep.Deduped)
			assert.Equal(t, ImportCounts{Updated: 3}, rep.Counts, "the touch arm advances last_seen")

			agent, ok, err := s.GetAsset(ctx, org, KindAgent, AgentKey("agent-d1"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.True(t, agent.LastSeen.Equal(at.Add(2*time.Hour)), "refold advances last_seen to the max")
			var ao agentObservation
			require.NoError(t, json.Unmarshal(agent.Payload, &ao))
			assert.True(t, ao.ObservedAt.Equal(at), "payload is write-once: the original observation stays")
		},
	},
	{
		name: "two observations of one agent fold into one asset with max last_seen",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat10"
			o, err := NewObserver(s)
			require.NoError(t, err)
			at1 := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			at2 := at1.Add(90 * time.Minute)
			_, err = o.ObserveEvent(ctx, org, dedupEventAt(at1, "bat-ag1", "gpt-5"))
			require.NoError(t, err)
			_, err = o.ObserveEvent(ctx, org, dedupEventAt(at2, "bat-ag2", "gpt-5"))
			require.NoError(t, err)

			row, ok, err := s.GetAsset(ctx, org, KindAgent, AgentKey("agent-d1"))
			require.NoError(t, err)
			require.True(t, ok)
			assert.True(t, row.FirstSeen.Equal(at1))
			assert.True(t, row.LastSeen.Equal(at2), "last_seen is the max observation")
		},
	},
	{
		name: "url normalization: two spellings one asset, both orders",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			dedupBatteryOneService(t, s, "org-bat11", "uppercase-first")
			dedupBatteryOneService(t, s, "org-bat12", "canonical-first")
		},
	},
	{
		name: "guard-rejected url drops only the service identity",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat13"
			o, err := NewObserver(s)
			require.NoError(t, err)
			e := dedupEventAt(time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), "bat-bad", "gpt-5")
			e.UpstreamURL = "https://admin:secret@up.example.com/v1"
			rep, err := o.ObserveEvent(ctx, org, e)
			require.NoError(t, err)
			assert.Equal(t, 2, rep.Counts.Created, "agent and model still fold")

			rows, _, err := s.ListAssets(ctx, org, ListParams{})
			require.NoError(t, err)
			for _, r := range rows {
				assert.NotEqual(t, KindService, r.Kind, "userinfo url yields no service identity")
			}
		},
	},
	{
		name: "failed write leaves the delivery unmarked and redeliverable (P2, both seams)",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat15"
			pool := s.db

			// The failure seam: a DB whose transactions fail while armed.
			flaky := &failingDB{DB: pool, fail: true}
			o, err := NewObserver(NewStore(flaky))
			require.NoError(t, err)

			// Gateway-event seam: the fold fails, the request-id must NOT
			// be consumed — the same observer redelivers successfully.
			_, err = o.ObserveEvent(ctx, org, dedupEventAt(
				time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), "bat-p2a", "gpt-5"))
			require.Error(t, err, "injected begin failure surfaces")
			flaky.fail = false
			rep, err := o.ObserveEvent(ctx, org, dedupEventAt(
				time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), "bat-p2a", "gpt-5"))
			require.NoError(t, err, "the failed delivery is redeliverable on the SAME observer")
			assert.False(t, rep.Deduped)
			assert.Equal(t, 3, rep.Counts.Created)

			// Sec-events seam: the batch fails, none of its event-ids are
			// consumed — the SAME batch redelivers and folds whole.
			flaky.fail = true
			o2, err := NewObserver(NewStore(flaky))
			require.NoError(t, err)
			batch := []*secevents.Event{{
				EventID:    "sec-p2-1",
				EventType:  "tool.denied",
				OccurredAt: time.Date(2026, 11, 8, 11, 0, 0, 0, time.UTC),
				Identity: secevents.Identity{Agent: secevents.IDRef{
					State: secevents.IDKnown, Value: "agent-p2"}},
			}}
			_, err = o2.ObserveSecEvents(ctx, org, batch)
			require.Error(t, err, "injected begin failure surfaces")
			flaky.fail = false
			rep, err = o2.ObserveSecEvents(ctx, org, batch)
			require.NoError(t, err, "the failed batch is redeliverable on the SAME observer")
			assert.False(t, rep.Deduped)
			assert.Equal(t, 1, rep.Counts.Created)

			// And the next redelivery of the SAME ids IS deduped now.
			rep, err = o2.ObserveSecEvents(ctx, org, batch)
			require.NoError(t, err)
			assert.True(t, rep.Deduped, "successful marks stay taken")
		},
	},
	{
		name: "concurrent duplicate delivery converges to the single-fold row state (P2)",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			ctx := context.Background()
			org := "org-bat16"
			o, err := NewObserver(s)
			require.NoError(t, err)
			at := time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
			ev := dedupEventAt(at, "bat-race", "gpt-5")

			// The P2 mark-after-success window: several goroutines deliver
			// the SAME event on the one process observer. Every fold that
			// slips past the seen map writes; the write-once payload arm
			// and the max last_seen arm make the FINAL row state equal
			// the single-fold state — no lost row, no corrupted payload.
			const n = 8
			var wg sync.WaitGroup
			errs := make(chan error, n)
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := o.ObserveEvent(ctx, org, ev)
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				require.NoError(t, err)
			}

			agent, ok, err := s.GetAsset(ctx, org, KindAgent, AgentKey("agent-d1"))
			require.NoError(t, err)
			require.True(t, ok, "the row is never lost")
			var ao agentObservation
			require.NoError(t, json.Unmarshal(agent.Payload, &ao))
			assert.True(t, ao.ObservedAt.Equal(at), "write-once payload: single-fold content")
			assert.True(t, agent.LastSeen.Equal(at), "max semantics: single-fold last_seen")
			assert.Equal(t, SourceObservation, agent.Source)

			rep, err := o.ObserveEvent(ctx, org, ev)
			require.NoError(t, err)
			assert.True(t, rep.Deduped, "after the race exactly one mark matters")
		},
	},
	{
		name: "documented model-key collision merges instead of hiding",
		run: func(t *testing.T, s *Store) {
			t.Helper()
			// The collision shape itself is pinned by
			// TestDedupDocumentedCollisionModelKey; the battery pins the
			// battery-level consequence: with a catalog wired, the wire
			// name "p/a/b" that RESOLVES converges, and only an
			// unresolved one can ever collide.
			ctx := context.Background()
			org := "org-bat14"
			cat := &dedupCatalog{entries: []provider.ModelCatalogEntry{
				{Provider: "p", Model: "a/b"},
			}}
			o, err := NewObserver(s)
			require.NoError(t, err)
			o.SetCatalog(cat)
			_, err = o.ObserveEvent(ctx, org, dedupEventAt(
				time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC), "bat-c", "p/a/b"))
			require.NoError(t, err)

			_, ok, err := s.GetAsset(ctx, org, KindModel, ModelKey("p", "a/b"))
			require.NoError(t, err)
			require.True(t, ok, "resolving name converges on the canonical key")
			_, ok, err = s.GetAsset(ctx, org, KindModel, observedModelKey("p/a/b") /* same string */)
			require.NoError(t, err)
			assert.True(t, ok, "canonical and observation spellings are one row")

			rows, _, err := s.ListAssets(ctx, org, ListParams{})
			require.NoError(t, err)
			models := 0
			for _, r := range rows {
				if r.Kind == KindModel {
					models++
				}
			}
			assert.Equal(t, 1, models)
		},
	},
}

// dedupBatteryCatalog is the shared battery catalog: gpt-5 with the
// unambiguous alias o5 plus a deliberately ambiguous shared-alias pair.
func dedupBatteryCatalog() []provider.ModelCatalogEntry {
	return []provider.ModelCatalogEntry{
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"o5"}},
		{Provider: "anthropic", Model: "claude-x", Aliases: []string{"shared-alias"}},
		{Provider: "openai", Model: "gpt-5-mini", Aliases: []string{"shared-alias"}},
	}
}

// dedupBatteryOneModelAsset: alias and direct observations of ONE model
// (in the given order) land on exactly one canonical row.
func dedupBatteryOneModelAsset(t *testing.T, s *Store, org, order, first string) {
	t.Helper()
	ctx := context.Background()
	cat := &dedupCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"o5"}},
	}}
	o, err := NewObserver(s)
	require.NoError(t, err)
	o.SetCatalog(cat)

	names := []string{first, "gpt-5"}
	if first == "gpt-5" {
		names = []string{first, "o5"}
	}
	for i, name := range names {
		_, err := o.ObserveEvent(ctx, org, dedupEventAt(
			time.Date(2026, 11, 8, 10, i, 0, 0, time.UTC), org+"-m"+name, name))
		require.NoError(t, err)
	}

	row, ok, err := s.GetAsset(ctx, org, KindModel, ModelKey("openai", "gpt-5"))
	require.NoError(t, err)
	require.True(t, ok, "%s: canonical row exists", order)
	assert.Equal(t, ModelKey("openai", "gpt-5"), row.AssetKey)
	rows, _, err := s.ListAssets(ctx, org, ListParams{})
	require.NoError(t, err)
	models := 0
	for _, r := range rows {
		if r.Kind == KindModel {
			models++
		}
	}
	assert.Equal(t, 1, models, "%s: one model asset under any order", order)
}

// dedupBatteryCrossPlane: the union of the import and observation planes
// over one model — in the given order — is exactly one authoritative row
// with the earliest first_seen and the max last_seen.
func dedupBatteryCrossPlane(t *testing.T, s *Store, org, order string) {
	t.Helper()
	ctx := context.Background()
	cat := &dedupCatalog{entries: []provider.ModelCatalogEntry{
		{Provider: "openai", Model: "gpt-5", Aliases: []string{"o5"}},
	}}
	t1 := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)
	impRow := Asset{OrgID: org, AssetKey: ModelKey("openai", "gpt-5"), Kind: KindModel,
		Payload: []byte(`{"battery":true}`), Source: SourceModelsRegistry,
		Confidence: ConfidenceHigh, FirstSeen: t2, LastSeen: t2}

	observe := func() {
		o, err := NewObserver(s)
		require.NoError(t, err)
		o.SetCatalog(cat)
		_, err = o.ObserveEvent(ctx, org, dedupEventAt(t1, org+"-x", "o5"))
		require.NoError(t, err)
	}

	if order == "import-first" {
		_, err := s.UpsertAssets(ctx, []Asset{impRow})
		require.NoError(t, err)
		observe()
	} else {
		observe()
		_, err := s.UpsertAssets(ctx, []Asset{impRow})
		require.NoError(t, err)
	}

	row, ok, err := s.GetAsset(ctx, org, KindModel, ModelKey("openai", "gpt-5"))
	require.NoError(t, err)
	require.True(t, ok, "%s: one converged row", order)
	assert.Equal(t, SourceModelsRegistry, row.Source, "%s: import authoritative", order)
	assert.JSONEq(t, `{"battery":true}`, string(row.Payload), "%s: import payload wins", order)
	if order == "observation-first" {
		// The row was BORN from the observation: the import upsert keeps
		// the earliest first_seen (LEAST arm).
		assert.True(t, row.FirstSeen.Equal(t1), "%s: earliest first_seen", order)
	} else {
		// The row was BORN from the import: the observation only touches
		// it — first_seen keeps the row's birth instant.
		assert.True(t, row.FirstSeen.Equal(t2), "%s: touch never rewrites first_seen", order)
	}
	assert.True(t, row.LastSeen.Equal(t2), "%s: max last_seen", order)

	rows, _, err := s.ListAssets(ctx, org, ListParams{})
	require.NoError(t, err)
	models := 0
	for _, r := range rows {
		if r.Kind == KindModel {
			models++
		}
	}
	assert.Equal(t, 1, models, "%s: one model asset across planes", order)
}

// dedupBatteryOneService: the same deployment URL observed under two
// spellings (in the given order) is one service asset keyed by the
// canonical form.
func dedupBatteryOneService(t *testing.T, s *Store, org, order string) {
	t.Helper()
	ctx := context.Background()
	o, err := NewObserver(s)
	require.NoError(t, err)
	spellings := [2]string{"HTTPS://Up.Example.COM:443/api", "https://up.example.com/api"}
	if order == "canonical-first" {
		spellings[0], spellings[1] = spellings[1], spellings[0]
	}
	for i, raw := range spellings {
		e := dedupEventAt(time.Date(2026, 11, 8, 10, i, 0, 0, time.UTC), org+"-s"+strconv.Itoa(i), "gpt-5")
		e.UpstreamURL = raw
		_, err := o.ObserveEvent(ctx, org, e)
		require.NoError(t, err)
	}

	row, ok, err := s.GetAsset(ctx, org, KindService, ServiceKey("https://up.example.com/api"))
	require.NoError(t, err)
	require.True(t, ok, "%s: canonical service row exists", order)
	assert.Equal(t, ServiceKey("https://up.example.com/api"), row.AssetKey)

	rows, _, err := s.ListAssets(ctx, org, ListParams{})
	require.NoError(t, err)
	services := 0
	for _, r := range rows {
		if r.Kind == KindService {
			services++
		}
	}
	assert.Equal(t, 1, services, "%s: two spellings, one service asset", order)
}

// TestDedupBattery is the W05-C02 acceptance command:
//
//	go test ./pkg/inventory/ -run TestDedupBattery -count=1
func TestDedupBattery(t *testing.T) {
	s := newTestStore(t)
	for _, row := range dedupBatteryRows {
		t.Run(row.name, func(t *testing.T) {
			row.run(t, s)
		})
	}
}
