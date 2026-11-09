package cli

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	apierrors "github.com/reireirei/yabanin/pkg/errors"
)

// modelEntry is one enabled model advertised by GET /v1/models.
// AliasOf is reserved for RM-14 and stays empty until aliases exist.
type modelEntry struct {
	ID          string
	DisplayName string
	Provider    string
	CreatedAt   time.Time
	AliasOf     string
}

type modelLister interface {
	ListEnabledModels(ctx context.Context) ([]modelEntry, error)
}

type staticModelLister struct {
	entry modelEntry
}

func (s staticModelLister) ListEnabledModels(context.Context) ([]modelEntry, error) {
	if s.entry.ID == "" {
		return []modelEntry{}, nil
	}
	return []modelEntry{s.entry}, nil
}

type pgModelLister struct {
	query   func(ctx context.Context) ([]modelEntry, error)
	now     func() time.Time
	mu      sync.Mutex
	entries []modelEntry
	expires time.Time
	filled  bool
}

func newPGModelLister(pool *pgxpool.Pool) *pgModelLister {
	return &pgModelLister{
		query: func(ctx context.Context) ([]modelEntry, error) {
			return queryEnabledModels(ctx, pool)
		},
		now: time.Now,
	}
}

const modelListCacheTTL = 30 * time.Second

const enabledModelsSQL = `
SELECT model_name, display_name, provider, created_at
FROM models_registry
WHERE enabled = true
ORDER BY model_name`

func queryEnabledModels(ctx context.Context, pool *pgxpool.Pool) ([]modelEntry, error) {
	rows, err := pool.Query(ctx, enabledModelsSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := make([]modelEntry, 0)
	for rows.Next() {
		var entry modelEntry
		if err := rows.Scan(&entry.ID, &entry.DisplayName, &entry.Provider, &entry.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	aliases, err := queryModelAliases(ctx, pool, list)
	if err != nil {
		return nil, err
	}
	return append(list, aliases...), nil
}

func queryModelAliases(ctx context.Context, pool *pgxpool.Pool, models []modelEntry) ([]modelEntry, error) {
	rows, err := pool.Query(ctx, `SELECT alias, target_model, created_at FROM model_aliases ORDER BY alias`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	providerOf := make(map[string]string, len(models))
	for _, m := range models {
		providerOf[m.ID] = m.Provider
	}
	var out []modelEntry
	for rows.Next() {
		var alias, target string
		var created time.Time
		if err := rows.Scan(&alias, &target, &created); err != nil {
			return nil, err
		}
		out = append(out, modelEntry{
			ID:          alias,
			DisplayName: target,
			Provider:    providerOf[target],
			CreatedAt:   created,
			AliasOf:     target,
		})
	}
	return out, rows.Err()
}

func (p *pgModelLister) ListEnabledModels(ctx context.Context) ([]modelEntry, error) {
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	p.mu.Lock()
	if p.filled && now().Before(p.expires) {
		out := append([]modelEntry(nil), p.entries...)
		p.mu.Unlock()
		return out, nil
	}
	p.mu.Unlock()

	list, err := p.query(ctx)
	if err != nil {
		return nil, err
	}
	if list == nil {
		list = []modelEntry{}
	}
	p.mu.Lock()
	p.entries = list
	p.filled = true
	p.expires = now().Add(modelListCacheTTL)
	out := append([]modelEntry(nil), p.entries...)
	p.mu.Unlock()
	return out, nil
}

func (gw *gateway) bindModelLister(pool *pgxpool.Pool) {
	if pool == nil {
		name := gw.cfg.FallbackModel
		gw.models = staticModelLister{entry: modelEntry{
			ID:          name,
			DisplayName: name,
			Provider:    "yabanin",
			CreatedAt:   time.Now().UTC(),
		}}
		return
	}
	gw.models = newPGModelLister(pool)
}

func (gw *gateway) listModels(w http.ResponseWriter, r *http.Request) {
	visible, ok := gw.modelsForRequest(w, r)
	if !ok {
		return
	}
	limit := modelsLimit(r)
	hasMore := len(visible) > limit
	if len(visible) > limit {
		visible = visible[:limit]
	}
	if anthropicModels(r) {
		writeAnthropicModelList(w, visible, hasMore)
		return
	}
	writeOpenAIModelList(w, visible)
}

func (gw *gateway) getModel(w http.ResponseWriter, r *http.Request) {
	visible, ok := gw.modelsForRequest(w, r)
	if !ok {
		return
	}
	id := chi.URLParam(r, "id")
	for _, entry := range visible {
		if entry.ID == id {
			if anthropicModels(r) {
				writeJSON(w, http.StatusOK, anthropicModel(entry))
				return
			}
			writeJSON(w, http.StatusOK, openAIModel(entry))
			return
		}
	}
	apierrors.Write(w, http.StatusNotFound, apierrors.ErrorCodeNotFound, "model not found")
}

func (gw *gateway) modelsForRequest(w http.ResponseWriter, r *http.Request) ([]modelEntry, bool) {
	if gw.models == nil {
		apierrors.Write(w, http.StatusServiceUnavailable, "models_unavailable", "model list is not configured")
		return nil, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	all, err := gw.models.ListEnabledModels(ctx)
	if err != nil {
		apierrors.Write(w, http.StatusServiceUnavailable, "models_unavailable", "model list temporarily unavailable")
		return nil, false
	}
	if gw.wl == nil {
		return all, true
	}
	apiKeyID := r.Header.Get("X-API-Key-Id")
	teamID := r.Header.Get("X-Team-Id")
	visible := make([]modelEntry, 0, len(all))
	for _, entry := range all {
		name := entry.ID
		if entry.AliasOf != "" {
			name = entry.AliasOf
		}
		allowed, err := gw.wl.Check(ctx, apiKeyID, teamID, name)
		if err != nil {
			apierrors.Write(w, http.StatusServiceUnavailable, "whitelist_check_unavailable",
				"whitelist check temporarily unavailable")
			return nil, false
		}
		if allowed {
			visible = append(visible, entry)
		}
	}
	return visible, true
}

func modelsLimit(r *http.Request) int {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return 1000
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 1000 {
		return 1000
	}
	return n
}

func anthropicModels(r *http.Request) bool {
	return r.Header.Get("anthropic-version") != ""
}

func ownedBy(provider string) string {
	if provider == "" {
		return "yabanin"
	}
	return provider
}

type openAIModelObject struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type openAIModelList struct {
	Object string              `json:"object"`
	Data   []openAIModelObject `json:"data"`
}

func openAIModel(entry modelEntry) openAIModelObject {
	return openAIModelObject{
		ID:      entry.ID,
		Object:  "model",
		Created: entry.CreatedAt.Unix(),
		OwnedBy: ownedBy(entry.Provider),
	}
}

func writeOpenAIModelList(w http.ResponseWriter, entries []modelEntry) {
	data := make([]openAIModelObject, 0, len(entries))
	for _, entry := range entries {
		data = append(data, openAIModel(entry))
	}
	writeJSON(w, http.StatusOK, openAIModelList{Object: "list", Data: data})
}

type anthropicModelObject struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
}

type anthropicModelList struct {
	Data    []anthropicModelObject `json:"data"`
	HasMore bool                   `json:"has_more"`
	FirstID string                 `json:"first_id"`
	LastID  string                 `json:"last_id"`
}

func anthropicModel(entry modelEntry) anthropicModelObject {
	return anthropicModelObject{
		Type:        "model",
		ID:          entry.ID,
		DisplayName: entry.DisplayName,
		CreatedAt:   entry.CreatedAt.UTC().Format(time.RFC3339),
	}
}

func writeAnthropicModelList(w http.ResponseWriter, entries []modelEntry, hasMore bool) {
	data := make([]anthropicModelObject, 0, len(entries))
	for _, entry := range entries {
		data = append(data, anthropicModel(entry))
	}
	list := anthropicModelList{Data: data, HasMore: hasMore}
	if len(data) > 0 {
		list.FirstID = data[0].ID
		list.LastID = data[len(data)-1].ID
	}
	writeJSON(w, http.StatusOK, list)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
