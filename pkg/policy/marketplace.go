// Package policy provides a consortium model for orgs to share anonymized policy templates.
package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Consortium represents a group of orgs that share policy templates.
type Consortium struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Members     []string  `json:"members"` // org_ids
	CreatedAt   time.Time `json:"created_at"`
}

// TemplateMarketplace provides a marketplace for browsing and subscribing to shared templates.
type TemplateMarketplace struct {
	mu         sync.RWMutex
	store      *pgxpool.Pool
	localTmpls map[string]Template // orgID -> templates they've created
	subscribed map[string][]string // orgID -> template IDs they subscribe to
}

// NewTemplateMarketplace creates a new marketplace.
func NewTemplateMarketplace(pool *pgxpool.Pool) *TemplateMarketplace {
	return &TemplateMarketplace{
		store:      pool,
		localTmpls: make(map[string]Template),
		subscribed: make(map[string][]string),
	}
}

// RegisterLocal registers a local org's policy template for sharing.
func (m *TemplateMarketplace) RegisterLocal(orgID string, tmpl Template) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.localTmpls[orgID] = tmpl
	return nil
}

// ListAvailable returns all public templates from other orgs.
func (m *TemplateMarketplace) ListAvailable(ctx context.Context) ([]Template, error) {
	rows, err := m.store.Query(ctx, `
		SELECT id, name, description, region, pack_id, rules, created_by, created_at, tags
		FROM policy_templates
		WHERE visible = true
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list templates: %w", err)
	}
	defer rows.Close()

	var tmpls []Template
	for rows.Next() {
		var id, name, desc, region, packID, createdBy string
		var rulesBytes, createdAtStr []byte
		var tagsJSON []byte
		if err := rows.Scan(&id, &name, &desc, &region, &packID, &rulesBytes, &createdBy, &createdAtStr, &tagsJSON); err != nil {
			continue
		}

		var rules ResidencyRule
		if err := json.Unmarshal(rulesBytes, &rules); err != nil {
			continue
		}

		var tags []string
		_ = json.Unmarshal(tagsJSON, &tags) // tags are optional

		tmpl := Template{
			ID:          id,
			Name:        name,
			Description: desc,
			Region:      Region(region),
			PackID:      packID,
			Rules:       rules,
			CreatedBy:   createdBy,
			Tags:        tags,
		}
		if createdAtStr != nil {
			tmpl.CreatedAt, _ = time.Parse(time.RFC3339, string(createdAtStr))
		}

		tmpls = append(tmpls, tmpl)
	}
	return tmpls, nil
}

// Subscribe adds a template to an org's subscription list.
func (m *TemplateMarketplace) Subscribe(orgID, templateID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, id := range m.subscribed[orgID] {
		if id == templateID {
			return nil // already subscribed
		}
	}
	m.subscribed[orgID] = append(m.subscribed[orgID], templateID)
	return nil
}

// GetSubscribed returns the template IDs an org has subscribed to.
func (m *TemplateMarketplace) GetSubscribed(orgID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]string, len(m.subscribed[orgID]))
	copy(result, m.subscribed[orgID])
	return result
}

// ApplySubscribed returns the config from subscribed templates.
func (m *TemplateMarketplace) ApplySubscribed(orgID string) ([]map[string]any, error) {
	ids := m.GetSubscribed(orgID)
	if len(ids) == 0 {
		return nil, nil
	}

	// Resolve subscriptions against localTmpls under the lock: Subscribe may
	// append concurrently, and RegisterLocal may rewrite localTmpls while we
	// look entries up. Templates are copied out, so ImportToConfig runs on
	// private values after the lock is released.
	m.mu.RLock()
	templates := make([]Template, 0, len(ids))
	for _, id := range ids {
		if t, ok := m.localTmpls[id]; ok {
			templates = append(templates, t)
		}
	}
	m.mu.RUnlock()

	results := make([]map[string]any, 0, len(ids))
	for _, t := range templates {
		cfg, err := t.ImportToConfig()
		if err != nil {
			continue
		}
		results = append(results, cfg)
	}

	return results, nil
}
