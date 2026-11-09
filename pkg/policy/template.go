// Package policy provides a template system for sharing policy packs between orgs.
package policy

import (
	"encoding/json"
	"fmt"
	"time"
)

// Template represents a shareable policy-pack template.
type Template struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Region      Region        `json:"region"`
	PackID      string        `json:"pack_id"`
	Rules       ResidencyRule `json:"rules"`
	CreatedBy   string        `json:"created_by"` // org_id of creator
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAT   time.Time     `json:"updated_at"`
	Tags        []string      `json:"tags,omitempty"` // e.g., ["finance", "rbi", "india"]
}

// ExportAsTemplate converts an org's policy pack config into a shareable template.
func ExportAsTemplate(orgID, name, description string, region Region, packID string, rules ResidencyRule) Template {
	return Template{
		ID:          fmt.Sprintf("tpl-%s-%s", region, packID),
		Name:        name,
		Description: description,
		Region:      region,
		PackID:      packID,
		Rules:       rules,
		CreatedBy:   orgID,
		CreatedAt:   time.Now().UTC(),
		UpdatedAT:   time.Now().UTC(),
	}
}

// ImportToConfig applies a template to an org's policy configuration.
func (t *Template) ImportToConfig() (map[string]any, error) {
	data, err := json.Marshal(t.Rules)
	if err != nil {
		return nil, fmt.Errorf("marshal rules: %w", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal rules: %w", err)
	}
	cfg["template_id"] = t.ID
	cfg["source_org"] = t.CreatedBy
	return cfg, nil
}
