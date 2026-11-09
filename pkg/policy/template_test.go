package policy_test

import (
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

// TestTemplate_ExportAsTemplate verifies template creation logic.
func TestTemplate_ExportAsTemplate(t *testing.T) {
	tmpl := policy.ExportAsTemplate(
		"org-acme", "finance-pack", "Indian RBI compliance",
		"sg", "rbi-finance",
		policy.ResidencyRule{
			AllowedJurisdictions: []policy.Region{"IN"},
			DataResidency:        "SG",
		},
	)

	if tmpl.ID != "tpl-sg-rbi-finance" {
		t.Errorf("ID = %q, want tpl-sg-rbi-finance", tmpl.ID)
	}
	if tmpl.Name != "finance-pack" {
		t.Errorf("Name = %q, want finance-pack", tmpl.Name)
	}
	if tmpl.CreatedBy != "org-acme" {
		t.Errorf("CreatedBy = %q, want org-acme", tmpl.CreatedBy)
	}
	if tmpl.Region != "sg" {
		t.Errorf("Region = %v, want sg", tmpl.Region)
	}
	if len(tmpl.Tags) != 0 {
		t.Error("expected empty tags")
	}
}

// TestTemplate_ImportToConfig verifies config export.
func TestTemplate_ImportToConfig(t *testing.T) {
	tmpl := policy.Template{
		ID:          "tpl-sg-test",
		Name:        "test-pack",
		Description: "A test template",
		Region:      "sg",
		PackID:      "test-pack-id",
		Rules: policy.ResidencyRule{
			AllowedJurisdictions: []policy.Region{"US"},
		},
		CreatedBy: "org-test",
		Tags:      []string{"test"},
	}

	cfg, err := tmpl.ImportToConfig()
	if err != nil {
		t.Fatalf("ImportToConfig error: %v", err)
	}

	if cfg["template_id"] != "tpl-sg-test" {
		t.Errorf("template_id = %v, want tpl-sg-test", cfg["template_id"])
	}
	if cfg["source_org"] != "org-test" {
		t.Errorf("source_org = %v, want org-test", cfg["source_org"])
	}
	// AllowedJurisdictions marshals to Go field name (no JSON tags on ResidencyRule).
	aj := cfg["AllowedJurisdictions"].([]interface{})
	if len(aj) != 1 || aj[0] != "US" {
		t.Errorf("AllowedJurisdictions = %v, want [US]", aj)
	}
}
