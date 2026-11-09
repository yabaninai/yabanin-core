package policy_test

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

// TestMarketplace_LocalRegistration verifies RegisterLocal.
func TestMarketplace_LocalRegistration(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil) // nil pool is fine for local-only tests

	tmpl := policy.ExportAsTemplate("org-acme", "finance-pack", "RBI compliance", "sg", "rbi-finance", policy.ResidencyRule{AllowedJurisdictions: []policy.Region{"US"}})
	if err := mp.RegisterLocal("org-acme", tmpl); err != nil {
		t.Fatalf("RegisterLocal error: %v", err)
	}

	subscribed := mp.GetSubscribed("org-acme")
	if len(subscribed) != 0 {
		t.Errorf("expected no subscriptions, got %d", len(subscribed))
	}
}

// TestMarketplace_Subscribe verifies Subscribe + GetSubscribed.
func TestMarketplace_Subscribe(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)

	// Subscribe to two templates.
	if err := mp.Subscribe("org-acme", "tpl-in-finance"); err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}
	if err := mp.Subscribe("org-acme", "tpl-sg-health"); err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}

	subscribed := mp.GetSubscribed("org-acme")
	if len(subscribed) != 2 {
		t.Fatalf("GetSubscribed = %d, want 2", len(subscribed))
	}

	// Duplicate subscribe should be a no-op.
	if err := mp.Subscribe("org-acme", "tpl-in-finance"); err != nil {
		t.Fatalf("duplicate Subscribe error: %v", err)
	}
	subscribed = mp.GetSubscribed("org-acme")
	if len(subscribed) != 2 {
		t.Errorf("after duplicate subscribe, got %d, want 2", len(subscribed))
	}

	// Different org gets empty list.
	orgB := mp.GetSubscribed("org-bob")
	if len(orgB) != 0 {
		t.Errorf("org-bob got %d, want 0", len(orgB))
	}
}

// TestMarketplace_ApplySubscribed verifies ApplySubscribed with local templates.
// Note: RegisterLocal uses orgID as key, and ApplySubscribed looks up subscribed IDs in localTmpls.
// So subscribing to an orgID that registered a template will find it.
func TestMarketplace_ApplySubscribed(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)

	// Register a local template under org-acme.
	tmpl := policy.ExportAsTemplate("org-acme", "finance-pack", "RBI compliance", "sg", "rbi-finance", policy.ResidencyRule{AllowedJurisdictions: []policy.Region{"US"}})
	if err := mp.RegisterLocal("org-acme", tmpl); err != nil {
		t.Fatalf("RegisterLocal error: %v", err)
	}

	// Subscribe to the org that registered the template.
	if err := mp.Subscribe("org-bob", "org-acme"); err != nil {
		t.Fatalf("Subscribe error: %v", err)
	}

	cfgs, err := mp.ApplySubscribed("org-bob")
	if err != nil {
		t.Fatalf("ApplySubscribed error: %v", err)
	}

	if len(cfgs) != 1 {
		t.Fatalf("ApplySubscribed returned %d configs, want 1", len(cfgs))
	}

	if cfgs[0]["template_id"] != "tpl-sg-rbi-finance" {
		t.Errorf("template_id = %v, want tpl-sg-rbi-finance", cfgs[0]["template_id"])
	}
}

// TestMarketplace_ApplySubscribed_Empty verifies empty case.
func TestMarketplace_ApplySubscribed_Empty(t *testing.T) {
	mp := policy.NewTemplateMarketplace(nil)
	cfgs, err := mp.ApplySubscribed("org-nonexistent")
	if err != nil {
		t.Fatalf("ApplySubscribed error: %v", err)
	}
	if cfgs != nil {
		t.Errorf("expected nil for empty subscriptions, got %d items", len(cfgs))
	}
}

// TestMarketplace_ListAvailable_WithoutDB verifies that ListAvailable panics (nil pool) —
// callers must guard with pool != nil before calling.
func TestMarketplace_ListAvailable_WithoutDB(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic from nil pool")
		}
	}()

	mp := policy.NewTemplateMarketplace(nil) // nil pool = no DB
	_, _ = mp.ListAvailable(context.Background())
}
