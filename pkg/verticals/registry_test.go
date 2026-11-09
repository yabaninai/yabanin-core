package verticals

import (
	"context"
	"testing"

	"github.com/reireirei/yabanin/pkg/policy"
)

// TestRegistry registers and retrieves verticals.
func TestRegistry(t *testing.T) {
	reg := NewRegistry()

	// Register a test vertical.
	testV := &testVertical{id: "test_v1"}
	if err := reg.Register(testV); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Retrieve and verify.
	got := reg.Get("test_v1")
	if got == nil {
		t.Fatal("expected test_v1, got nil")
	}
	if got.ID() != "test_v1" {
		t.Errorf("expected test_v1, got %s", got.ID())
	}

	// Duplicate register should fail.
	if err := reg.Register(testV); err == nil {
		t.Error("expected duplicate register to fail")
	}

	// List should include our vertical.
	list := reg.List()
	found := false
	for _, id := range list {
		if id == "test_v1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("list did not contain test_v1")
	}

	// Unregister.
	if err := reg.Unregister("test_v1"); err != nil {
		t.Fatalf("unregister: %v", err)
	}
	if reg.Get("test_v1") != nil {
		t.Error("expected nil after unregister")
	}
}

// TestRegistryEnableFor tests org-level enable/disable.
func TestRegistryEnableFor(t *testing.T) {
	reg := NewRegistry()

	testV := &testVertical{id: "v1"}
	if err := reg.Register(testV); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Enable for org.
	if err := reg.EnableFor("org-1", "v1"); err != nil {
		t.Fatalf("enable: %v", err)
	}

	enabled := reg.EnabledFor("org-1")
	if len(enabled) != 1 || enabled[0] != "v1" {
		t.Errorf("expected [v1], got %v", enabled)
	}

	// Double enable should be no-op.
	if err := reg.EnableFor("org-1", "v1"); err != nil {
		t.Error("expected double enable to succeed")
	}

	// Disable.
	if err := reg.DisableFor("org-1", "v1"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if len(reg.EnabledFor("org-1")) != 0 {
		t.Error("expected empty after disable")
	}

	// Disable non-existent should fail.
	if err := reg.DisableFor("org-1", "v1"); err == nil {
		t.Error("expected error disabling non-enabled vertical")
	}
}

// TestRegistryPreTransform runs Transform on all enabled verticals.
func TestRegistryPreTransform(t *testing.T) {
	reg := NewRegistry()

	testV := &testVertical{id: "v1"}
	if err := reg.Register(testV); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := reg.EnableFor("org-1", "v1"); err != nil {
		t.Fatalf("enable: %v", err)
	}

	ctx := context.Background()
	in := Request{
		OrgID:          "org-1",
		ModelRequested: "gpt-4o",
		Prompt:         "hello",
		Metadata:       make(map[string]string),
	}

	newCtx, newIn, err := reg.PreTransform(ctx, "org-1", in)
	if err != nil {
		t.Fatalf("pre-transform: %v", err)
	}

	// Verify the test vertical's Transform was called.
	if newIn.Metadata["v1_transformed"] != "true" {
		t.Error("expected v1_transformed=true")
	}
	_ = newCtx
}

// testVertical is a minimal Vertical implementation for testing.
type testVertical struct {
	id string
}

func (v *testVertical) ID() string            { return v.id }
func (v *testVertical) Region() policy.Region { return "GLOBAL" }
func (v *testVertical) Name() string          { return "Test Vertical" }
func (v *testVertical) Description() string   { return "Test vertical for unit tests" }
func (v *testVertical) DefaultRules() policy.ResidencyRule {
	return policy.ResidencyRule{
		AllowedJurisdictions: []policy.Region{"GLOBAL"},
		AllowedModelFamilies: []string{"*"},
		DataResidency:        "GLOBAL",
	}
}
func (v *testVertical) Evaluate(_ context.Context, in policy.EvalContext, overrideRules *policy.ResidencyRule) policy.Decision {
	return policy.Decision{Allowed: true, Region: "GLOBAL", PackID: v.id}
}
func (v *testVertical) Transform(ctx context.Context, in Request) (context.Context, Response, error) {
	in.Metadata["v1_transformed"] = "true"
	return ctx, Response{Model: in.ModelRequested, Prompt: in.Prompt}, nil
}
func (v *testVertical) Report(_ context.Context, orgID, from, until, mode string) ([]byte, error) {
	return []byte(`{"vertical":"test","org_id":"` + orgID + `"}`), nil
}
