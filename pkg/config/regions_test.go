package config

import (
	"os"
	"strings"
	"testing"
)

func TestRegionMap_Lookup(t *testing.T) {
	m := RegionMap{
		"sg": {Name: "sg", Country: "SG", Priority: 1},
		"in": {Name: "in", Country: "IN", Priority: 2},
	}
	r, ok := m.Lookup("in")
	if !ok {
		t.Fatal("expected in to be found")
	}
	if r.Country != "IN" {
		t.Errorf("expected IN, got %s", r.Country)
	}
	if _, ok := m.Lookup("xx"); ok {
		t.Fatal("expected xx to be unknown")
	}
}

func TestRegionMap_SortedByPriority(t *testing.T) {
	m := RegionMap{
		"sg": {Name: "sg", Priority: 1},
		"in": {Name: "in", Priority: 2},
		"eu": {Name: "eu", Priority: 3},
	}
	got := m.SortedByPriority()
	if len(got) != 3 {
		t.Fatalf("expected 3 regions, got %d", len(got))
	}
	want := []string{"sg", "in", "eu"}
	for i, r := range got {
		if r.Name != want[i] {
			t.Errorf("position %d: expected %s, got %s", i, want[i], r.Name)
		}
	}
}

func TestGateway_RegionMustBeInRegions(t *testing.T) {
	cfg := DefaultGateway()
	cfg.PGURI = "postgres://u:p@h/db"
	cfg.CacheHMACSecret = "s"
	cfg.Region = "sg"
	cfg.Regions = RegionMap{
		"in": {Name: "in", Priority: 1},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error: region not in map")
	}
	if !strings.Contains(err.Error(), "not found in regions map") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGateway_EmptyRegions_BackwardCompat(t *testing.T) {
	cfg := DefaultGateway()
	cfg.PGURI = "postgres://u:p@h/db"
	cfg.CacheHMACSecret = "s"
	cfg.Region = ""
	cfg.Regions = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty Regions must be backward-compatible, got: %v", err)
	}
}

func TestLoad_RegionsFromYAML(t *testing.T) {
	yaml := `
gateway:
  listen_address: ":8082"
  provider: "localhost:8081"
  pg_uri: "postgres://u:p@h/db"
  cache_hmac_secret: "s"
  region: sg
  regions:
    sg: { name: sg, country: SG, priority: 1 }
    in: { name: in, country: IN, priority: 2 }
`
	path := tempFile(t, yaml)
	defer func() { _ = os.Remove(path) }()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Gateway.Region != "sg" {
		t.Errorf("expected region sg, got %q", cfg.Gateway.Region)
	}
	if len(cfg.Gateway.Regions) != 2 {
		t.Fatalf("expected 2 regions, got %d", len(cfg.Gateway.Regions))
	}
	sorted := cfg.Gateway.Regions.SortedByPriority()
	if sorted[0].Name != "sg" || sorted[1].Name != "in" {
		t.Errorf("unexpected order: %s %s", sorted[0].Name, sorted[1].Name)
	}
	if err := cfg.Gateway.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func tempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "cfg-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return f.Name()
}
