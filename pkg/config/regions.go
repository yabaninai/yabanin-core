package config

// RegionConfig describes one regional deployment's data-plane endpoints.
// Used for active-active multi-region routing (PB2).
type RegionConfig struct {
	// Name is the short lowercase id ("sg","in","eu"). Must match a key in
	// the Regions map.
	Name string `yaml:"name"`
	// Country is the ISO-3166-1 alpha-2 code ("SG","IN","DE").
	Country string `yaml:"country"`
	// PGURI is the regional Postgres connection string.
	PGURI string `yaml:"pg_uri"`
	// RedisAddr is the regional Redis host:port.
	RedisAddr string `yaml:"redis_addr"`
	// KMSKeyID is the cloud-KMS key ARN/ID for this region's envelope DEK.
	KMSKeyID string `yaml:"kms_key_id"`
	// GatewayURL is the peer gateway base URL (for health-check + failover).
	GatewayURL string `yaml:"gateway_url"`
	// Priority orders failover: lower = preferred for non-pinned orgs.
	Priority int `yaml:"priority"`
}

// RegionMap holds all known regions keyed by short name.
type RegionMap map[string]RegionConfig

// Lookup returns the RegionConfig for a region name; ok=false when unknown.
func (m RegionMap) Lookup(name string) (RegionConfig, bool) {
	r, ok := m[name]
	return r, ok
}

// SortedByPriority returns regions ordered by Priority ascending (failover
// order). Uses insertion sort — N is tiny (3 regions).
func (m RegionMap) SortedByPriority() []RegionConfig {
	out := make([]RegionConfig, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Priority < out[j-1].Priority; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
