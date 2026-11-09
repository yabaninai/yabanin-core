package config

import (
	"path/filepath"
	"testing"
)

// TestNewMLPackConfig pins the model-pack env surface (YABANIN_ML_PACK_DIR,
// lazy read like the embedder config); the zero value is the minimal mode —
// no pack, nothing verified, nothing downloaded.
func TestNewMLPackConfig(t *testing.T) {
	t.Run("unset env is the minimal mode", func(t *testing.T) {
		t.Setenv("YABANIN_ML_PACK_DIR", "")
		cfg := NewMLPackConfig()
		if cfg.Dir != "" {
			t.Errorf("Dir = %q, want empty", cfg.Dir)
		}
		gw := Gateway{}
		if got := gw.MLPack().Dir; got != "" {
			t.Errorf("Gateway.MLPack().Dir = %q, want empty", got)
		}
	})
	t.Run("set env is passed through", func(t *testing.T) {
		t.Setenv("YABANIN_ML_PACK_DIR", "/var/lib/yabanin/packs/bge")
		if cfg := NewMLPackConfig(); cfg.Dir != "/var/lib/yabanin/packs/bge" {
			t.Errorf("Dir = %q, want /var/lib/yabanin/packs/bge", cfg.Dir)
		}
	})
	t.Run("surrounding whitespace is trimmed", func(t *testing.T) {
		t.Setenv("YABANIN_ML_PACK_DIR", "  /packs/e5  ")
		if cfg := NewMLPackConfig(); cfg.Dir != "/packs/e5" {
			t.Errorf("Dir = %q, want trimmed /packs/e5", cfg.Dir)
		}
	})
}

// TestMLPackConfigEnabled pins the explicit-activation predicate: minimal
// mode is exactly the empty Dir (after the env trim), and activation is
// explicit — there is no discovery or download path. A set-but-broken pack
// is NOT silently degraded: Enabled stays true and the wiring-site
// verification (pkg/mlpack.AttachDir) refuses startup, so a wrong digest or
// a missing runtime artifact can never yield a false ready.
func TestMLPackConfigEnabled(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want bool
	}{
		{"unset env is minimal mode", "", false},
		{"whitespace-only env is minimal mode", "   ", false},
		{"set env is an explicit activation", "/var/lib/yabanin/packs/bge", true},
		{"whitespace around the path still activates (trim)", "  /packs/e5  ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YABANIN_ML_PACK_DIR", tc.env)
			cfg := NewMLPackConfig()
			if got := cfg.Enabled(); got != tc.want {
				t.Errorf("Enabled(Dir=%q) = %v, want %v", cfg.Dir, got, tc.want)
			}
			if got := (Gateway{}).MLPack().Enabled(); got != tc.want {
				t.Errorf("Gateway.MLPack().Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMLPackConfigManifestPath pins the JSON digest manifest location inside
// the pack dir (pack.json — the same file pkg/mlpack.Load reads).
func TestMLPackConfigManifestPath(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want string
	}{
		{"minimal mode has no dir prefix", "", filepath.Join("", "pack.json")},
		{"manifest sits inside the pack dir", "/var/lib/yabanin/packs/bge", "/var/lib/yabanin/packs/bge/pack.json"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := MLPackConfig{Dir: tc.dir}
			if got := cfg.ManifestPath(); got != tc.want {
				t.Errorf("ManifestPath(Dir=%q) = %q, want %q", tc.dir, got, tc.want)
			}
		})
	}
}

// TestGuardPackVerifyConfig pins the lazy env resolution of the static
// pack-signature key set (guardpack-sig.v1): unset/blank env means no
// verifier (unsigned packs load, signed packs fail closed at wiring).
func TestGuardPackVerifyConfig(t *testing.T) {
	t.Run("unset env configures no verifier", func(t *testing.T) {
		t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR", "")
		t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS", "")
		cfg := Gateway{}.GuardPackVerify()
		if cfg.KeysDir != "" || len(cfg.InlineKeys) != 0 {
			t.Errorf("GuardPackVerify() = %#v, want zero value", cfg)
		}
	})
	t.Run("dir and inline entries resolve", func(t *testing.T) {
		t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR", " /keys/guard-packs ")
		t.Setenv("YABANIN_GUARD_PACK_VERIFY_KEYS", " release-2026=abc , , second=def ")
		cfg := Gateway{}.GuardPackVerify()
		if cfg.KeysDir != "/keys/guard-packs" {
			t.Errorf("KeysDir = %q, want trimmed dir", cfg.KeysDir)
		}
		if len(cfg.InlineKeys) != 2 || cfg.InlineKeys[0] != "release-2026=abc" || cfg.InlineKeys[1] != "second=def" {
			t.Errorf("InlineKeys = %#v, want two trimmed entries", cfg.InlineKeys)
		}
	})
}
