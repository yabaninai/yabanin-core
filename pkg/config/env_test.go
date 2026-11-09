package config

import (
	"os"
	"path/filepath"
	"testing"
)

// unset is a tiny wrapper over t.Setenv for the "must be absent" case:
// t.Setenv cannot express unset, so we restore the previous state manually.
func unset(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		prev, had := os.LookupEnv(key)
		if had {
			if err := os.Unsetenv(key); err != nil {
				t.Fatalf("unset %s: %v", key, err)
			}
		}
		t.Cleanup(func() {
			if had {
				_ = os.Setenv(key, prev)
			}
		})
	}
}

func TestPathFromEnv(t *testing.T) {
	unset(t, "YABANIN_CONFIG")
	if got := PathFromEnv(); got != "" {
		t.Errorf("PathFromEnv() = %q, want empty", got)
	}
	t.Setenv("YABANIN_CONFIG", "/etc/yabanin/config.yaml")
	if got := PathFromEnv(); got != "/etc/yabanin/config.yaml" {
		t.Errorf("PathFromEnv() = %q, want /etc/yabanin/config.yaml", got)
	}
}

func TestLicenseFromEnv(t *testing.T) {
	unset(t, "YABANIN_LICENSE_FILE", "YABANIN_LICENSE_ROOT_PUBKEY", "YABANIN_LICENSE_CRL_FILE", "YABANIN_LICENSE_INTERMEDIATE_CERT")
	t.Setenv("YABANIN_LICENSE_FILE", "/run/secrets/license.jwt")
	t.Setenv("YABANIN_LICENSE_ROOT_PUBKEY", "aabbcc")
	t.Setenv("YABANIN_LICENSE_CRL_FILE", "/run/secrets/crl.pem")
	t.Setenv("YABANIN_LICENSE_INTERMEDIATE_CERT", "/run/secrets/intermediate.json")
	got := LicenseFromEnv()
	if got.File != "/run/secrets/license.jwt" || got.RootPubKey != "aabbcc" ||
		got.CRLFile != "/run/secrets/crl.pem" || got.IntermediateCert != "/run/secrets/intermediate.json" {
		t.Errorf("LicenseFromEnv() = %+v", got)
	}
}

func TestMigrateFromEnv(t *testing.T) {
	t.Run("direct value wins", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_PG_URI_FILE", "YABANIN_REGION")
		t.Setenv("YABANIN_PG_URI", "postgres://direct")
		t.Setenv("YABANIN_REGION", "eu")
		got := MigrateFromEnv()
		if got.PGURI != "postgres://direct" || got.Region != "eu" {
			t.Errorf("MigrateFromEnv() = %+v", got)
		}
	})
	t.Run("empty direct falls back to _FILE with trim", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_PG_URI_FILE", "YABANIN_REGION")
		file := filepath.Join(t.TempDir(), "pguri")
		if err := os.WriteFile(file, []byte("  postgres://fromfile\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("YABANIN_PG_URI_FILE", file)
		got := MigrateFromEnv()
		if got.PGURI != "postgres://fromfile" {
			t.Errorf("PGURI = %q, want postgres://fromfile", got.PGURI)
		}
	})
	t.Run("missing file keeps empty", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_PG_URI_FILE", "YABANIN_REGION")
		t.Setenv("YABANIN_PG_URI_FILE", filepath.Join(t.TempDir(), "nonexistent"))
		if got := MigrateFromEnv(); got.PGURI != "" {
			t.Errorf("PGURI = %q, want empty", got.PGURI)
		}
	})
}

func TestRollupFromEnv(t *testing.T) {
	unset(t, "YABANIN_ROLLUPS", "YABANIN_ROLLUP_BACKFILL")
	got := RollupFromEnv()
	if got.Disabled || got.Backfill != "" {
		t.Errorf("RollupFromEnv() = %+v, want defaults off", got)
	}
	t.Setenv("YABANIN_ROLLUPS", "0")
	t.Setenv("YABANIN_ROLLUP_BACKFILL", " 2026-01-01T00:00:00Z,2026-02-01T00:00:00Z ")
	got = RollupFromEnv()
	if !got.Disabled {
		t.Error("Disabled = false with YABANIN_ROLLUPS=0, want true")
	}
	want := "2026-01-01T00:00:00Z,2026-02-01T00:00:00Z"
	if got.Backfill != want {
		t.Errorf("Backfill = %q, want %q", got.Backfill, want)
	}
}

func TestDebugLogResponse(t *testing.T) {
	unset(t, "YABANIN_DEBUG_LOG_RESPONSE")
	if DebugLogResponse() {
		t.Error("DebugLogResponse() = true when unset, want false")
	}
	for _, v := range []string{"true", "TRUE", "1", "yes"} {
		t.Setenv("YABANIN_DEBUG_LOG_RESPONSE", v)
		if got := DebugLogResponse(); got != (v == "true") {
			t.Errorf("DebugLogResponse() with %q = %v", v, got)
		}
	}
}

func TestLogRetentionDays(t *testing.T) {
	cases := []struct {
		name  string
		value string
		unset bool
		days  int
		ok    bool
	}{
		{"unset", "", true, 0, false},
		{"empty", "", false, 0, false},
		{"malformed", "soon", false, 0, false},
		{"zero", "0", false, 0, false},
		{"negative", "-7", false, 0, false},
		{"positive", "30", false, 30, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unset(t, "YABANIN_LOG_RETENTION_DAYS")
			if !tc.unset {
				t.Setenv("YABANIN_LOG_RETENTION_DAYS", tc.value)
			}
			days, ok := LogRetentionDays()
			if days != tc.days || ok != tc.ok {
				t.Errorf("LogRetentionDays() = (%d, %v), want (%d, %v)", days, ok, tc.days, tc.ok)
			}
		})
	}
}

func TestSimpleStringFacets(t *testing.T) {
	unset(t, "YABANIN_ADMIN_API_KEY", "YABANIN_ENV", "YABANIN_ADMIN_PASSWORD_FILE", "EE_INTERNAL_TOKEN")
	if got := InternalAdminKey(); got != "" {
		t.Errorf("InternalAdminKey() = %q, want empty", got)
	}
	if got := DeploymentEnv(); got != "" {
		t.Errorf("DeploymentEnv() = %q, want empty", got)
	}
	if got := AdminPasswordFile(); got != "" {
		t.Errorf("AdminPasswordFile() = %q, want empty", got)
	}
	if got := EEInternalToken(); got != "" {
		t.Errorf("EEInternalToken() = %q, want empty", got)
	}
	t.Setenv("YABANIN_ADMIN_API_KEY", "k1")
	t.Setenv("YABANIN_ENV", "dev")
	t.Setenv("YABANIN_ADMIN_PASSWORD_FILE", "/run/secrets/adminpw")
	t.Setenv("EE_INTERNAL_TOKEN", "ee-tok")
	if got := InternalAdminKey(); got != "k1" {
		t.Errorf("InternalAdminKey() = %q, want k1", got)
	}
	if got := DeploymentEnv(); got != "dev" {
		t.Errorf("DeploymentEnv() = %q, want dev", got)
	}
	if got := AdminPasswordFile(); got != "/run/secrets/adminpw" {
		t.Errorf("AdminPasswordFile() = %q, want /run/secrets/adminpw", got)
	}
	if got := EEInternalToken(); got != "ee-tok" {
		t.Errorf("EEInternalToken() = %q, want ee-tok", got)
	}
}

func TestMCPBridgeFromEnv(t *testing.T) {
	unset(t, "YABANIN_GATEWAY_URL", "YABANIN_ADMIN_URL", "YABANIN_PARTNER_API_KEY", "YABANIN_ADMIN_API_KEY", "YABANIN_MCP_HTTP")
	t.Setenv("YABANIN_GATEWAY_URL", "https://gw.example.com")
	t.Setenv("YABANIN_ADMIN_URL", "https://admin.example.com")
	t.Setenv("YABANIN_PARTNER_API_KEY", "pk")
	t.Setenv("YABANIN_ADMIN_API_KEY", "ak")
	t.Setenv("YABANIN_MCP_HTTP", "1")
	got := MCPBridgeFromEnv()
	if got.GatewayURL != "https://gw.example.com" || got.AdminURL != "https://admin.example.com" ||
		got.PartnerAPIKey != "pk" || got.AdminAPIKey != "ak" || !got.HTTP {
		t.Errorf("MCPBridgeFromEnv() = %+v", got)
	}
}

func TestEncryptionAllowPlaintext(t *testing.T) {
	unset(t, "YABANIN_ENCRYPTION_ALLOW_PLAINTEXT")
	if EncryptionAllowPlaintext() {
		t.Error("EncryptionAllowPlaintext() = true when unset, want false")
	}
	for _, v := range []string{"1", "true", "0"} {
		t.Setenv("YABANIN_ENCRYPTION_ALLOW_PLAINTEXT", v)
		if got := EncryptionAllowPlaintext(); got != (v == "1") {
			t.Errorf("EncryptionAllowPlaintext() with %q = %v", v, got)
		}
	}
}

func TestKMSLocalFromEnv(t *testing.T) {
	unset(t, "YABANIN_KMS_LOCAL_KEY_FILE", "YABANIN_KMS_LOCAL_KEY")
	t.Setenv("YABANIN_KMS_LOCAL_KEY_FILE", "/run/secrets/kms.key")
	t.Setenv("YABANIN_KMS_LOCAL_KEY", "rawkey")
	got := KMSLocalFromEnv()
	if got.KeyFile != "/run/secrets/kms.key" || got.Key != "rawkey" {
		t.Errorf("KMSLocalFromEnv() = %+v", got)
	}
}

func TestDelegationFromEnv(t *testing.T) {
	cases := []struct {
		enabled string
		want    bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {" yes ", true}, {"On", true},
		{"0", false}, {"", false}, {"nope", false},
	}
	for _, tc := range cases {
		t.Run("enabled="+tc.enabled, func(t *testing.T) {
			unset(t, "YABANIN_DELEGATION_ENABLED", "YABANIN_DELEGATION_WORKSPACE", "YABANIN_DELEGATION_BRIDGE_URL")
			if tc.enabled != "" {
				t.Setenv("YABANIN_DELEGATION_ENABLED", tc.enabled)
			}
			t.Setenv("YABANIN_DELEGATION_WORKSPACE", " /tmp/ws ")
			t.Setenv("YABANIN_DELEGATION_BRIDGE_URL", " https://bridge.example.com ")
			got := DelegationFromEnv()
			if got.Enabled != tc.want {
				t.Errorf("Enabled with %q = %v, want %v", tc.enabled, got.Enabled, tc.want)
			}
			if got.Workspace != "/tmp/ws" || got.BridgeURL != "https://bridge.example.com" {
				t.Errorf("DelegationFromEnv() = %+v", got)
			}
		})
	}
}

func TestEnvTruthy(t *testing.T) {
	for _, v := range []string{"1", "true", "TRUE", "Yes", "on", " yes "} {
		if !envTruthy(v) {
			t.Errorf("envTruthy(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", "0", "false", "nope", " enabled "} {
		if envTruthy(v) {
			t.Errorf("envTruthy(%q) = true, want false", v)
		}
	}
}

func TestKeyRateLimitsEnabled(t *testing.T) {
	unset(t, "YABANIN_KEY_RATE_LIMITS")
	if KeyRateLimitsEnabled() {
		t.Error("KeyRateLimitsEnabled() = true when unset, want false")
	}
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "YES")
	if !KeyRateLimitsEnabled() {
		t.Error("KeyRateLimitsEnabled() with YES = false, want true")
	}
	t.Setenv("YABANIN_KEY_RATE_LIMITS", "off")
	if KeyRateLimitsEnabled() {
		t.Error("KeyRateLimitsEnabled() with off = true, want false")
	}
}

func TestAdminBootstrapPGURI(t *testing.T) {
	t.Run("primary wins", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_GATEWAY_PG_URI")
		t.Setenv("YABANIN_PG_URI", "postgres://primary")
		t.Setenv("YABANIN_GATEWAY_PG_URI", "postgres://legacy")
		if got := AdminBootstrapPGURI(); got != "postgres://primary" {
			t.Errorf("AdminBootstrapPGURI() = %q, want primary", got)
		}
	})
	t.Run("legacy fallback", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_GATEWAY_PG_URI")
		t.Setenv("YABANIN_GATEWAY_PG_URI", "postgres://legacy")
		if got := AdminBootstrapPGURI(); got != "postgres://legacy" {
			t.Errorf("AdminBootstrapPGURI() = %q, want legacy", got)
		}
	})
	t.Run("both empty", func(t *testing.T) {
		unset(t, "YABANIN_PG_URI", "YABANIN_GATEWAY_PG_URI")
		if got := AdminBootstrapPGURI(); got != "" {
			t.Errorf("AdminBootstrapPGURI() = %q, want empty", got)
		}
	})
}

func TestLogFormatOverride(t *testing.T) {
	unset(t, "LOG_FORMAT")
	if format, ok := LogFormatOverride(); ok || format != "" {
		t.Errorf("LogFormatOverride() = (%q, %v) when unset, want empty/false", format, ok)
	}
	t.Setenv("LOG_FORMAT", "json")
	if format, ok := LogFormatOverride(); !ok || format != "json" {
		t.Errorf("LogFormatOverride() = (%q, %v), want (json, true)", format, ok)
	}
}

func TestLogContentProfileFromEnv(t *testing.T) {
	cases := []struct {
		name string
		val  string
		set  bool
		want LogContentProfile
	}{
		{name: "unset keeps legacy", set: false, want: LogContentProfileLegacy},
		{name: "empty keeps legacy", val: "", set: true, want: LogContentProfileLegacy},
		{name: "legacy exact", val: "legacy", set: true, want: LogContentProfileLegacy},
		{name: "legacy trimmed and upper", val: "  LEGACY ", set: true, want: LogContentProfileLegacy},
		{name: "metadata-only exact", val: "metadata-only", set: true, want: LogContentProfileMetadataOnly},
		{name: "metadata-only trimmed and upper", val: " METADATA-ONLY\t", set: true, want: LogContentProfileMetadataOnly},
		{name: "unknown explicit fails closed", val: "verbose", set: true, want: LogContentProfileMetadataOnly},
		{name: "underscore typo fails closed", val: "metadata_only", set: true, want: LogContentProfileMetadataOnly},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unset(t, "YABANIN_LOG_CONTENT_PROFILE")
			if tc.set {
				t.Setenv("YABANIN_LOG_CONTENT_PROFILE", tc.val)
			}
			if got := LogContentProfileFromEnv(); got != tc.want {
				t.Errorf("LogContentProfileFromEnv() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectiveLogContentProfile(t *testing.T) {
	legacy := LogContentProfileLegacy
	strict := LogContentProfileMetadataOnly

	t.Run("local legacy + absent wire stays legacy", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, nil, false); got != legacy {
			t.Errorf("got %q, want legacy", got)
		}
	})
	t.Run("local legacy + wire legacy stays legacy", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, "legacy", true); got != legacy {
			t.Errorf("got %q, want legacy", got)
		}
	})
	t.Run("local legacy + wire metadata-only tightens", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, "metadata-only", true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
	})
	t.Run("present empty wire fails closed", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, "", true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
	})
	t.Run("present non-string wire fails closed", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, nil, true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
		if got := EffectiveLogContentProfile(legacy, 42, true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
	})
	t.Run("present unknown wire fails closed", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, "full", true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
	})
	t.Run("present non-canonical casing fails closed", func(t *testing.T) {
		if got := EffectiveLogContentProfile(legacy, "LEGACY", true); got != strict {
			t.Errorf("got %q, want metadata-only: the wire value is matched exactly", got)
		}
		if got := EffectiveLogContentProfile(legacy, " legacy ", true); got != strict {
			t.Errorf("got %q, want metadata-only: the wire value is matched exactly", got)
		}
	})
	t.Run("local strict wins over any wire", func(t *testing.T) {
		if got := EffectiveLogContentProfile(strict, "legacy", true); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
		if got := EffectiveLogContentProfile(strict, nil, false); got != strict {
			t.Errorf("got %q, want metadata-only", got)
		}
	})
}
