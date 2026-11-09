package config

import (
	"os"
	"path/filepath"
	"strings"
)

// GuardPackConfig configures local detector packs. A directory is optional;
// ActivePacks is a comma-separated list of pack IDs enabled from that root.
type GuardPackConfig struct {
	Dir         string
	ActivePacks []string
	Mode        string
}

// GuardPackVerifyConfig resolves the static pack-signature verification key
// set (scheme guardpack-sig.v1). KeysDir is a directory of trusted public
// keys; InlineKeys are key-id=material entries. An empty config means no
// verifier: unsigned packs load freely, signed packs fail closed.
type GuardPackVerifyConfig struct {
	KeysDir    string
	InlineKeys []string
}

// GuardPackVerify resolves YABANIN_GUARD_PACK_VERIFY_KEYS_DIR and
// YABANIN_GUARD_PACK_VERIFY_KEYS (comma-separated key-id=base64 entries).
// Lazy env read at the usage site, the same lifecycle as GuardPacks/MLPack:
// the values are turned into a guardhooks.SignatureVerifier by
// guardhooks.NewVerifierFromConfig at wiring time, where a configured-but-
// broken key set fails loud.
func (gw Gateway) GuardPackVerify() GuardPackVerifyConfig {
	dir := strings.TrimSpace(os.Getenv("YABANIN_GUARD_PACK_VERIFY_KEYS_DIR"))
	var inline []string
	for _, entry := range strings.Split(os.Getenv("YABANIN_GUARD_PACK_VERIFY_KEYS"), ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			inline = append(inline, entry)
		}
	}
	return GuardPackVerifyConfig{KeysDir: dir, InlineKeys: inline}
}

// GuardPacks resolves YABANIN_GUARD_PACK_DIR and the active pack IDs.
func (gw Gateway) GuardPacks() GuardPackConfig {
	dir := strings.TrimSpace(os.Getenv("YABANIN_GUARD_PACK_DIR"))
	var active []string
	for _, id := range strings.Split(os.Getenv("YABANIN_GUARD_ACTIVE_PACKS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			active = append(active, id)
		}
	}
	return GuardPackConfig{Dir: dir, ActivePacks: active, Mode: strings.TrimSpace(os.Getenv("YABANIN_GUARD_PACK_MODE"))}
}

// GuardPackManifestPath returns the standard manifest location for one pack.
func (c GuardPackConfig) GuardPackManifestPath(id string) string {
	return filepath.Join(c.Dir, id, "manifest.json")
}

// MLPackConfig holds the configuration for optional versioned model packs.
// An explicitly attached pack (YABANIN_ML_PACK_DIR) is the only way model
// weights reach a deployment — the core never downloads. The zero value
// (Dir == "") is the minimal mode: no pack, no verification, no download.
type MLPackConfig struct {
	// Dir is the model pack directory containing pack.json — the JSON
	// digest manifest recording provenance and per-file sha256 digests —
	// and the declared weight files (env: YABANIN_ML_PACK_DIR). Empty
	// disables packs. The canonical manifest is produced offline by
	// scripts/airgap/mlpack_manifest.sh (schema_version-stamped) and
	// verified on disk at wiring time by pkg/mlpack.
	Dir string
}

// mlpackManifestFileName is the JSON digest manifest file name inside a
// pack directory. Kept literal so this config surface stays dependency-free
// (the canonical constant lives in pkg/mlpack; same pattern as
// GuardPackManifestPath).
const mlpackManifestFileName = "pack.json"

// Enabled reports whether a pack is explicitly attached: false is the
// minimal mode (base policies, no ML, nothing verified or downloaded).
// Activation is explicit — there is no download path. A set-but-broken
// pack is never silently degraded to minimal mode: Enabled stays true and
// the on-disk verification at the wiring site (pkg/mlpack.AttachDir)
// refuses startup, so a wrong digest or missing weights can never yield a
// false ready.
func (c MLPackConfig) Enabled() bool {
	return c.Dir != ""
}

// ManifestPath returns the location of the pack's JSON digest manifest
// (pack.json — provenance plus per-file sha256 digests) inside Dir.
func (c MLPackConfig) ManifestPath() string {
	return filepath.Join(c.Dir, mlpackManifestFileName)
}

// NewMLPackConfig reads model-pack configuration from environment variables.
//
// Like NewEmbedderConfig, this is read lazily at the usage site (outside
// Load), so YABANIN_CONFIG_STRICT=1 does not gate it; a set-but-broken pack
// is refused by the mlpack verification at wiring time, not by env parsing.
func NewMLPackConfig() MLPackConfig {
	return MLPackConfig{
		Dir: strings.TrimSpace(os.Getenv("YABANIN_ML_PACK_DIR")),
	}
}

// MLPack returns the resolved model-pack configuration from env vars. Lazy,
// env-driven — the same lifecycle as Embedder().
func (gw Gateway) MLPack() MLPackConfig {
	return NewMLPackConfig()
}
