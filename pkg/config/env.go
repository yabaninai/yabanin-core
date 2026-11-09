package config

import (
	"bytes"
	"os"
	"strconv"
	"strings"
)

// This file is the single home for YABANIN_* environment reads outside the
// wrappers, and library facades route their env access through these facets
// instead of calling os.Getenv directly, so the env contract is documented
// and greppable in one package.

// PathFromEnv returns the config file path selected by YABANIN_CONFIG.
// Empty means "no explicit path": callers fall back to ./config.yaml when it
// exists, or to env-only defaults (Load("")).
func PathFromEnv() string {
	return os.Getenv("YABANIN_CONFIG")
}

// AdminSessionRotationFromEnv reads the current/previous admin cookie keys.
// Remove YABANIN_ADMIN_SESSION_SECRET_PREVIOUS and restart to revoke the old
// secret immediately; configuration changes take effect only after restart.
func AdminSessionRotationFromEnv() (current, previous, grace string) {
	current = os.Getenv("YABANIN_ADMIN_SESSION_SECRET")
	if current == "" {
		current = os.Getenv("YABANIN_SESSION_KEY")
	}
	return current, os.Getenv("YABANIN_ADMIN_SESSION_SECRET_PREVIOUS"), os.Getenv("YABANIN_ADMIN_SESSION_SECRET_GRACE")
}

// LicenseEnv holds the license-activation variables. All are optional:
// enforcement mode starts only when both File and RootPubKey are set
// (callers fail closed when only one is present).
type LicenseEnv struct {
	// File is YABANIN_LICENSE_FILE — the license token path.
	File string
	// RootPubKey is YABANIN_LICENSE_ROOT_PUBKEY — hex Ed25519 root public key.
	RootPubKey string
	// CRLFile is YABANIN_LICENSE_CRL_FILE — optional certificate revocation
	// list path ("" disables CRL checks).
	CRLFile string
	// IntermediateCert is YABANIN_LICENSE_INTERMEDIATE_CERT — optional
	// override for the intermediate certificate path ("" = the bundled
	// deploy/license/intermediate.json default).
	IntermediateCert string
}

// LicenseFromEnv reads the license-activation variables (see LicenseEnv).
func LicenseFromEnv() LicenseEnv {
	return LicenseEnv{
		File:             os.Getenv("YABANIN_LICENSE_FILE"),
		RootPubKey:       os.Getenv("YABANIN_LICENSE_ROOT_PUBKEY"),
		CRLFile:          os.Getenv("YABANIN_LICENSE_CRL_FILE"),
		IntermediateCert: os.Getenv("YABANIN_LICENSE_INTERMEDIATE_CERT"),
	}
}

// MigrateEnv holds the standalone migration runner's settings. Both fields
// are required by the runner (it exits with an error when either is empty —
// unlike the services, no defaults apply here).
type MigrateEnv struct {
	// PGURI is YABANIN_PG_URI, with the YABANIN_PG_URI_FILE Docker/K8s
	// secret convention applied when the direct value is empty.
	PGURI string
	// Region is YABANIN_REGION (RLS region the migrations are stamped with).
	Region string
}

// MigrateFromEnv reads the standalone migration runner's settings. The _FILE
// fallback applies only when YABANIN_PG_URI is empty (including when it is
// set to ""), matching the historical runner behavior.
func MigrateFromEnv() MigrateEnv {
	pgURI := os.Getenv("YABANIN_PG_URI")
	if pgURI == "" {
		if keyFile := os.Getenv("YABANIN_PG_URI_FILE"); keyFile != "" {
			//nolint:gosec // G304: path comes from the operator's own env (_FILE docker-secret convention)
			if data, err := os.ReadFile(keyFile); err == nil {
				pgURI = string(bytes.TrimSpace(data))
			}
		}
	}
	return MigrateEnv{PGURI: pgURI, Region: os.Getenv("YABANIN_REGION")}
}

// RollupEnv holds the loggerd analytics-rollup scheduler switches.
type RollupEnv struct {
	// Disabled is true when YABANIN_ROLLUPS=0 (the only disabling value).
	Disabled bool
	// Backfill is the trimmed YABANIN_ROLLUP_BACKFILL spec "from,to"
	// (RFC3339); empty disables the one-shot backfill.
	Backfill string
}

// RollupFromEnv reads the rollup scheduler switches (see RollupEnv).
func RollupFromEnv() RollupEnv {
	return RollupEnv{
		Disabled: os.Getenv("YABANIN_ROLLUPS") == "0",
		Backfill: strings.TrimSpace(os.Getenv("YABANIN_ROLLUP_BACKFILL")),
	}
}

// DebugLogResponse reports whether YABANIN_DEBUG_LOG_RESPONSE=true requests
// storing (truncated) model responses in request_logs for debugging. Only
// the exact lowercase value "true" enables it.
func DebugLogResponse() bool {
	return os.Getenv("YABANIN_DEBUG_LOG_RESPONSE") == "true"
}

// LogRetentionDays parses YABANIN_LOG_RETENTION_DAYS for the request_logs
// purge job. ok is false when the variable is unset/empty, malformed, or
// non-positive — in every case the purge job stays off, exactly like the
// historical call-site parse.
func LogRetentionDays() (days int, ok bool) {
	v := os.Getenv("YABANIN_LOG_RETENTION_DAYS")
	if v == "" {
		return 0, false
	}
	days, err := strconv.Atoi(v)
	if err != nil || days <= 0 {
		return 0, false
	}
	return days, true
}

// InternalAdminKey returns YABANIN_ADMIN_API_KEY — the X-Admin-Key for the
// stateless /internal admin service API. Empty keeps that API disabled.
func InternalAdminKey() string {
	return os.Getenv("YABANIN_ADMIN_API_KEY")
}

// EEInternalToken returns EE_INTERNAL_TOKEN — the shared internal token
// guarding POST /auth/ee/session (X-EE-Internal header), where the EE
// backend validates admin sessions it relays from the browser (D-UI-4).
// Empty keeps the endpoint disabled: the route is not mounted and the path
// answers 404 (feature-dark).
func EEInternalToken() string {
	return os.Getenv("EE_INTERNAL_TOKEN")
}

// DeploymentEnv returns the raw YABANIN_ENV value. Interpreting it
// (dev/development/test vs everything else = production) stays with the
// caller; the empty/unknown value must keep meaning production.
func DeploymentEnv() string {
	return os.Getenv("YABANIN_ENV")
}

// MCPBridgeEnv holds the MCP partner bridge connection settings (services
// run wrapper). All URLs default at the call site, so empty values are
// meaningful.
type MCPBridgeEnv struct {
	// GatewayURL is YABANIN_GATEWAY_URL (data-plane base URL).
	GatewayURL string
	// AdminURL is YABANIN_ADMIN_URL (admin REST base URL, not gateway-admin).
	AdminURL string
	// PartnerAPIKey is YABANIN_PARTNER_API_KEY (required by the bridge).
	PartnerAPIKey string
	// AdminAPIKey is YABANIN_ADMIN_API_KEY; empty = share PartnerAPIKey.
	AdminAPIKey string
	// HTTP is true when YABANIN_MCP_HTTP=1 (HTTP-SSE mode; default stdio).
	HTTP bool
}

// MCPBridgeFromEnv reads the MCP partner bridge settings (see MCPBridgeEnv).
func MCPBridgeFromEnv() MCPBridgeEnv {
	return MCPBridgeEnv{
		GatewayURL:    os.Getenv("YABANIN_GATEWAY_URL"),
		AdminURL:      os.Getenv("YABANIN_ADMIN_URL"),
		PartnerAPIKey: os.Getenv("YABANIN_PARTNER_API_KEY"),
		AdminAPIKey:   os.Getenv("YABANIN_ADMIN_API_KEY"),
		HTTP:          os.Getenv("YABANIN_MCP_HTTP") == "1",
	}
}

// EncryptionAllowPlaintext reports whether YABANIN_ENCRYPTION_ALLOW_PLAINTEXT=1
// explicitly opts the deployment into plaintext secret writes (dev escape
// hatch). Only the exact value "1" enables it.
func EncryptionAllowPlaintext() bool {
	return os.Getenv("YABANIN_ENCRYPTION_ALLOW_PLAINTEXT") == "1"
}

// KMSLocalEnv holds the local KMS master key material: KeyFile is
// YABANIN_KMS_LOCAL_KEY_FILE (Docker/K8s _FILE convention, takes
// precedence), Key is YABANIN_KMS_LOCAL_KEY (direct dev convenience).
type KMSLocalEnv struct {
	KeyFile string
	Key     string
}

// KMSLocalFromEnv reads the local KMS master key handles (see KMSLocalEnv).
func KMSLocalFromEnv() KMSLocalEnv {
	return KMSLocalEnv{
		KeyFile: os.Getenv("YABANIN_KMS_LOCAL_KEY_FILE"),
		Key:     os.Getenv("YABANIN_KMS_LOCAL_KEY"),
	}
}

// DelegationEnv holds the MCP tr_delegate delegation settings.
type DelegationEnv struct {
	// Enabled is the truthy YABANIN_DELEGATION_ENABLED (1/true/yes/on,
	// case-insensitive, trimmed). Default off.
	Enabled bool
	// Workspace is the trimmed YABANIN_DELEGATION_WORKSPACE ("" = caller
	// falls back to the working directory).
	Workspace string
	// BridgeURL is the trimmed YABANIN_DELEGATION_BRIDGE_URL ("" = local
	// fake executors instead of the bridge HTTP endpoint).
	BridgeURL string
}

// DelegationFromEnv reads the MCP delegation settings (see DelegationEnv).
func DelegationFromEnv() DelegationEnv {
	return DelegationEnv{
		Enabled:   envTruthy(os.Getenv("YABANIN_DELEGATION_ENABLED")),
		Workspace: strings.TrimSpace(os.Getenv("YABANIN_DELEGATION_WORKSPACE")),
		BridgeURL: strings.TrimSpace(os.Getenv("YABANIN_DELEGATION_BRIDGE_URL")),
	}
}

// envTruthy is the shared loose boolean parse (1/true/yes/on,
// case-insensitive, trimmed). Unlike envBool it trims and accepts yes/on.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// KeyRateLimitsEnabled reports whether YABANIN_KEY_RATE_LIMITS is set (1/true/yes/on, case-insensitive,
// trimmed). Default off — the flag gates entirely new behavior.
func KeyRateLimitsEnabled() bool {
	return envTruthy(os.Getenv("YABANIN_KEY_RATE_LIMITS"))
}

// AdminBootstrapPGURI returns the connection string for the
// `admin create-user` bootstrap CLI: YABANIN_PG_URI, falling back to the
// legacy alias YABANIN_GATEWAY_PG_URI. Both names stay accepted for
// compatibility; YABANIN_PG_URI is the documented primary.
func AdminBootstrapPGURI() string {
	if pgURI := os.Getenv("YABANIN_PG_URI"); pgURI != "" {
		return pgURI
	}
	return os.Getenv("YABANIN_GATEWAY_PG_URI")
}

// AdminPasswordFile returns YABANIN_ADMIN_PASSWORD_FILE — the path holding
// the `admin create-user` bootstrap password (the password itself is never
// accepted on the command line).
func AdminPasswordFile() string {
	return os.Getenv("YABANIN_ADMIN_PASSWORD_FILE")
}

// LogFormatOverride returns the LOG_FORMAT value and whether the variable
// was present at all. Presence (not the value) matters: an unknown value is
// ignored by the caller, so the boolean preserves the historical
// LookupEnv-based override behavior.
func LogFormatOverride() (format string, ok bool) {
	return os.LookupEnv("LOG_FORMAT")
}

// like the other feature gates; default off keeps existing behavior
// bit-for-bit (no middleware work, no extra Redis/DB calls).
const (
	// OrgCapsOff is the default: the org-caps enforcer is not mounted.
	OrgCapsOff = "off"
	// OrgCapsShadow measures would-deny decisions without enforcing.
	OrgCapsShadow = "shadow"
	// OrgCapsEnforce denies: org windows answer 429, the hard monthly budget
	// answers 402 budget_exceeded, and dependency failures fail CLOSED.
	OrgCapsEnforce = "enforce"
)

// OrgCapsMode resolves YABANIN_ORG_CAPS to off|shadow|enforce (case-
// insensitive, trimmed). Unknown values degrade to off — the mode only ever
// tightens admission when it is spelled correctly.
func OrgCapsMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("YABANIN_ORG_CAPS"))) {
	case OrgCapsShadow:
		return OrgCapsShadow
	case OrgCapsEnforce:
		return OrgCapsEnforce
	default:
		return OrgCapsOff
	}
}

// LogContentProfile controls what producers may put into analytics event bodies and the loggerd wire
// stream.
type LogContentProfile string

const (
	// LogContentProfileLegacy is the default: full request/response captures
	// ride the event, subject to the existing PII redaction only.
	LogContentProfileLegacy LogContentProfile = "legacy"
	// LogContentProfileMetadataOnly strips the content captures from the
	// event before the observer and the wire publish, replacing the error
	// text with a fixed redaction notice and stamping a prompt digest.
	LogContentProfileMetadataOnly LogContentProfile = "metadata-only"
)

// LogContentProfileFromEnv resolves the process-local policy from
// keeps legacy; "legacy" and "metadata-only" are accepted exactly (trimmed,
// lower-cased); any other explicit value fails CLOSED to metadata-only. The
// rejected value is never echoed back.
func LogContentProfileFromEnv() LogContentProfile {
	return parseLogContentProfile(os.Getenv("YABANIN_LOG_CONTENT_PROFILE"))
}

// parseLogContentProfile implements the fail-closed profile parse; see
// LogContentProfileFromEnv.
func parseLogContentProfile(v string) LogContentProfile {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", string(LogContentProfileLegacy):
		return LogContentProfileLegacy
	case string(LogContentProfileMetadataOnly):
		return LogContentProfileMetadataOnly
	default:
		return LogContentProfileMetadataOnly
	}
}

// EffectiveLogContentProfile resolves the effective policy for one event:
// the strictest of the process-local profile and the wire-declared profile.
// wirePresent is true only when the event carried a content_profile field at
// all — an ABSENT key is legacy-compatible; a PRESENT value must be the
// exact string "legacy" to stay permissive, and a present empty, non-string
// or unknown value fails closed to metadata-only (the contract treats
// presence as intent, so malformed intent never widens retention; unlike
// the operator env, the wire value is matched exactly, never normalized).
func EffectiveLogContentProfile(local LogContentProfile, wire any, wirePresent bool) LogContentProfile {
	if local == LogContentProfileMetadataOnly {
		return LogContentProfileMetadataOnly
	}
	if !wirePresent {
		return LogContentProfileLegacy
	}
	if declared, ok := wire.(string); ok && declared == string(LogContentProfileLegacy) {
		return LogContentProfileLegacy
	}
	return LogContentProfileMetadataOnly
}
