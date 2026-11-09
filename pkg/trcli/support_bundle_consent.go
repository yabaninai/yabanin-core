package trcli

// Support-bundle consent and local export (packet N13-P05-T04): the operator
// reviews what the diagnostics bundle contains BEFORE any archive is written,
// consents explicitly, and the bundle is exported to a local file only.
//
// Chain (each step an observable operator action):
//
//  1. `diagnostics preview` (unchanged): prints the exact bundle JSON without
//     writing anything. `--summary` prints the consent summary instead —
//     a compact, deterministic description of what the archive would contain.
//  2. `diagnostics create` without --consent: collects, marshals, renders the
//     consent summary (including the bundle byte count and sha256) and then
//     REFUSES with the fixed consent category. No file is created, no path
//     outside the operator's own machine is touched. Mirrors the
//     litellm-migrate posture: preview only — nothing was written.
//  3. `diagnostics create --consent`: writes the local archive (0600, O_EXCL,
//     never overwrites) and prints the summary followed by the exact bundle
//     JSON. `--consent-digest <sha256>` optionally binds the consent to the
//     exact previewed bytes: collection is deterministic, so a digest
//     mismatch means the machine state changed between preview and create
//     and the operator must re-preview and re-consent.
//
// Safety invariants (all carried over from T02/T03, restated in the summary):
//
//   - No egress: collection never contacts the network; probes run only with
//     --probe; the bundle is never sent anywhere by this command.
//   - The summary prints counts, categorical states and bundle digests only —
//     never log content, secret values, or file system paths.
//   - The exported file is local (mode 0600, never overwritten); stdout
//     remains deterministic for the same machine state.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

const (
	// supportDiagConsentRequiredError is the fixed failure category for a
	// create without explicit operator consent; like every other support
	// bundle category it carries no paths or environment detail.
	supportDiagConsentRequiredError = "consent required: review the bundle preview, then rerun create with --consent to write the local archive"
	// supportDiagConsentDigestFlagError refuses a malformed --consent-digest
	// before any collection happens.
	supportDiagConsentDigestFlagError = "--consent-digest must be a 64-character sha256 hex digest of the previewed bundle bytes"
	// supportDiagConsentDigestMismatchError refuses a consent whose digest
	// does not match the current bundle bytes; the fixed category never
	// echoes either digest value.
	supportDiagConsentDigestMismatchError = "consent digest does not match the current bundle; rerun preview and consent to the fresh bundle"
)

// supportDiagConsentMode selects the summary footer: which step of the
// preview → consent → export chain produced this rendering.
type supportDiagConsentMode int

const (
	supportDiagConsentPreview supportDiagConsentMode = iota
	supportDiagConsentRefusal
	supportDiagConsentExported
)

// supportDiagConsentMaxFileList bounds the echoed log-file basenames so the
// summary stays a summary; the full list always rides in the bundle itself.
const supportDiagConsentMaxFileList = 8

var supportDiagConsentDigestHex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// supportDiagConsentDigest is the sha256 hex digest of the exact marshaled
// bundle bytes — the value `preview` prints and the archive would store.
func supportDiagConsentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// parseSupportDiagConsentDigest normalizes an optional --consent-digest
// value: empty stays empty; anything else must be a 64-character hex sha256.
func parseSupportDiagConsentDigest(value string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return "", nil
	}
	if !supportDiagConsentDigestHex.MatchString(trimmed) {
		return "", errors.New(supportDiagConsentDigestFlagError)
	}
	return trimmed, nil
}

// renderSupportDiagConsentSummary renders the deterministic consent summary:
// every value derives from the collected payload and the marshaled bytes —
// no timestamps, no wall-clock, no paths. The footer names the chain step.
func renderSupportDiagConsentSummary(payload *supportDiagnostics, data []byte, mode supportDiagConsentMode) string {
	var b strings.Builder
	b.WriteString("support bundle diagnostics — consent summary\n")
	fmt.Fprintf(&b, "schema_version: %d\n", payload.SchemaVersion)
	fmt.Fprintf(&b, "build: version=%s commit=%s\n", payload.Build.Version, payload.Build.Commit)
	fmt.Fprintf(&b, "runtime: go=%s os=%s arch=%s\n", payload.Runtime.GoVersion, payload.Runtime.OS, payload.Runtime.Arch)
	fmt.Fprintf(&b, "local_config: cli_profile_file_present=%s gateway_url_env_set=%s admin_url_env_set=%s api_key_env_set=%s\n",
		supportDiagConsentBool(payload.LocalConfig.CLIProfileFilePresent),
		supportDiagConsentBool(payload.LocalConfig.GatewayURLEnvSet),
		supportDiagConsentBool(payload.LocalConfig.AdminURLEnvSet),
		supportDiagConsentBool(payload.LocalConfig.APIKeyEnvSet))

	readError := payload.Config.ReadError
	if readError == "" {
		readError = "none"
	}
	fmt.Fprintf(&b, "config: collected=%s read_error=%s profiles=%d harness=%d redacted_keys=%d\n",
		supportDiagConsentBool(payload.Config.Collected), readError,
		len(payload.Config.Profiles), len(payload.Config.Harness), payload.Config.RedactedKeys)

	probes := "none"
	if len(payload.Health.Probes) > 0 {
		probes = fmt.Sprintf("%d", len(payload.Health.Probes))
	}
	fmt.Fprintf(&b, "health: profile_readable=%s profile_parse_ok=%s credentials_file_present=%s session_cache=%d/%d/%d/%d probes=%s\n",
		payload.Health.ProfileReadable,
		supportDiagConsentBool(payload.Health.ProfileParseOK),
		supportDiagConsentBool(payload.Health.CredentialsFilePresent),
		payload.Health.SessionCache.Files, payload.Health.SessionCache.Valid,
		payload.Health.SessionCache.Expired, payload.Health.SessionCache.Unreadable,
		probes)

	org := "unset"
	if payload.Logs.Org != "" {
		org = payload.Logs.Org
	}
	fmt.Fprintf(&b, "logs: org=%s scrub_profile=%s files=%d included_lines=%d excluded_foreign_org=%d excluded_non_json=%d redaction_hits=%d content_masks=%d content_fields_removed=%d\n",
		org, payload.Logs.ScrubProfile, len(payload.Logs.Files), payload.Logs.IncludedLines,
		payload.Logs.ExcludedForeignOrg, payload.Logs.ExcludedNonJSON,
		payload.Logs.RedactionHits, payload.Logs.ContentMasks, payload.Logs.ContentFieldsRemoved)
	fmt.Fprintf(&b, "log_files: %s\n", supportDiagConsentFileList(payload.Logs.Files))
	fmt.Fprintf(&b, "manifest: artifacts=%d\n", len(payload.Manifest))
	fmt.Fprintf(&b, "bundle: bytes=%d sha256=%s\n", len(data), supportDiagConsentDigest(data))
	b.WriteString("safety: foreign-org and non-JSON lines are excluded and counted; credential, PII and customer-content scrubbing follows the recorded profile; collection is local-only with no network egress unless --probe; this command never sends the bundle anywhere\n")
	switch mode {
	case supportDiagConsentPreview:
		b.WriteString("export: preview only — nothing written; create --consent writes the local archive (mode 0600, never overwritten)\n")
	case supportDiagConsentRefusal:
		b.WriteString("export: refused — nothing written; rerun create with --consent to write the local archive (mode 0600, never overwritten)\n")
	case supportDiagConsentExported:
		b.WriteString("export: local archive written (mode 0600, never overwritten) — nothing was sent anywhere\n")
	}
	return b.String()
}

// supportDiagConsentFileList renders bounded operator-selected log basenames
// (already the bundle's own naming policy: basenames only, never full paths).
func supportDiagConsentFileList(files []supportDiagLogFile) string {
	if len(files) == 0 {
		return "none"
	}
	names := make([]string, 0, len(files))
	limit := len(files)
	if limit > supportDiagConsentMaxFileList {
		limit = supportDiagConsentMaxFileList
	}
	for _, file := range files[:limit] {
		names = append(names, file.Name)
	}
	out := strings.Join(names, ", ")
	if remaining := len(files) - limit; remaining > 0 {
		out += fmt.Sprintf(" +%d more", remaining)
	}
	return out
}

func supportDiagConsentBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// supportDiagConsentFlags registers the create-command consent flags.
func supportDiagConsentFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("consent", false, "explicit operator consent to write the local archive after reviewing the preview")
	cmd.Flags().String("consent-digest", "", "optional sha256 hex of the previewed bundle bytes; the consent is bound to that exact payload")
}
