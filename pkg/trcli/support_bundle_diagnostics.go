package trcli

// Support-bundle diagnostics (packet N13-P05-T02): a schema-v2 bundle that
// collects versions, sanitized config, a local health snapshot and bounded
// recent logs — safely.
//
// Scrub-by-profile layer (packet N13-P05-T03, schema v3): the operator picks
// --scrub-profile minimal|standard|strict (default standard, fail-closed).
// Log entries pass through pkg/auditlog profile scrubbing: minimal is the
// T02 credentials-only behavior byte-for-byte; standard additionally masks
// PII (email, JWT, IPv4, international phone) and drops customer-content
// fields (payload/prompt/messages/... — prompt_hash kept); strict masks every
// remaining JSON string value. The applied profile and the per-layer counts
// (content_masks, content_fields_removed) are recorded in the bundle. Org
// scoping and exclusion counting run before scrubbing, unchanged.
//
// Consent and local-export layer (packet N13-P05-T04): `preview` (or
// `preview --summary`) shows exactly what the bundle contains before any
// archive exists; `create` refuses with the fixed consent category unless the
// operator passes --consent (optionally bound to the previewed bytes via
// --consent-digest); a consented create exports the bundle to a local 0600
// file only and never sends anything anywhere. See
// support_bundle_consent.go for the chain and its invariants.
//
// Safety invariants (mirroring the accepted v1 metadata bundle):
//
//   - Deny-by-default sanitization: every config key outside the allowlist is
//     counted and suppressed; allowlisted values are emitted only after
//     pattern validation (URLs stripped to scheme/host/path, durations pinned
//     to a strict shape). Secret-bearing keys (key_ref, api keys, tokens,
//     labels values) never enter the bundle — only presence/counts.
//   - Org scoping for logs: a log line is included only when it parses as a
//     JSON object AND its org attribute is absent (local/unattributed) or
//     equal to the operator-selected org. Org-tagged lines from any other org
//     — and lines that cannot be attributed at all (non-JSON) — are excluded
//     and counted, never silently dropped.
//   - Redaction: bearer tokens and secret-shaped key/value pairs are masked
//     both structurally (JSON keys) and textually, with the hit count kept in
//     the bundle. Under standard/strict, PII shapes and customer-content
//     fields are scrubbed on top, each counted in its own counter.
//   - No egress without operator action: collection never contacts the
//     network. Live health probes run only when the operator passes --probe,
//     and only against explicitly configured targets (never inferred
//     defaults). Sending the bundle anywhere is always a separate manual
//     operator action; this command writes a local 0600 file or stdout only.
//   - Determinism: no timestamps, sorted iteration everywhere; the same
//     machine state yields byte-identical output across invocations.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/reireirei/yabanin/pkg/auditlog"
)

const (
	// supportBundleDiagnosticsError is the fixed failure category for the
	// diagnostics bundle; like the v1 category it never carries paths or
	// environment detail.
	supportBundleDiagnosticsError = "support bundle diagnostics could not be created"
	// supportBundleDiagLogReadError fails closed when an operator-requested
	// log file cannot be read: no partial bundle is produced and no path is
	// disclosed.
	supportBundleDiagLogReadError = "support bundle diagnostics could not read a requested log file"
	// supportBundleDiagProbeTargetError mirrors doctor's consent posture: a
	// probe never infers a target from defaults.
	supportBundleDiagProbeTargetError = "support bundle diagnostics probe requires an explicitly configured target"
)

// Bounds for the log tail. Bounded recent logs: at most maxLines lines taken
// from the most recent maxBytes window of each file.
const (
	supportDiagDefaultMaxLines = 200
	supportDiagMinLines        = 1
	supportDiagMaxLines        = 10000
	supportDiagDefaultMaxBytes = 256 << 10 // 256 KiB
	supportDiagMinBytes        = 1024
	supportDiagMaxBytes        = 16 << 20 // 16 MiB
	// supportDiagMaxSessionScan mirrors sweepSessionCache's bounded scan.
	supportDiagMaxSessionScan = 200
)

var (
	// supportDiagBearer masks "Bearer <token>" shapes inside any text.
	supportDiagBearer = regexp.MustCompile(`(?i)\b(bearer\s+)([a-z0-9._~+/=-]{8,})`)
	// supportDiagSecretKV masks secret-shaped key/value pairs ("api_key: v",
	// "authorization=x", "token": "v") inside any text.
	supportDiagSecretKV = regexp.MustCompile(`(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|session[-_]?key|token|password|passwd|secret|private[-_]?key|authorization)\b(\s*["']?\s*[:=]\s*["']?)([^\s"',;}]{4,})`)
	// supportDiagSecretJSONKey matches JSON object keys whose values must be
	// masked structurally.
	supportDiagSecretJSONKey = regexp.MustCompile(`(?i)^(authorization|bearer|api[-_]?key|access[-_]?token|refresh[-_]?token|token|password|passwd|secret|private[-_]?key|session[-_]?key|key)$`)
	// supportDiagTTL is the only harness value shape allowlisted verbatim.
	supportDiagTTL = regexp.MustCompile(`^[0-9]{1,6}(?:ms|s|m|h)$`)
)

// supportDiagLogOrgKeys lists the JSON fields checked (in order) for a log
// line's owning organization.
var supportDiagLogOrgKeys = []string{"org_id", "organization", "org"}

type supportDiagnostics struct {
	SchemaVersion int                        `json:"schema_version"`
	Build         supportBundleBuild         `json:"build"`
	Runtime       supportBundleRuntime       `json:"runtime"`
	LocalConfig   supportBundleConfig        `json:"local_config"`
	Config        supportDiagConfig          `json:"config"`
	Health        supportDiagHealth          `json:"health"`
	Logs          supportDiagLogs            `json:"logs"`
	Manifest      []supportDiagManifestEntry `json:"manifest"`
}

// supportDiagConfig is the deny-by-default sanitized view of the CLI profile
// file. Collected means the file was read (even if its shape was invalid);
// ReadError is categorical. Version is the allowlisted schema int. Profiles
// and Harness are sorted by name for determinism. RedactedKeys counts every
// suppressed key/value pair.
type supportDiagConfig struct {
	Source       string                   `json:"source"`
	Collected    bool                     `json:"collected"`
	ReadError    string                   `json:"read_error,omitempty"`
	Version      *int                     `json:"version,omitempty"`
	Profiles     []supportDiagProfile     `json:"profiles,omitempty"`
	Harness      []supportDiagHarnessTool `json:"harness,omitempty"`
	RedactedKeys int                      `json:"redacted_keys"`
}

type supportDiagProfile struct {
	Name              string `json:"name"`
	GatewayURL        string `json:"gateway_url,omitempty"` // sanitized: scheme://host[:port][/path]
	GatewayURLPresent bool   `json:"gateway_url_present"`
	GatewayURLRedact  bool   `json:"gateway_url_redacted,omitempty"` // present but not safely sanitizable
	KeyRefPresent     bool   `json:"key_ref_present"`                // reference presence only, never the value
	LabelsPresent     int    `json:"labels_present"`                 // label values are operator data — count only
}

type supportDiagHarnessTool struct {
	Tool          string `json:"tool"`
	Session       bool   `json:"session"`
	SessionKnown  bool   `json:"session_known"`
	TTL           string `json:"ttl,omitempty"` // allowlisted duration shape only
	OtherRedacted int    `json:"other_keys_redacted"`
}

// supportDiagHealth is a purely local snapshot: file readability, parse
// state, credential file presence and bounded session-cache counts. Probes
// are appended only on the operator's explicit --probe action.
type supportDiagHealth struct {
	ProfileReadable        string                  `json:"profile_readable"` // yes|no|absent
	ProfileParseOK         bool                    `json:"profile_parse_ok"`
	CredentialsFilePresent bool                    `json:"credentials_file_present"`
	SessionCache           supportDiagSessionCache `json:"session_cache"`
	Probes                 []supportDiagProbe      `json:"probes,omitempty"`
}

type supportDiagSessionCache struct {
	Files      int `json:"files"`
	Valid      int `json:"valid"`
	Expired    int `json:"expired"`
	Unreadable int `json:"unreadable"`
}

type supportDiagProbe struct {
	Target string `json:"target"` // gateway|admin — categorical, never a URL
	Status string `json:"status"` // doctor's sanitized diagnosis vocabulary
}

type supportDiagLogs struct {
	Org                  string                `json:"org"`
	ScrubProfile         string                `json:"scrub_profile"` // applied profile: minimal|standard|strict (N13-P05-T03)
	Files                []supportDiagLogFile  `json:"files"`
	Entries              []supportDiagLogEntry `json:"entries"`
	IncludedLines        int                   `json:"included_lines"`
	ExcludedForeignOrg   int                   `json:"excluded_foreign_org"`
	ExcludedNonJSON      int                   `json:"excluded_non_json"`
	RedactionHits        int                   `json:"redaction_hits"`         // credential masks (T02 semantics)
	ContentMasks         int                   `json:"content_masks"`          // PII masks (standard) / full-value masks (strict)
	ContentFieldsRemoved int                   `json:"content_fields_removed"` // customer-content fields dropped
}

type supportDiagLogFile struct {
	Name      string `json:"name"` // basename only: full paths never enter the bundle
	Bytes     int64  `json:"bytes"`
	Sha256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
	Lines     int    `json:"lines"`
}

type supportDiagLogEntry struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Org     string `json:"org,omitempty"`
	Message string `json:"message"`
}

type supportDiagManifestEntry struct {
	Artifact  string `json:"artifact"`
	Bytes     int64  `json:"bytes"`
	Sha256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
	Note      string `json:"note"`
}

// supportDiagNow is injectable for deterministic session-expiry tests.
var supportDiagNow = time.Now

// supportDiagProbeEnabled is true when the operator explicitly asked for live
// health probes. Probes reuse doctor's URL validation and categorical
// diagnoses; collection without this stays fully offline.
func collectSupportDiagnostics(ctx context.Context, opts supportDiagOptions) (supportDiagnostics, error) {
	home, err := credentialHome()
	if err != nil {
		return supportDiagnostics{}, errors.New("support bundle metadata unavailable")
	}

	payload := supportDiagnostics{SchemaVersion: 3}
	payload.Build = supportBundleBuild{Version: safeSupportVersion(version), Commit: safeSupportCommit(commit)}
	payload.Runtime = supportBundleRuntime{GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}

	profilePath := configPath(home)
	raw, statErr := os.ReadFile(profilePath) //nolint:gosec // G304: path is built from the operator's credential home, mirroring v1
	switch {
	case statErr == nil:
		payload.LocalConfig.CLIProfileFilePresent = true
		payload.Config = sanitizeSupportProfile(raw)
		payload.Health.ProfileReadable = "yes"
		payload.Health.ProfileParseOK = payload.Config.ReadError == ""
	case errors.Is(statErr, os.ErrNotExist):
		payload.Health.ProfileReadable = "absent"
	default:
		payload.Health.ProfileReadable = "no"
	}
	payload.LocalConfig.GatewayURLEnvSet = supportEnvSet("YABANIN_GATEWAY_URL")
	payload.LocalConfig.AdminURLEnvSet = supportEnvSet("YABANIN_ADMIN_URL")
	payload.LocalConfig.APIKeyEnvSet = supportEnvSet("YABANIN_API_KEY")

	payload.Health.CredentialsFilePresent = supportFilePresent(filepath.Join(home, ".yabanin", "credentials.json"))
	payload.Health.SessionCache = collectSupportSessionCache(home, supportDiagNow())

	logs, manifest, logErr := collectSupportDiagLogs(opts)
	if logErr != nil {
		return supportDiagnostics{}, logErr
	}
	payload.Logs = *logs
	payload.Manifest = manifest

	if opts.Probe {
		probes, err := collectSupportDiagProbes(ctx, opts)
		if err != nil {
			return supportDiagnostics{}, err
		}
		payload.Health.Probes = probes
	}
	return payload, nil
}

// supportFilePresent reports file presence; every other stat outcome (permission,
// symlink loop, ...) is reported as absent rather than guessing.
func supportFilePresent(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// sanitizeSupportProfile walks the raw profile JSON with an explicit
// allowlist; everything else is counted into RedactedKeys and suppressed.
func sanitizeSupportProfile(raw []byte) supportDiagConfig {
	out := supportDiagConfig{Source: "cli_profile"}
	if len(strings.TrimSpace(string(raw))) == 0 {
		out.Collected = true
		out.ReadError = "empty"
		return out
	}
	var tree map[string]any
	if err := json.Unmarshal(raw, &tree); err != nil || tree == nil {
		out.Collected = true
		out.ReadError = "invalid_json"
		return out
	}
	out.Collected = true
	keys := supportDiagSortedKeys(tree)
	for _, key := range keys {
		switch key {
		case "version":
			if v := supportDiagSafeInt(tree[key]); v != nil {
				out.Version = v
			} else {
				out.RedactedKeys++
			}
		case "profiles":
			out.appendSanitizedProfiles(tree[key], &out.RedactedKeys)
		case "harness":
			out.appendSanitizedHarness(tree[key], &out.RedactedKeys)
		default:
			out.RedactedKeys++
		}
	}
	return out
}

func (c *supportDiagConfig) appendSanitizedProfiles(value any, redacted *int) {
	profiles, ok := value.(map[string]any)
	if !ok {
		*redacted++
		return
	}
	for _, name := range supportDiagSortedKeys(profiles) {
		entry := supportDiagProfile{Name: name}
		fields, ok := profiles[name].(map[string]any)
		if !ok {
			*redacted++
			c.Profiles = append(c.Profiles, entry)
			continue
		}
		for _, field := range supportDiagSortedKeys(fields) {
			switch field {
			case "gateway_url":
				entry.GatewayURLPresent = true
				if sanitized, ok := sanitizeSupportGatewayURL(fmt.Sprint(fields[field])); ok {
					entry.GatewayURL = sanitized
				} else {
					entry.GatewayURLRedact = true
				}
			case "key_ref":
				entry.KeyRefPresent = true
			case "labels":
				if labels, ok := fields[field].(map[string]any); ok {
					entry.LabelsPresent = len(labels)
				} else {
					*redacted++
				}
			default:
				*redacted++
			}
		}
		c.Profiles = append(c.Profiles, entry)
	}
}

func (c *supportDiagConfig) appendSanitizedHarness(value any, redacted *int) {
	harness, ok := value.(map[string]any)
	if !ok {
		*redacted++
		return
	}
	for _, tool := range supportDiagSortedKeys(harness) {
		entry := supportDiagHarnessTool{Tool: tool}
		fields, ok := harness[tool].(map[string]any)
		if !ok {
			*redacted++
			c.Harness = append(c.Harness, entry)
			continue
		}
		for _, field := range supportDiagSortedKeys(fields) {
			switch field {
			case "session":
				if session, ok := fields[field].(bool); ok {
					entry.Session = session
					entry.SessionKnown = true
				} else {
					*redacted++
				}
			case "ttl":
				if ttl, ok := fields[field].(string); ok && supportDiagTTL.MatchString(ttl) && len(ttl) <= 12 {
					entry.TTL = ttl
				} else {
					*redacted++
				}
			default:
				*redacted++
			}
		}
		c.Harness = append(c.Harness, entry)
	}
}

// sanitizeSupportGatewayURL reduces a gateway URL to scheme://host[:port][/path]:
// userinfo, query and fragment are stripped because they can carry credentials;
// control characters, opaque forms and non-http(s) schemes are refused.
func sanitizeSupportGatewayURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.ContainsFunc(s, unicode.IsControl) || len(s) > 2048 {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil || u == nil || u.Opaque != "" || u.Host == "" {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	cleaned := u.Scheme + "://" + u.Host + strings.TrimRight(u.EscapedPath(), "/")
	return cleaned, true
}

func supportDiagSafeInt(value any) *int {
	number, ok := value.(float64)
	if !ok || number != math.Trunc(number) || number < 0 || number > 1e6 {
		return nil
	}
	out := int(number)
	return &out
}

func supportDiagSortedKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// collectSupportSessionCache counts session-cache files by expiry class.
// File contents are read only to classify expiry; no identifier, key or label
// ever leaves this function.
func collectSupportSessionCache(home string, now time.Time) supportDiagSessionCache {
	out := supportDiagSessionCache{}
	dir := filepath.Join(home, ".yabanin", "sessions")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if out.Files >= supportDiagMaxSessionScan {
			return out
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		out.Files++
		body, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // G304: path is the user's own session cache, mirroring sweepSessionCache
		if err != nil {
			out.Unreadable++
			continue
		}
		var cached cachedSession
		if err := json.Unmarshal(body, &cached); err != nil {
			out.Unreadable++
			continue
		}
		if cached.ExpiresAt.After(now) {
			out.Valid++
		} else {
			out.Expired++
		}
	}
	return out
}

// collectSupportDiagProbes runs doctor's probes for explicitly configured
// targets only. This is the one code path that may touch the network and it
// runs exclusively behind the operator's --probe flag.
func collectSupportDiagProbes(ctx context.Context, opts supportDiagOptions) ([]supportDiagProbe, error) {
	targets := []struct {
		name   string
		target string
		path   string
	}{
		{"gateway", opts.GatewayBaseURL, "/healthz"},
		{"admin", opts.AdminBaseURL, "/health"},
	}
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var out []supportDiagProbe
	configured := 0
	for _, target := range targets {
		if strings.TrimSpace(target.target) == "" {
			continue
		}
		configured++
		healthURL, err := scopedHealthURL(strings.TrimSpace(target.target), target.path)
		if err != nil {
			out = append(out, supportDiagProbe{Target: target.name, Status: "invalid health URL"})
			continue
		}
		result := probeHealth(ctx, client, healthURL)
		status := result.diagnosis
		if result.canceled {
			return nil, errors.New(supportBundleDiagnosticsError)
		}
		out = append(out, supportDiagProbe{Target: target.name, Status: status})
	}
	if configured == 0 {
		return nil, errors.New(supportBundleDiagProbeTargetError)
	}
	return out, nil
}

// supportDiagOptions carries the operator-selected collection scope. Gateway
// and admin base URLs are pre-resolved by the command layer via doctor's
// resolvers so collection itself stays dependency-free. ScrubProfile "" (zero
// value, unset by internal callers) resolves fail-closed to the standard
// profile; the command layer always passes an explicitly parsed value.
type supportDiagOptions struct {
	Org            string
	LogFiles       []string
	MaxLines       int
	MaxBytes       int64
	Probe          bool
	GatewayBaseURL string
	AdminBaseURL   string
	ScrubProfile   auditlog.ScrubProfile
}

// collectSupportDiagLogs reads bounded tails of operator-named log files and
// returns the org-scoped, profile-scrubbed entries plus the manifest of
// artifacts. The applied scrub profile is recorded in the bundle.
func collectSupportDiagLogs(opts supportDiagOptions) (*supportDiagLogs, []supportDiagManifestEntry, error) {
	profile := auditlog.ParseScrubProfile(string(opts.ScrubProfile))
	logs := &supportDiagLogs{Org: opts.Org, ScrubProfile: string(profile)}
	var manifest []supportDiagManifestEntry
	for _, path := range opts.LogFiles {
		window, truncated, err := readSupportDiagLogTail(path, opts.MaxBytes)
		if err != nil {
			return nil, nil, errors.New(supportBundleDiagLogReadError)
		}
		sum := sha256.Sum256(window)
		file := supportDiagLogFile{
			Name:      filepath.Base(path),
			Bytes:     int64(len(window)),
			Sha256:    hex.EncodeToString(sum[:]),
			Truncated: truncated,
		}
		included, foreignOrg, nonJSON, hits, contentMasks, contentDropped := supportDiagLogLines(window, opts)
		logs.ExcludedForeignOrg += foreignOrg
		logs.ExcludedNonJSON += nonJSON
		logs.RedactionHits += hits
		logs.ContentMasks += contentMasks
		logs.ContentFieldsRemoved += contentDropped
		for _, line := range included {
			file.Lines++
			logs.Entries = append(logs.Entries, supportDiagLogEntry{
				File:    file.Name,
				Line:    len(logs.Entries) + 1,
				Org:     line.org,
				Message: line.message,
			})
		}
		logs.Files = append(logs.Files, file)
		manifest = append(manifest, supportDiagManifestEntry{
			Artifact:  "logs:" + file.Name,
			Bytes:     file.Bytes,
			Sha256:    file.Sha256,
			Truncated: file.Truncated,
			Note:      "bounded tail; redacted org-scoped entries in logs.entries",
		})
	}
	logs.IncludedLines = len(logs.Entries)
	return logs, manifest, nil
}

type supportDiagLogLine struct {
	message string
	org     string
}

// supportDiagLogLines splits the window into lines, applies org scoping and
// then the scrub profile, and returns the includable lines plus the exclusion
// and per-layer scrub counts. The most recent maxLines lines win: earlier
// lines beyond the bound are dropped (bounded recent).
func supportDiagLogLines(window []byte, opts supportDiagOptions) (included []supportDiagLogLine, foreignOrg, nonJSON, credHits, contentMasks, contentDropped int) {
	profile := auditlog.ParseScrubProfile(string(opts.ScrubProfile))
	rawLines := strings.Split(strings.TrimSuffix(string(window), "\n"), "\n")
	if len(rawLines) == 1 && rawLines[0] == "" {
		return nil, 0, 0, 0, 0, 0
	}
	start := 0
	if len(rawLines) > opts.MaxLines {
		start = len(rawLines) - opts.MaxLines
	}
	out := make([]supportDiagLogLine, 0, len(rawLines)-start)
	for _, raw := range rawLines[start:] {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		org, isJSON := supportDiagLogOrg(line)
		if !isJSON {
			nonJSON++
			continue
		}
		if org != "" && (opts.Org == "" || org != opts.Org) {
			foreignOrg++
			continue
		}
		message, lineCred, lineMasks, lineDropped := scrubSupportDiagLineByProfile(line, profile)
		credHits += lineCred
		contentMasks += lineMasks
		contentDropped += lineDropped
		out = append(out, supportDiagLogLine{org: org, message: message})
	}
	return out, foreignOrg, nonJSON, credHits, contentMasks, contentDropped
}

// supportDiagLogOrg extracts a log line's owning organization. Only JSON
// object lines are attributable; the second return value reports whether the
// line is a JSON object at all.
func supportDiagLogOrg(line string) (org string, isJSON bool) {
	var tree map[string]any
	if err := json.Unmarshal([]byte(line), &tree); err != nil || tree == nil {
		return "", false
	}
	for _, key := range supportDiagLogOrgKeys {
		value, present := tree[key]
		if !present {
			continue
		}
		switch typed := value.(type) {
		case string:
			if strings.TrimSpace(typed) != "" {
				return strings.TrimSpace(typed), true
			}
		case map[string]any:
			if id, present := typed["id"]; present {
				if idText, ok := id.(string); ok && strings.TrimSpace(idText) != "" {
					return strings.TrimSpace(idText), true
				}
			}
		}
	}
	return "", true
}

// readSupportDiagLogTail reads at most maxBytes from the end of the file,
// aligned to the first complete line inside the window.
func readSupportDiagLogTail(path string, maxBytes int64) ([]byte, bool, error) {
	if maxBytes < supportDiagMinBytes {
		return nil, false, errors.New(supportBundleDiagLogReadError)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, false, errors.New(supportBundleDiagLogReadError)
	}
	// #nosec G304 -- the operator explicitly names this log file for inclusion.
	file, err := os.Open(path)
	if err != nil {
		return nil, false, errors.New(supportBundleDiagLogReadError)
	}
	defer func() { _ = file.Close() }()
	size := info.Size()
	if size <= maxBytes {
		window := make([]byte, size)
		if _, err := io.ReadFull(file, window); err != nil {
			return nil, false, errors.New(supportBundleDiagLogReadError)
		}
		return window, false, nil
	}
	if _, err := file.Seek(size-maxBytes, io.SeekStart); err != nil {
		return nil, false, errors.New(supportBundleDiagLogReadError)
	}
	window := make([]byte, maxBytes)
	if _, err := io.ReadFull(file, window); err != nil {
		return nil, false, errors.New(supportBundleDiagLogReadError)
	}
	if newline := indexByte(window, '\n'); newline >= 0 && newline+1 < len(window) {
		window = window[newline+1:]
	}
	return window, true, nil
}

func indexByte(window []byte, marker byte) int {
	for i, item := range window {
		if item == marker {
			return i
		}
	}
	return -1
}

// redactSupportDiagLine structurally masks secret-keyed values in JSON lines
// and then masks textual secret shapes; it returns the redacted line and the
// number of masks applied.
func redactSupportDiagLine(line string) (string, int) {
	hits := 0
	out := line
	var tree map[string]any
	if err := json.Unmarshal([]byte(line), &tree); err == nil && tree != nil {
		if masked, changed := supportDiagMaskJSON(tree, &hits); changed {
			if encoded, err := json.Marshal(masked); err == nil {
				out = string(encoded)
			}
		}
	}
	out = supportDiagMaskText(out, &hits)
	return out, hits
}

// supportDiagMaskedValue is the fixed mask sentinel.
const supportDiagMaskedValue = "[REDACTED]"

func supportDiagMaskText(text string, hits *int) string {
	masked := supportDiagBearer.ReplaceAllStringFunc(text, func(match string) string {
		if strings.HasSuffix(match, supportDiagMaskedValue) {
			return match // already masked by the structural pass
		}
		*hits++
		return supportDiagBearer.ReplaceAllString(match, `${1}`+supportDiagMaskedValue)
	})
	return supportDiagSecretKV.ReplaceAllStringFunc(masked, func(match string) string {
		if strings.HasSuffix(match, supportDiagMaskedValue) {
			return match // already masked by the structural pass
		}
		*hits++
		return supportDiagSecretKV.ReplaceAllString(match, `${1}${2}`+supportDiagMaskedValue)
	})
}

func supportDiagMaskJSON(value any, hits *int) (any, bool) {
	switch node := value.(type) {
	case map[string]any:
		changed := false
		for key, child := range node {
			if supportDiagSecretJSONKey.MatchString(key) {
				if _, isTree := child.(map[string]any); !isTree && child != supportDiagMaskedValue {
					node[key] = supportDiagMaskedValue
					*hits++
					changed = true
					continue
				}
			}
			clean, childChanged := supportDiagMaskJSON(child, hits)
			node[key] = clean
			changed = changed || childChanged
		}
		return node, changed
	case []any:
		changed := false
		for i, child := range node {
			clean, childChanged := supportDiagMaskJSON(child, hits)
			node[i] = clean
			changed = changed || childChanged
		}
		return node, changed
	case string:
		before := *hits
		clean := supportDiagMaskText(node, hits)
		return clean, *hits != before
	default:
		return value, false
	}
}

func marshalSupportDiagnostics(payload supportDiagnostics) ([]byte, error) {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, errors.New(supportBundleDiagnosticsError)
	}
	return append(data, '\n'), nil
}

func supportBundleDiagnosticsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "diagnostics",
		Short:        "Preview, consent to, and locally export a schema-v3 diagnostics bundle (versions, sanitized config, health, bounded org-scoped logs)",
		SilenceUsage: true,
	}
	cmd.AddCommand(supportDiagPreviewCmd())
	cmd.AddCommand(supportDiagCreateCmd())
	return cmd
}

func supportDiagPreviewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "preview",
		Short:        "Print the diagnostics bundle without writing a file (--summary for the consent summary)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := supportDiagOptionsFromFlags(cmd)
			if err != nil {
				return err
			}
			payload, err := collectSupportDiagnostics(cmd.Context(), opts)
			if err != nil {
				return err
			}
			data, err := marshalSupportDiagnostics(payload)
			if err != nil {
				return err
			}
			if summary, _ := cmd.Flags().GetBool("summary"); summary {
				out := []byte(renderSupportDiagConsentSummary(&payload, data, supportDiagConsentPreview))
				if n, writeErr := cmd.OutOrStdout().Write(out); writeErr != nil || n != len(out) {
					return errors.New(supportBundleDiagnosticsError)
				}
				return nil
			}
			if n, err := cmd.OutOrStdout().Write(data); err != nil || n != len(data) {
				return errors.New(supportBundleDiagnosticsError)
			}
			return nil
		},
	}
	supportDiagAddFlags(cmd)
	cmd.Flags().Bool("summary", false, "print the consent summary (what the bundle contains) instead of the full JSON")
	return cmd
}

func supportDiagCreateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "create",
		Short:        "Create a local diagnostics bundle file (0600, never overwritten; requires --consent)",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, _ := cmd.Flags().GetString("output")
			if path == "" {
				return errors.New("--output is required")
			}
			consent, _ := cmd.Flags().GetBool("consent")
			digestFlag, _ := cmd.Flags().GetString("consent-digest")
			expectedDigest, err := parseSupportDiagConsentDigest(digestFlag)
			if err != nil {
				return err
			}
			opts, err := supportDiagOptionsFromFlags(cmd)
			if err != nil {
				return err
			}
			payload, err := collectSupportDiagnostics(cmd.Context(), opts)
			if err != nil {
				return err
			}
			data, err := marshalSupportDiagnostics(payload)
			if err != nil {
				return err
			}
			// Consent gate: without the operator's explicit --consent the
			// summary is the whole output and nothing is written — the
			// filesystem is never touched, so a consent refusal always wins
			// over any later failure (e.g. an existing target file).
			if !consent {
				out := []byte(renderSupportDiagConsentSummary(&payload, data, supportDiagConsentRefusal))
				if n, writeErr := cmd.OutOrStdout().Write(out); writeErr != nil || n != len(out) {
					return errors.New(supportBundleDiagnosticsError)
				}
				return errors.New(supportDiagConsentRequiredError)
			}
			// Digest-bound consent: a mismatch means the machine state changed
			// between preview and create; nothing is written.
			if actual := supportDiagConsentDigest(data); expectedDigest != "" && expectedDigest != actual {
				return errors.New(supportDiagConsentDigestMismatchError)
			}
			// #nosec G304 -- The operator selects this output path; O_EXCL prevents replacing an existing file or symlink, and permissions are fixed to 0600.
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return errors.New(supportBundleDiagnosticsError)
			}
			if n, err := file.Write(data); err != nil || n != len(data) {
				_ = file.Close()
				return errors.New(supportBundleDiagnosticsError)
			}
			if err := file.Close(); err != nil {
				return errors.New(supportBundleDiagnosticsError)
			}
			// Everything prints only after a successful local write, so any
			// failure path keeps stdout empty.
			out := append([]byte(renderSupportDiagConsentSummary(&payload, data, supportDiagConsentExported)), data...)
			if n, err := cmd.OutOrStdout().Write(out); err != nil || n != len(out) {
				return errors.New(supportBundleDiagnosticsError)
			}
			return nil
		},
	}
	cmd.Flags().String("output", "", "Path for the newly created local bundle file")
	supportDiagConsentFlags(cmd)
	supportDiagAddFlags(cmd)
	return cmd
}

func supportDiagAddFlags(cmd *cobra.Command) {
	cmd.Flags().StringArray("log-file", nil, "Log file to include as a bounded, redacted, org-scoped tail (repeatable)")
	cmd.Flags().Int("log-max-lines", supportDiagDefaultMaxLines, "Maximum included log lines per file")
	cmd.Flags().Int64("log-max-bytes", supportDiagDefaultMaxBytes, "Maximum tail window in bytes per file")
	cmd.Flags().Bool("probe", false, "Run live health probes against explicitly configured gateway/admin targets (network action)")
	cmd.Flags().String("scrub-profile", string(auditlog.ScrubProfileStandard), "Scrub profile for log entries: minimal (credentials only), standard (credentials, PII, drop customer content), strict (mask every value)")
}

func supportDiagOptionsFromFlags(cmd *cobra.Command) (supportDiagOptions, error) {
	opts := supportDiagOptions{}
	org, _ := cmd.Flags().GetString("org")
	if org == "" {
		org = strings.TrimSpace(os.Getenv("YABANIN_ORG"))
	}
	opts.Org = org
	opts.LogFiles, _ = cmd.Flags().GetStringArray("log-file")
	lines, _ := cmd.Flags().GetInt("log-max-lines")
	if lines < supportDiagMinLines || lines > supportDiagMaxLines {
		return opts, errors.New("--log-max-lines must be between 1 and 10000")
	}
	opts.MaxLines = lines
	bytes, _ := cmd.Flags().GetInt64("log-max-bytes")
	if bytes < supportDiagMinBytes || bytes > supportDiagMaxBytes {
		return opts, errors.New("--log-max-bytes must be between 1024 and 16777216")
	}
	opts.MaxBytes = bytes
	scrubFlag, _ := cmd.Flags().GetString("scrub-profile")
	profile, scrubErr := supportDiagParseScrubFlag(scrubFlag)
	if scrubErr != nil {
		return opts, scrubErr
	}
	opts.ScrubProfile = profile
	opts.Probe, _ = cmd.Flags().GetBool("probe")
	if opts.Probe {
		baseURL, _ := cmd.Flags().GetString("base-url")
		adminURL, _ := cmd.Flags().GetString("admin-url")
		opts.GatewayBaseURL = resolveGatewayURL(baseURL)
		opts.AdminBaseURL = resolveAdminURL(adminURL)
	}
	return opts, nil
}
