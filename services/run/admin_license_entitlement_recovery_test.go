package run

// N11-P05-T08 recovery corpus: interruption / restart / retry / resume
// verification of the offline entitlement wiring at the admin entry point.
// The corpus CONFIRMS the previously supported contract (shipped
// N11-P05-T03..T06 behavior) — every row documents behavior that already
// holds; zero production changes.
//
// Non-duplication contract: T06's five-replica pin and the T07 boundary
// corpus cover steady-state resolution and refusal families. The rows below
// are NEW dynamic scenarios — a replacement document interrupted mid-write,
// a transient disappearance with retries, resolution purity under
// repetition and concurrency, and the operator-visible report chain across
// an interrupted renewal — none of which any existing test feeds.
//
// HONESTY CLAUSE (card requirement): uncertain external effects must not be
// passed off as exactly-once. ResolveEntitlement is a PURE function of the
// environment and the document bytes: it consumes nothing, advances no
// state, writes nothing back and has no once-semantics to enforce. These
// tests pin exactly that — repeatability, statelessness and identical
// results across replicas — and explicitly do NOT claim (nor could any test
// here prove) an exactly-once guarantee; none is owed by this layer.

import (
	"bytes"
	"crypto/ed25519"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reireirei/yabanin/pkg/license"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recoveryIssueToken issues a token with a caller-chosen nonce and returns
// the TOKEN (distinct nonces make the renewal and rollback documents
// independently identifiable). Reachable only with the vendor private key.
func recoveryIssueToken(t *testing.T, priv ed25519.PrivateKey, modules []string, issued, me time.Time, nonce string) string {
	t.Helper()
	token, err := fixtureSignedModuleEntitlement(priv, license.PaidModuleEntitlement{
		CustomerID:     "cust_acme",
		DeploymentID:   "prod-eu-1",
		Modules:        modules,
		IssuedAt:       issued,
		MaintenanceEnd: me,
		Nonce:          nonce,
	}, issued)
	require.NoError(t, err)
	return token
}

// TestModuleEntitlementRecovery_InterruptedDocumentReplacement pins the
// operator's renewal under an INTERRUPTED document replacement: every
// truncation class of the new document (half-written payload, payload
// written without its signature, one byte short) refuses startup with a
// named cause and a nil grant — the running paid term is never silently
// lost — and writing the complete document afterwards recovers fully
// offline, same modules, renewed term.
func TestModuleEntitlementRecovery_InterruptedDocumentReplacement(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{"protection-pack-av", "internal-loop", "media-persistence"}

	// The live document: a PAST maintenance term (the deployment resumed
	// after its term ended — verification has no maintenance gate, I24).
	legacyToken := recoveryIssueToken(t, priv, modules,
		now.Add(-400*day), now.Add(-30*day), "recovery-legacy-0001")
	livePath := filepath.Join(t.TempDir(), "module-entitlement.token")
	require.NoError(t, os.WriteFile(livePath, []byte(legacyToken+"\n"), 0o600))
	t.Setenv(licenseModuleEntitlementFileEnv, livePath)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	resumed, err := resolveModuleEntitlement()
	require.NoError(t, err, "resuming with an ended term must resolve — the paid version continues without renewal")
	require.NotNil(t, resumed)
	assert.False(t, resumed.UpdatesEntitledAt(now), "fixture precondition: the live term has ended")
	assert.True(t, resumed.HasModule("media-persistence"), "the ended term never revokes paid modules (I24)")

	// The renewal document (operator's atomic replacement interrupted
	// mid-write, leaving partial bytes on disk).
	renewedToken := recoveryIssueToken(t, priv, modules,
		now.Add(-time.Hour), now.Add(395*day), "recovery-renewal-0001")

	truncated := []struct {
		name    string
		content string
	}{
		{"half-written payload", renewedToken[:len(renewedToken)/2]},
		{"payload without its signature", renewedToken[:strings.Index(renewedToken, ".")+1]},
		{"one byte short of the signature", renewedToken[:len(renewedToken)-1]},
	}
	for _, tc := range truncated {
		require.NoError(t, os.WriteFile(livePath, []byte(tc.content), 0o600),
			"fixture: interrupted write left %q bytes", tc.name)
		ent, err := resolveModuleEntitlement()
		require.Error(t, err, "an interrupted replacement (%s) must refuse startup, not degrade the grant", tc.name)
		assert.Contains(t, err.Error(), "verify module entitlement",
			"the refusal must name the verify family (envelope damage, not a read failure)")
		assert.Nil(t, ent, "a refused replacement grants nothing")
	}

	// The interrupted write completes: the full renewal document lands.
	require.NoError(t, os.WriteFile(livePath, []byte(renewedToken+"\n"), 0o600))
	renewed, err := resolveModuleEntitlement()
	require.NoError(t, err, "recovery after the interrupted write completes must be a pure offline resolve")
	require.NotNil(t, renewed)
	assert.Equal(t, modules, renewed.Modules, "recovery carries the same paid module list")
	assert.True(t, renewed.UpdatesEntitledAt(now.Add(31*day)),
		"the renewal extends the paid term past the ended one (I24)")
	assert.NotEqual(t, resumed.Nonce, renewed.Nonce, "the replacement is a genuinely new document")
}

// TestModuleEntitlementRecovery_RetryAfterTransientCondition pins the retry
// direction the refusals allow: a transiently absent document refuses
// through the read family; when the document appears, the NEXT resolve
// succeeds with no operator step beyond restoring the bytes; when it
// disappears again, success is not sticky — the absence refuses again; and
// restoring the identical bytes resolves to the identical grant. Refusal
// states are never cached.
func TestModuleEntitlementRecovery_RetryAfterTransientCondition(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	modules := []string{"internal-loop"}
	token := recoveryIssueToken(t, priv, modules, now.Add(-time.Hour), now.Add(365*24*time.Hour), "recovery-retry-0001")
	path := filepath.Join(t.TempDir(), "module-entitlement.token")
	t.Setenv(licenseModuleEntitlementFileEnv, path)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	// Absent: refused (read family), nil grant.
	_, err := resolveModuleEntitlement()
	require.Error(t, err, "an absent document must refuse")
	assert.Contains(t, err.Error(), "read module entitlement file")

	// Appears: the next resolve succeeds — no cached refusal, no extra step.
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	ent1, err := resolveModuleEntitlement()
	require.NoError(t, err, "restoring the document must clear the refusal on the next resolve")
	require.NotNil(t, ent1)

	// Disappears again: success is not sticky — the same configuration now
	// refuses (fail-closed, never a stale grant).
	require.NoError(t, os.Remove(path))
	_, err = resolveModuleEntitlement()
	require.Error(t, err, "a disappeared document must refuse again — no sticky success")
	assert.Contains(t, err.Error(), "read module entitlement file")

	// Restored byte-identically: identical grant.
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	ent2, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, ent2)
	assert.Equal(t, ent1, ent2, "restoring the identical bytes resolves to the identical grant")
}

// TestModuleEntitlementRecovery_ResolveIsPureAndRepeatable pins resolution
// purity: five resolves of the same configuration return identical grants,
// and the resolve leaves the document bytes, file mode, directory contents
// and environment untouched — nothing consumed, nothing written back, no
// hidden state. Per the honesty clause: this pins repeatability and
// statelessness; it does NOT (and cannot) prove exactly-once — no such
// semantics exist in this layer, and none is claimed.
func TestModuleEntitlementRecovery_ResolveIsPureAndRepeatable(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	modules := []string{"protection-pack-av", "internal-loop"}
	token := recoveryIssueToken(t, priv, modules, now.Add(-time.Hour), now.Add(30*24*time.Hour), "recovery-purity-0001")
	path := filepath.Join(t.TempDir(), "module-entitlement.token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	t.Setenv(licenseModuleEntitlementFileEnv, path)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	snapshot := func(t *testing.T) ([]byte, os.FileMode, []string) {
		t.Helper()
		data, err := os.ReadFile(path) //nolint:gosec // G304: test fixture path built in this test (same class as the production operator-configured path)
		require.NoError(t, err)
		info, err := os.Stat(path)
		require.NoError(t, err)
		entries, err := os.ReadDir(filepath.Dir(path))
		require.NoError(t, err)
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		return data, info.Mode(), names
	}
	beforeData, beforeMode, beforeEntries := snapshot(t)

	var first *license.PaidModuleEntitlement
	for i := 0; i < 5; i++ {
		ent, err := resolveModuleEntitlement()
		require.NoError(t, err, "resolve %d must succeed", i)
		require.NotNil(t, ent)
		if i == 0 {
			first = ent
			continue
		}
		assert.Equal(t, first, ent, "resolve %d drifted — resolution is pure", i)
	}

	afterData, afterMode, afterEntries := snapshot(t)
	assert.Equal(t, beforeData, afterData, "the resolve must not rewrite the document")
	assert.Equal(t, beforeMode, afterMode, "the resolve must not change the file mode")
	assert.Equal(t, beforeEntries, afterEntries, "the resolve must not add sidecar state files")
	assert.Equal(t, token+"\n", string(afterData), "document bytes stay exactly as installed")
}

// TestModuleEntitlementRecovery_ConcurrentReplicasResolve pins replica
// independence under concurrency: every simultaneous resolve of the same
// document returns the identical grant — HA/DR replicas of the contour
// (I23) share one document without coordination. The race detector is the
// point of running this under -race.
func TestModuleEntitlementRecovery_ConcurrentReplicasResolve(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	modules := []string{"internal-loop", "media-persistence"}
	token := recoveryIssueToken(t, priv, modules, now.Add(-time.Hour), now.Add(365*24*time.Hour), "recovery-replicas-0001")
	path := filepath.Join(t.TempDir(), "module-entitlement.token")
	require.NoError(t, os.WriteFile(path, []byte(token+"\n"), 0o600))
	t.Setenv(licenseModuleEntitlementFileEnv, path)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	const replicas = 8
	start := make(chan struct{})
	results := make([]*license.PaidModuleEntitlement, replicas)
	errs := make([]error, replicas)
	var wg sync.WaitGroup
	for i := 0; i < replicas; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = resolveModuleEntitlement()
		}(i)
	}
	close(start)
	wg.Wait()

	for i := 0; i < replicas; i++ {
		require.NoError(t, errs[i], "replica %d resolve failed", i)
		require.NotNil(t, results[i], "replica %d granted nothing", i)
		assert.Equal(t, results[0], results[i], "replica %d resolved a different grant", i)
	}
	assert.True(t, results[0].HasModule("media-persistence"), "fixture precondition: the shared grant carries its modules")
}

// TestModuleEntitlementRecovery_RestartChainObservableReports pins the
// operator-visible startup report across a renewal/rollback chain with an
// interrupted replacement in the middle: the report is emitted ONLY on a
// successful resolve (an interrupted replacement adds no report and no
// state), the renewal honestly reports the extended term, the rollback
// honestly reports the old term, and trial fields exist only when a signed
// trial exists. The report is a local sink write (observational per I24),
// never an enforcement input.
func TestModuleEntitlementRecovery_RestartChainObservableReports(t *testing.T) {
	pinEntitlementEnvClean(t)
	pub, priv := entitlementWiringKeys(t)
	swapVendorKey(t, pub)

	now := time.Now()
	day := 24 * time.Hour
	modules := []string{"protection-pack-av", "internal-loop", "media-persistence"}
	legacyToken := recoveryIssueToken(t, priv, modules, now.Add(-400*day), now.Add(-30*day), "recovery-report-a-0001")
	renewedToken := recoveryIssueToken(t, priv, modules, now.Add(-time.Hour), now.Add(395*day), "recovery-report-b-0001")
	meB := now.Add(395 * day)

	livePath := filepath.Join(t.TempDir(), "module-entitlement.token")
	require.NoError(t, os.WriteFile(livePath, []byte(legacyToken+"\n"), 0o600))
	t.Setenv(licenseModuleEntitlementFileEnv, livePath)
	t.Setenv(licenseModuleEntitlementDeploymentEnv, "prod-eu-1")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reportCount := func(t *testing.T) int {
		t.Helper()
		return strings.Count(buf.String(), "paid-module entitlement verified (offline)")
	}

	// Restart 1: the ended-term document resolves and honestly reports it.
	resumed, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, resumed)
	logModuleEntitlementStatus(logger, resumed)
	require.Equal(t, 1, reportCount(t), "exactly one report after the first successful resolve")
	line1 := buf.String()[strings.LastIndex(buf.String(), "paid-module entitlement verified (offline)"):]
	assert.Contains(t, line1, "modules=3", "the report names the signed module count")
	assert.Contains(t, line1, "maintenance_ended=true", "an ended term is reported honestly")
	assert.Contains(t, line1, "updates_entitled=false", "the renewal-gated status is honest at the entry point")
	assert.NotContains(t, line1, "trial_", "no trial fields exist when no signed trial exists")

	// Interrupted replacement: refusal — no report, no state change.
	require.NoError(t, os.WriteFile(livePath, []byte(renewedToken[:len(renewedToken)/2]), 0o600))
	_, err = resolveModuleEntitlement()
	require.Error(t, err, "the interrupted replacement refuses startup")
	assert.Equal(t, 1, reportCount(t), "a refused resolve emits no report — startup refuses before reporting")

	// Restart 2: the renewal lands — the extended term is reported honestly.
	require.NoError(t, os.WriteFile(livePath, []byte(renewedToken+"\n"), 0o600))
	renewed, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, renewed)
	logModuleEntitlementStatus(logger, renewed)
	require.Equal(t, 2, reportCount(t), "exactly one report per successful resolve")
	line2 := buf.String()[strings.LastIndex(buf.String(), "paid-module entitlement verified (offline)"):]
	assert.Contains(t, line2, "maintenance_ended=false", "the renewed term is running")
	assert.Contains(t, line2, "updates_entitled=true", "the renewed term entitles updates")
	assert.Contains(t, line2, "maintenance_end="+meB.UTC().Format(time.RFC3339),
		"the report carries the signed term end (issuance normalizes to UTC)")

	// Restart 3: rollback to the previous document — status reverts
	// honestly, modules keep running (I24).
	require.NoError(t, os.WriteFile(livePath, []byte(legacyToken+"\n"), 0o600))
	rolledBack, err := resolveModuleEntitlement()
	require.NoError(t, err)
	require.NotNil(t, rolledBack)
	logModuleEntitlementStatus(logger, rolledBack)
	require.Equal(t, 3, reportCount(t), "exactly one report per successful resolve")
	line3 := buf.String()[strings.LastIndex(buf.String(), "paid-module entitlement verified (offline)"):]
	assert.Contains(t, line3, "updates_entitled=false", "the rollback honestly reverts the update status")
	assert.True(t, rolledBack.HasModule("internal-loop"), "the rollback never revokes paid modules")

	assert.Equal(t, 3, reportCount(t), "three restarts, three reports, nothing else")
}
