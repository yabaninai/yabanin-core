package upstream

// Recovery corpus for the catalog installation primitive: the arcs an
// installation experiences when a refresh is interrupted, a bad revision
// fails mid-build, the same document is retried, snapshots are swapped
// while consumers read them, and a stale revision is retried after a newer
// one. Every arc pins the observable contract — a failed or interrupted
// attempt leaves the previous snapshot intact and serving, a retry
// recovers the full result without duplicates or losses, and every
// installed snapshot stays attributable through its version/source/as_of
// metadata.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

// recoveryVendorBytes is the raw vendor snapshot for the recovery arcs: one
// row with an alias, plus the end-of-life announcement when deprecated is
// set.
func recoveryVendorBytes(t *testing.T, version string, model string, deprecated bool) []byte {
	t.Helper()
	doc := CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       version,
		Source:        "recovery-walk",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{{
			Provider:      "openai",
			Model:         model,
			Aliases:       []string{model + "-mini"},
			Capabilities:  map[string]bool{"chat": true},
			Price:         &CatalogPrice{Input: 2.5, Output: 10},
			EffectiveFrom: "2023-01-01",
			EffectiveTo:   "2025-06-01",
		}},
	}
	if deprecated {
		doc.Models[0].DeprecatedAt = "2024-03-01"
	}
	return jointDocBytes(t, doc)
}

// errReader delivers a prefix of the payload and then fails with
// sendErr — the byte-level shape of an interrupted document transfer:
// the connection dies mid-stream, after a partial body arrived.
type errReader struct {
	data    []byte
	off     int
	limit   int
	sendErr error
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.off >= r.limit {
		return 0, r.sendErr
	}
	n := copy(p, r.data[r.off:min(r.off+len(p), r.limit)])
	r.off += n
	return n, nil
}

// restoreInstalledCatalog swaps the process-wide catalog back when the test
// finishes, so -shuffle order can never leak install state between tests.
func restoreInstalledCatalog(t *testing.T) {
	t.Helper()
	prev := provider.CurrentModelCatalog()
	t.Cleanup(func() { provider.SetModelCatalog(prev) })
}

// TestRecoveryInterruptedTransferArc walks the interruption arc through the
// real byte path: a live snapshot serves, a refresh dies mid-transfer, the
// live snapshot keeps serving unchanged, and the retry with the complete
// bytes recovers the full result — every row and alias of the new revision
// present, nothing from the failed attempt left behind.
func TestRecoveryInterruptedTransferArc(t *testing.T) {
	restoreInstalledCatalog(t)

	// Phase 1 — the live revision: an announced-EOL snapshot installed
	// and serving.
	liveRaw := recoveryVendorBytes(t, "recovery-rev-1", "gpt-alpha", true)
	live, liveSum, err := InstallCatalog(bytes.NewReader(liveRaw))
	if err != nil {
		t.Fatalf("live install: %v", err)
	}
	if !live.Deprecated("openai", "gpt-alpha", jAnnounced) {
		t.Fatal("the live revision must flag the announced end of life")
	}
	if !provider.ProviderAdmitted("openai") {
		t.Fatal("sanity: the live snapshot's provider must be admitted")
	}

	// Phase 2 — the refresh is interrupted mid-transfer: a prefix of the
	// new bytes arrives, then the stream dies. The parse must fail and
	// the live snapshot must stay installed untouched.
	freshRaw := recoveryVendorBytes(t, "recovery-rev-2", "gpt-beta", false)
	interrupted := &errReader{data: freshRaw, limit: len(freshRaw) / 2, sendErr: io.ErrUnexpectedEOF}
	if _, _, err := InstallCatalog(interrupted); err == nil {
		t.Fatal("an interrupted transfer must fail the install")
	} else if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("the failure must carry the read error, got: %v", err)
	}
	if provider.CurrentModelCatalog() != live {
		t.Fatal("the interrupted refresh must not displace the live snapshot")
	}
	if _, st := live.Lookup("openai", "gpt-alpha", jOpened); st != provider.StatusActive {
		t.Fatalf("the live snapshot must keep serving after the interruption, got %v", st)
	}
	if !live.Deprecated("openai", "gpt-alpha", jAnnounced) {
		t.Fatal("the live snapshot must keep its retirement facts after the interruption")
	}

	// Phase 3 — the retry with the complete bytes recovers the full
	// result of the new revision.
	recovered, sum, err := InstallCatalog(bytes.NewReader(freshRaw))
	if err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if provider.CurrentModelCatalog() != recovered {
		t.Fatal("the retry must install the recovered snapshot process-wide")
	}
	if recovered.Version() != "recovery-rev-2" {
		t.Fatalf("recovered revision = %q", recovered.Version())
	}
	if got := recovered.EntryCount(); got != 1 {
		t.Fatalf("recovered entries = %d, want exactly the new revision's row (no residue)", got)
	}
	for _, name := range []string{"gpt-beta", "gpt-beta-mini"} {
		if _, st := recovered.Lookup("openai", name, jOpened); st != provider.StatusActive {
			t.Fatalf("the recovered name %s must serve, got %v", name, st)
		}
	}
	if _, st := recovered.Lookup("openai", "gpt-alpha", jOpened); st == provider.StatusActive {
		t.Fatal("the old revision's row must be gone after the recovery")
	}
	// The fingerprint pins exactly which bytes the recovery installed.
	if sum == "" || sum == liveSum {
		t.Fatalf("recovery fingerprint must name the new bytes: %q", sum)
	}
	if _, sumAgain, err := ParseCatalogDocument(bytes.NewReader(freshRaw)); err != nil || sumAgain != sum {
		t.Fatalf("recovered fingerprint must be reproducible: %q vs %q (%v)", sumAgain, sum, err)
	}
}

// TestRecoveryFailedMergeLeavesNoTornState walks the failure-after-parse
// arc: the document decodes and passes document validation, but the merged
// name space rejects it at build (the override alias collides with a vendor
// alias — document validation leaves vendor-space collisions to the merge
// on purpose). The failed merge must leave no torn state: the live snapshot
// keeps its identity and its complete namespace, and no attribute of the
// failed revision (the custom row, the colliding alias) is visible.
func TestRecoveryFailedMergeLeavesNoTornState(t *testing.T) {
	restoreInstalledCatalog(t)

	liveRaw := recoveryVendorBytes(t, "merge-rev-1", "gpt-alpha", false)
	live, _, err := InstallCatalog(bytes.NewReader(liveRaw))
	if err != nil {
		t.Fatalf("live install: %v", err)
	}
	liveRows := len(live.Entries())

	// The bad revision: passes document validation (cross-override
	// uniqueness is clean, nothing shadows its own model) but the merged
	// space would carry the vendor alias twice.
	torn := CatalogDocument{
		SchemaVersion: CatalogSchemaV2,
		Version:       "merge-rev-2",
		Source:        "recovery-walk",
		AsOf:          "2024-06-01",
		Models: []CatalogModelEntry{{
			Provider:      "openai",
			Model:         "gpt-alpha",
			Aliases:       []string{"gpt-alpha-mini"},
			Capabilities:  map[string]bool{"chat": true},
			Price:         &CatalogPrice{Input: 2.5, Output: 10},
			EffectiveFrom: "2023-01-01",
			EffectiveTo:   "2025-06-01",
		}},
		Customizations: []CatalogOverride{{
			Provider:     "openai",
			Model:        "other-local",
			Aliases:      []string{"gpt-alpha-mini"},
			Capabilities: map[string]bool{"chat": true},
		}},
	}
	// The document itself must be clean — the finding is merge-only.
	if err := ValidateCatalogDocument(torn); err != nil {
		t.Fatalf("torn fixture must pass document validation: %v", err)
	}
	tornRaw, err := json.Marshal(torn)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, _, err := InstallCatalog(bytes.NewReader(tornRaw)); err == nil {
		t.Fatal("the vendor-alias collision must fail the merged build")
	} else if !strings.Contains(err.Error(), "duplicate alias") {
		t.Fatalf("the merge failure must name the collision: %v", err)
	}

	if provider.CurrentModelCatalog() != live {
		t.Fatal("the failed merge must not displace the live snapshot")
	}
	if got := len(live.Entries()); got != liveRows {
		t.Fatalf("live namespace size changed after a failed merge: %d -> %d", liveRows, got)
	}
	// No attribute of the failed revision is visible anywhere: the
	// colliding alias still resolves to the vendor row only, and the
	// custom row does not exist.
	if m, _ := live.ResolveAlias("openai", "gpt-alpha-mini", jOpened); m != "gpt-alpha" {
		t.Fatalf("the colliding alias must still resolve to the vendor row, got %q", m)
	}
	if _, ok := live.Entry("openai", "other-local"); ok {
		t.Fatal("the failed revision's custom row must not be visible")
	}
}

// TestRecoveryReinstallIdempotent walks the retry-after-success arc:
// installing the exact same bytes again is a no-op at the namespace level —
// same fingerprint, same rows, same retirement facts, same lookup answers —
// and never duplicates a row.
func TestRecoveryReinstallIdempotent(t *testing.T) {
	restoreInstalledCatalog(t)

	raw := recoveryVendorBytes(t, "idem-rev-1", "gpt-alpha", true)
	first, sum1, err := InstallCatalog(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("first install: %v", err)
	}

	for attempt := 2; attempt <= 3; attempt++ {
		again, sum2, err := InstallCatalog(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("re-install %d: %v", attempt, err)
		}
		if sum2 != sum1 {
			t.Fatalf("re-install %d fingerprint changed: %q -> %q", attempt, sum1, sum2)
		}
		want, got := first.Entries(), again.Entries()
		if len(got) != len(want) {
			t.Fatalf("re-install %d namespace size = %d, want %d (no duplicates)", attempt, len(got), len(want))
		}
		for i := range want {
			if got[i].Provider != want[i].Provider || got[i].Model != want[i].Model ||
				len(got[i].Aliases) != len(want[i].Aliases) || !got[i].DeprecatedAt.Equal(want[i].DeprecatedAt) {
				t.Fatalf("re-install %d row %d drifted: %+v vs %+v", attempt, i, got[i], want[i])
			}
		}
		if gotW, wantW := again.Withdrawals(), first.Withdrawals(); len(gotW) != len(wantW) {
			t.Fatalf("re-install %d withdrawals = %d, want %d", attempt, len(gotW), len(wantW))
		}
		// Consumer answers are identical before and after the re-install.
		for _, probe := range []string{"gpt-alpha", "gpt-alpha-mini"} {
			_, st1 := first.Lookup("openai", probe, jAnnounced)
			_, st2 := again.Lookup("openai", probe, jAnnounced)
			if st1 != st2 {
				t.Fatalf("re-install %d changed the answer for %s: %v -> %v", attempt, probe, st1, st2)
			}
		}
		if first.Deprecated("openai", "gpt-alpha", jAnnounced) != again.Deprecated("openai", "gpt-alpha", jAnnounced) {
			t.Fatalf("re-install %d changed the retirement flag", attempt)
		}
	}
}

// TestRecoveryConcurrentSwapCoherence walks the swap-under-load arc:
// writers install alternating revisions while readers consult the
// process-wide snapshot. Every reader observation must be coherent — a
// reader that takes the snapshot pointer once sees exactly one complete
// revision, never a mix and never nil — and under -race the arc doubles as
// the concurrency regression check for the atomic swap.
func TestRecoveryConcurrentSwapCoherence(t *testing.T) {
	restoreInstalledCatalog(t)

	rawX := recoveryVendorBytes(t, "swap-rev-x", "gpt-alpha", false)
	rawY := recoveryVendorBytes(t, "swap-rev-y", "gpt-beta", true)
	if _, _, err := InstallCatalog(bytes.NewReader(rawX)); err != nil {
		t.Fatalf("baseline install: %v", err)
	}

	const writers = 4
	const readers = 4
	const iterations = 30
	var wg sync.WaitGroup
	stop := make(chan struct{})
	failCh := make(chan error, writers+readers)

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			raw := rawX
			if w%2 == 1 {
				raw = rawY
			}
			for i := 0; i < iterations; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if _, _, err := InstallCatalog(bytes.NewReader(raw)); err != nil {
					failCh <- err
					return
				}
			}
		}(w)
	}
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				select {
				case <-stop:
					return
				default:
				}
				// One pointer read per observation: everything checked
				// below belongs to the same immutable snapshot.
				c := provider.CurrentModelCatalog()
				if c == nil {
					failCh <- errors.New("reader observed a nil catalog mid-swap")
					return
				}
				switch c.Version() {
				case "swap-rev-x":
					if c.EntryCount() != 1 {
						failCh <- errors.New("rev-x observed with a torn namespace")
						return
					}
					if _, st := c.Lookup("openai", "gpt-alpha", jOpened); st != provider.StatusActive {
						failCh <- errors.New("rev-x observed without its own row")
						return
					}
					if _, st := c.Lookup("openai", "gpt-beta", jOpened); st == provider.StatusActive {
						failCh <- errors.New("rev-x observed carrying rev-y's row (mixed observation)")
						return
					}
				case "swap-rev-y":
					if c.EntryCount() != 1 {
						failCh <- errors.New("rev-y observed with a torn namespace")
						return
					}
					if _, st := c.Lookup("openai", "gpt-beta", jOpened); st != provider.StatusActive {
						failCh <- errors.New("rev-y observed without its own row")
						return
					}
					if !c.Deprecated("openai", "gpt-beta", jAnnounced) {
						failCh <- errors.New("rev-y observed without its retirement fact")
						return
					}
				default:
					failCh <- errors.New("reader observed an unknown revision: " + c.Version())
					return
				}
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case err := <-failCh:
		close(stop)
		<-done
		t.Fatalf("swap-arc failure: %v", err)
	}
	close(stop)
	select {
	case err := <-failCh:
		t.Fatalf("swap-arc failure: %v", err)
	default:
	}

	// After the storm the installed snapshot is one complete revision.
	final := provider.CurrentModelCatalog()
	if final == nil || (final.Version() != "swap-rev-x" && final.Version() != "swap-rev-y") {
		t.Fatalf("final snapshot version = %v, want one complete revision", final)
	}
	if final.EntryCount() != 1 {
		t.Fatalf("final namespace size = %d, want exactly one row (no duplicates)", final.EntryCount())
	}
}

// TestRecoveryStaleRetryDowngradeIsObservable pins the stale-retry
// boundary honestly: the installation primitive installs whatever document
// it is given, so retrying a stale revision without the end-of-life
// announcement after a revision carrying it succeeds and the retirement
// flag disappears — the catalog reflects the document, and a rollback to an
// older revision is therefore a legitimate recovery operation. What keeps
// the downgrade from being a silent loss is attribution: the snapshot
// exposes the revision, source and as-of it was built from, so every
// consumer view can name the stale revision it is serving. Revision
// monotonicity is an operator policy above this primitive, not a property
// of it (classified residue for the packet review).
func TestRecoveryStaleRetryDowngradeIsObservable(t *testing.T) {
	restoreInstalledCatalog(t)

	freshRaw := recoveryVendorBytes(t, "stale-rev-2", "gpt-alpha", true)
	fresh, _, err := InstallCatalog(bytes.NewReader(freshRaw))
	if err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if !fresh.Deprecated("openai", "gpt-alpha", jAnnounced) {
		t.Fatal("the fresh revision must flag the announced end of life")
	}

	staleRaw := recoveryVendorBytes(t, "stale-rev-1", "gpt-alpha", false)
	stale, sum, err := InstallCatalog(bytes.NewReader(staleRaw))
	if err != nil {
		t.Fatalf("stale retry: %v", err)
	}
	if provider.CurrentModelCatalog() != stale {
		t.Fatal("the stale retry must install what it was given")
	}
	if stale.Deprecated("openai", "gpt-alpha", jAnnounced) {
		t.Fatal("a revision without the announcement must not flag deprecation (pinned downgrade)")
	}
	// Attribution stays intact: the snapshot names the stale revision,
	// its source and its as-of, so the downgrade is inspectable drift.
	if stale.Version() != "stale-rev-1" || stale.Source() != "recovery-walk" {
		t.Fatalf("stale snapshot attribution = %q/%q", stale.Version(), stale.Source())
	}
	if stale.AsOf().IsZero() {
		t.Fatal("stale snapshot must carry its as-of instant")
	}
	if _, sumStale, err := ParseCatalogDocument(bytes.NewReader(staleRaw)); err != nil || sumStale != sum {
		t.Fatalf("stale fingerprint must name the stale bytes: %q vs %q (%v)", sumStale, sum, err)
	}
}
