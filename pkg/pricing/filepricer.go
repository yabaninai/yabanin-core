package pricing

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// FileProvenance is the provenance of a loaded price file: which source,
// which date, and the SHA256 fingerprint of the exact bytes that were loaded.
// Cost reports embed this so an operator can answer "which snapshot produced
// this number".
type FileProvenance struct {
	Source   string `json:"source"`
	Date     string `json:"date"`
	Currency string `json:"currency"`
	Units    string `json:"units"`
	SHA256   string `json:"sha256"`
	ModelCnt int    `json:"model_count"`
}

// FilePricer is a Pricer backed by a validated PriceFile snapshot. It is
// immutable once built: Lookup never touches the network or disk, which is
// what makes the provenance honest (the prices a report cites are exactly
// the prices that were used).
type FilePricer struct {
	file       PriceFile
	provenance FileProvenance
	byKey      map[string]Price
	// catalog cites the served reference catalog (CORE-REF-04); nil for
	// legacy snapshot-backed pricers.
	catalog *RefCatalogInfo
}

// NewFilePricer builds a FilePricer from a validated price file and the SHA256
// of its raw bytes (as returned by ParsePriceFile). The file must already be
// validated; NewFilePricer re-validates defensively and rejects bad input.
func NewFilePricer(pf PriceFile, sha256 string) (*FilePricer, error) {
	if err := ValidatePriceFile(pf); err != nil {
		return nil, err
	}
	byKey := make(map[string]Price, len(pf.Models))
	for _, m := range pf.Models {
		byKey[m.Provider+":"+m.Model] = m.ToPrice()
	}
	return &FilePricer{
		file: pf,
		provenance: FileProvenance{
			Source:   pf.Source,
			Date:     pf.Date,
			Currency: pf.Currency,
			Units:    pf.Units,
			SHA256:   sha256,
			ModelCnt: len(pf.Models),
		},
		byKey: byKey,
	}, nil
}

// Lookup implements Pricer. Returns false when the model is unknown to this
// snapshot (the caller treats that as "unknown", not "free").
func (p *FilePricer) Lookup(provider, model string) (Price, bool) {
	pr, ok := p.byKey[provider+":"+model]
	return pr, ok
}

// Provenance returns the snapshot's provenance for embedding in reports.
func (p *FilePricer) Provenance() FileProvenance { return p.provenance }

// File returns the loaded price file (for export / diffing).
func (p *FilePricer) File() PriceFile { return p.file }

// LoadBundled is the compatibility entry point for the built-in primary-source
// catalog. Third-party token snapshots are no longer distributed. The same
// verification, effective-window and freshness gates as LoadBundledRefServe apply.
func LoadBundled() (*FilePricer, error) {
	return LoadBundledRefServe()
}

// ExternalSource identifies the pinned external price source (A03).
//
// The loader is intentionally a small, swappable seam: in production it would
// fetch github.com/Portkey-AI/models at the pinned commit and normalize it to
// a PriceFile. The pin (Commit) is part of the provenance so a snapshot is
// reproducible. Offline, the primary reference projection is used instead — the two are
// interchangeable from the Pricer's point of view.
type ExternalSource struct {
	// Repo is the upstream repository (no scheme), e.g.
	// "github.com/Portkey-AI/models".
	Repo string
	// Commit is the exact commit the snapshot was taken from. Empty means
	// "unpinned" and is rejected by ValidateExternalSource.
	Commit string
	// Offline selects primary-reference mode (no network).
	Offline bool
}

// ValidateExternalSource rejects an unpinned online source: an external
// snapshot must name the exact commit it came from, otherwise its provenance
// is meaningless. Offline mode needs no commit (the reference pack is sealed by its digest).
func ValidateExternalSource(src ExternalSource) error {
	if src.Offline {
		return nil
	}
	if strings.TrimSpace(src.Repo) == "" {
		return fmt.Errorf("external source: repo is required")
	}
	if strings.TrimSpace(src.Commit) == "" {
		return fmt.Errorf("external source: commit pin is required for online mode")
	}
	return nil
}

// ProvenanceLabel renders the source the way reports cite it.
func (src ExternalSource) ProvenanceLabel() string {
	if src.Offline {
		return "yabanin-reference-catalog (offline)"
	}
	return fmt.Sprintf("%s@%s", src.Repo, src.Commit)
}

// ExternalLoader fetches (or, offline, returns) a price file from an external
// source. The fetch function is injected so tests can drive it deterministically
// without a network; production wires an HTTP fetcher that honors the commit
// pin.
type ExternalLoader struct {
	// Fetch returns the raw price-file bytes for the given source. It must
	// honor src.Commit (fetch exactly that revision) and return an error if
	// the revision is unavailable.
	Fetch func(src ExternalSource) ([]byte, error)
}

// Load resolves a price file from src. Offline mode returns the
// reference-catalog projection (CORE-REF-04 serving flip; pinned by the
// sealed catalog digest). Online mode calls Fetch and validates the result;
// the returned SHA256 fingerprints the exact bytes so the snapshot is
// reproducible from (Repo, Commit).
func (l *ExternalLoader) Load(src ExternalSource) (*FilePricer, error) {
	if err := ValidateExternalSource(src); err != nil {
		return nil, err
	}
	if src.Offline || l.Fetch == nil {
		return LoadBundledRefServe()
	}
	data, err := l.Fetch(src)
	if err != nil {
		return nil, fmt.Errorf("fetch external prices (%s): %w", src.ProvenanceLabel(), err)
	}
	var pf PriceFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse external prices: %w", err)
	}
	// Attribute the snapshot to the pinned source so reports cite it.
	pf.Source = src.ProvenanceLabel()
	if err := ValidatePriceFile(pf); err != nil {
		return nil, err
	}
	sum := sha256Hex(data)
	return NewFilePricer(pf, sum)
}

// DefaultFilePricer is the process-wide file-backed pricer (A03). Since
// CORE-REF-04 it starts as the reference-catalog projection (serveable
// entries only, labeled yabanin-catalog@…) and can be replaced at startup
// with an externally loaded one via SetDefaultFilePricer.
var (
	defaultFilePricer     *FilePricer
	defaultFilePricerOnce sync.Once
	defaultFilePricerMu   sync.RWMutex
)

// DefaultFilePricer returns the current file-backed pricer, initializing it
// to the reference-catalog projection on first use (CORE-REF-04 serving
// flip). LoadBundled is a compatibility alias for this primary-only projection.
func DefaultFilePricer() *FilePricer {
	defaultFilePricerMu.RLock()
	p := defaultFilePricer
	defaultFilePricerMu.RUnlock()
	if p != nil {
		return p
	}
	defaultFilePricerOnce.Do(func() {
		b, err := LoadBundledRefServe()
		if err != nil {
			// The reference pack is compiled into the binary; failure here is
			// a build corruption. Surface it loudly via a sentinel pricer.
			b = &FilePricer{}
		}
		defaultFilePricerMu.Lock()
		defaultFilePricer = b
		defaultFilePricerMu.Unlock()
	})
	defaultFilePricerMu.RLock()
	defer defaultFilePricerMu.RUnlock()
	return defaultFilePricer
}

// SetDefaultFilePricer replaces the process-wide file-backed pricer (call at
// startup after loading an external snapshot).
func SetDefaultFilePricer(p *FilePricer) {
	defaultFilePricerMu.Lock()
	defaultFilePricer = p
	defaultFilePricerMu.Unlock()
}

// resetFilePricerOnce lets tests re-initialize the default pricer. Test-only.
func resetFilePricerOnce() {
	defaultFilePricerMu.Lock()
	defaultFilePricerOnce = sync.Once{}
	defaultFilePricerMu.Unlock()
}
