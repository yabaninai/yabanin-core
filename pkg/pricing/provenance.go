package pricing

import (
	"crypto/sha256"
	_ "embed"
	"fmt"
)

//go:embed pricing.go
var embeddedPriceSource []byte

// Provenance identifies the bundled price implementation without claiming freshness.
type Provenance struct {
	Source  string `json:"source"`
	Version string `json:"version"`
	AsOf    string `json:"as_of"`
	Note    string `json:"note"`
}

// Snapshot fingerprints the bundled table source; upstream verification date is unknown.
//
// Deprecated (A03): use DefaultFilePricer().Provenance() to cite the actual
// price-file snapshot a report was computed against. Snapshot is kept for
// backward compatibility and now delegates to the file-backed pricer when it
// is available, falling back to the legacy embedded-table fingerprint.
func Snapshot() Provenance {
	if p := DefaultFilePricer(); p != nil && p.Provenance().SHA256 != "" {
		fp := p.Provenance()
		return Provenance{
			Source:  fp.Source,
			Version: fp.SHA256,
			AsOf:    fp.Date,
			Note:    "Usage-based estimate, not invoice reconciliation. Cached-token discounts, negotiated rates and provider service tiers are not included in audit totals.",
		}
	}
	return Provenance{
		Source:  "pkg/pricing/pricing.go (bundled historical list prices)",
		Version: fmt.Sprintf("sha256:%x", sha256.Sum256(embeddedPriceSource)),
		AsOf:    "unknown — upstream verification date not recorded",
		Note:    "Usage-based estimate, not invoice reconciliation. Cached-token discounts, negotiated rates and provider service tiers are not included in audit totals.",
	}
}
