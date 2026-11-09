package catalogs

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/pricing"
)

// ProvenanceLabel renders the REF-04 preview label contract:
//
//	yabanin-catalog@<version> <generated_at date> sha256:<digest>
//
// The label identifies WHICH catalog produced a price. It is a source
// citation, not a freshness claim: the reviewer and review date are
// separate metadata (REF-04 wires them into the pricing metadata surface),
// and the digest part is the only thing that pins content.
//
// The label names the Yabanin artifact only — upstream attribution of
// derived entries lives at entry level (sources), never in the label: the
// label is OUR citation, the entry sources are the honest derivation
// records. Fail closed on unsealed input: a label without a verified
// digest would be an uncheckable claim.
func ProvenanceLabel(c pricing.Catalog) (string, error) {
	if c.Digest == "" {
		return "", fmt.Errorf("provenance label: catalog is not sealed (digest empty); seal with pricing.SealCatalog / MarshalCatalog first")
	}
	if !isLabelDigestHex(c.Digest) {
		return "", fmt.Errorf("provenance label: catalog digest is not 64-hex (%q)", c.Digest)
	}
	if err := pricing.ValidateRefTime(c.GeneratedAt); err != nil {
		return "", fmt.Errorf("provenance label: generated_at: %w", err)
	}
	date := c.GeneratedAt
	if len(date) > 10 {
		date = date[:10]
	}
	if err := pricing.ValidateRefTime(date); err != nil {
		return "", fmt.Errorf("provenance label: generated_at date part: %w", err)
	}
	return fmt.Sprintf("yabanin-catalog@%s %s sha256:%s", c.Version, date, c.Digest), nil
}

// isLabelDigestHex reports whether s is a lowercase-or-mixed 64-hex digest.
func isLabelDigestHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// LabelDigest is the digest part of the label as a bare string (structural
// metadata for REF-04's structured pricing metadata, which needs the digest
// without the prose). Fails closed on unsealed catalogs like ProvenanceLabel.
func LabelDigest(c pricing.Catalog) (string, error) {
	if !isLabelDigestHex(c.Digest) {
		return "", fmt.Errorf("label digest: catalog is not sealed (digest empty or malformed)")
	}
	return strings.ToLower(c.Digest), nil
}
