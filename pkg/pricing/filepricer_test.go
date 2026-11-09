package pricing

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestLoadBundled(t *testing.T) {
	// Positive rates use a fixed instant; wall-clock compatibility is tested separately.
	p, err := loadBundledRefServeAt(audit02Time)
	if err != nil {
		t.Fatalf("LoadBundled: %v", err)
	}
	prov := p.Provenance()
	if prov.SHA256 == "" || !strings.HasPrefix(prov.SHA256, "sha256:") {
		t.Errorf("provenance sha256 = %q", prov.SHA256)
	}
	if prov.ModelCnt == 0 {
		t.Error("bundled snapshot has no models")
	}
	if prov.Currency != "USD" {
		t.Errorf("currency = %q, want USD", prov.Currency)
	}
	// Independently verified primary rates still resolve.
	pr, ok := p.Lookup("nebius-token-factory", "deepseek-ai/DeepSeek-V4-Flash-0731")
	if !ok || pr.InputPerM != 0.14 || pr.OutputPerM != 0.28 {
		t.Fatalf("primary rate = %+v/%v", pr, ok)
	}
	if _, ok := p.Lookup("openai", "gpt-4o"); ok {
		t.Fatal("removed upstream model resolved")
	}
	// An unknown model is "unknown", not "free".
	if _, ok := p.Lookup("openai", "does-not-exist"); ok {
		t.Error("unknown model should not resolve")
	}
}

func TestFilePricer_Lookup(t *testing.T) {
	pf := validFile()
	p, err := NewFilePricer(pf, "sha256:abc")
	if err != nil {
		t.Fatalf("NewFilePricer: %v", err)
	}
	if pr, ok := p.Lookup("anthropic", "claude-3-opus"); !ok || pr.OutputPerM != 75.0 {
		t.Errorf("lookup = %+v, %v", pr, ok)
	}
	if _, ok := p.Lookup("nope", "nope"); ok {
		t.Error("unknown pair should miss")
	}
}

func TestNewFilePricer_RejectsInvalid(t *testing.T) {
	pf := validFile()
	pf.Models[0].Input = -1
	if _, err := NewFilePricer(pf, "sha256:x"); err == nil {
		t.Fatal("expected rejection of invalid file")
	}
}

func TestExternalSource_Validation(t *testing.T) {
	if err := ValidateExternalSource(ExternalSource{Offline: true}); err != nil {
		t.Errorf("offline should be valid: %v", err)
	}
	if err := ValidateExternalSource(ExternalSource{Repo: "github.com/Portkey-AI/models", Commit: "abc123"}); err != nil {
		t.Errorf("pinned online should be valid: %v", err)
	}
	if err := ValidateExternalSource(ExternalSource{Repo: "github.com/Portkey-AI/models"}); err == nil {
		t.Error("unpinned online should be rejected")
	}
	if err := ValidateExternalSource(ExternalSource{Commit: "abc"}); err == nil {
		t.Error("missing repo should be rejected")
	}
}

func TestExternalSource_Label(t *testing.T) {
	if got := (ExternalSource{Offline: true}).ProvenanceLabel(); got != "yabanin-reference-catalog (offline)" {
		t.Errorf("offline label = %q", got)
	}
	got := (ExternalSource{Repo: "github.com/Portkey-AI/models", Commit: "abc"}).ProvenanceLabel()
	if got != "github.com/Portkey-AI/models@abc" {
		t.Errorf("online label = %q", got)
	}
}

// TestExternalLoader_OfflineReturnsReferenceCatalog: offline mode (CORE-REF-04
// serving flip) returns the reference-catalog projection, pinned by the
// sealed catalog digest.
func TestExternalLoader_OfflineReturnsReferenceCatalog(t *testing.T) {
	l := &ExternalLoader{} // no Fetch
	p, err := l.Load(ExternalSource{Offline: true})
	if err != nil {
		t.Fatalf("offline load: %v", err)
	}
	if p.Provenance().ModelCnt == 0 {
		t.Error("offline snapshot empty")
	}
	if !strings.HasPrefix(p.Provenance().Source, "yabanin-catalog@") {
		t.Errorf("offline load must serve the reference catalog, got %q", p.Provenance().Source)
	}
}

func TestExternalLoader_OnlineFetch(t *testing.T) {
	upstream := PriceFile{
		Source:   "ignored", // loader overwrites with the pin label
		Date:     "2026-02-01",
		Currency: "USD",
		Units:    "per_1m_tokens",
		Models:   []PriceFileModel{{Provider: "x", Model: "y", Input: 1, Output: 2}},
	}
	raw, _ := json.Marshal(upstream)
	l := &ExternalLoader{
		Fetch: func(src ExternalSource) ([]byte, error) {
			if src.Commit != "deadbeef" {
				return nil, errors.New("wrong commit fetched")
			}
			return raw, nil
		},
	}
	p, err := l.Load(ExternalSource{Repo: "github.com/Portkey-AI/models", Commit: "deadbeef"})
	if err != nil {
		t.Fatalf("online load: %v", err)
	}
	// Provenance cites the pinned source, not the upstream's self-claim.
	if !strings.Contains(p.Provenance().Source, "github.com/Portkey-AI/models@deadbeef") {
		t.Errorf("provenance source = %q", p.Provenance().Source)
	}
	if _, ok := p.Lookup("x", "y"); !ok {
		t.Error("fetched model not found")
	}
}

func TestExternalLoader_UnpinnedRejected(t *testing.T) {
	l := &ExternalLoader{Fetch: func(ExternalSource) ([]byte, error) { return nil, nil }}
	if _, err := l.Load(ExternalSource{Repo: "github.com/Portkey-AI/models"}); err == nil {
		t.Fatal("unpinned online load should be rejected before fetch")
	}
}

func TestExternalLoader_FetchError(t *testing.T) {
	l := &ExternalLoader{Fetch: func(ExternalSource) ([]byte, error) { return nil, errors.New("network down") }}
	_, err := l.Load(ExternalSource{Repo: "github.com/Portkey-AI/models", Commit: "abc"})
	if err == nil || !strings.Contains(err.Error(), "network down") {
		t.Fatalf("expected fetch error to surface, got %v", err)
	}
}

func TestExternalLoader_InvalidFetchedRejected(t *testing.T) {
	bad := PriceFile{Source: "s", Date: "d", Currency: "USD", Units: "per_1m_tokens",
		Models: []PriceFileModel{{Provider: "x", Model: "y", Input: -1}}}
	raw, _ := json.Marshal(bad)
	l := &ExternalLoader{Fetch: func(ExternalSource) ([]byte, error) { return raw, nil }}
	if _, err := l.Load(ExternalSource{Repo: "r", Commit: "c"}); err == nil {
		t.Fatal("invalid fetched file should be rejected")
	}
}

// TestDefaultFilePricer_ReferenceCatalogByDefault pins the CORE-REF-04
// serving flip: the process default is the reference-catalog projection
// (serveable entries only), the draft corpus is out of the serving path
// (unknown, never free), and the override seam still wins.
func TestDefaultFilePricer_ReferenceCatalogByDefault(t *testing.T) {
	// Save/restore so the test does not leak global state.
	defaultFilePricerMu.Lock()
	saved := defaultFilePricer
	defaultFilePricer = nil
	defaultFilePricerMu.Unlock()
	resetFilePricerOnce()

	p := DefaultFilePricer()
	if p == nil || p.Provenance().ModelCnt == 0 {
		t.Fatal("default file pricer should be the reference-catalog projection")
	}
	prov := p.Provenance()
	if !strings.HasPrefix(prov.Source, "yabanin-catalog@") {
		t.Errorf("default pricer source = %q, want the reference catalog label", prov.Source)
	}
	info, ok := p.CatalogProvenance()
	if !ok || info.Version != "0.1.0" {
		t.Errorf("catalog provenance = %+v (ok=%v), want the genesis citation", info, ok)
	}
	// A verified arm serves with its exact committed cents.
	price, ok := p.Lookup("nebius-token-factory", "deepseek-ai/DeepSeek-V4-Flash-0731")
	if !ok {
		t.Fatal("default pricer missing the verified DeepSeek arm")
	}
	if price.InputPerM != 0.14 || price.OutputPerM != 0.28 {
		t.Errorf("DeepSeek arm = %v/%v per 1M, want 0.14/0.28", price.InputPerM, price.OutputPerM)
	}
	// The draft corpus (gpt-4o et al.) is NOT served: unknown, not free.
	if _, ok := p.Lookup("openai", "gpt-4o"); ok {
		t.Error("draft corpus entry must not serve through the default pricer")
	}

	// Replace and observe.
	custom, _ := NewFilePricer(validFile(), "sha256:zzz")
	SetDefaultFilePricer(custom)
	if got := DefaultFilePricer(); got != custom {
		t.Error("SetDefaultFilePricer did not take effect")
	}

	// Restore. If this test was the first toucher (saved == nil), the plain
	// restore would leave a nil pricer behind with the sync.Once already
	// consumed — DefaultFilePricer() would then return nil for the rest of
	// the process and shuffle-order siblings (azure alias lookups) fail.
	// Re-arm the lazy init in that case so the bundled snapshot reloads.
	// itself; calling it under the held Lock self-deadlocks (non-reentrant
	// RWMutex) whenever shuffle order runs this test first (saved == nil).
	defaultFilePricerMu.Lock()
	defaultFilePricer = saved
	firstToucher := saved == nil
	defaultFilePricerMu.Unlock()
	if firstToucher {
		resetFilePricerOnce()
	}
}
