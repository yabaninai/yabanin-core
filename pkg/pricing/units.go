package pricing

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

// Non-token prices are operator-supplied snapshots for audio seconds,
// characters and images. No non-token pricing dataset is shipped. An absent
// rate returns ok=false; callers must retain their unpriced/refusal behavior.
// Imported snapshots retain their source, date and digest in cost provenance.

// Non-token metering units (USD per one unit).
const (
	// UnitPerAudioSecond is USD per second of input audio (transcription).
	UnitPerAudioSecond = "per_second_audio"
	// UnitPerCharacter is USD per input character (text-to-speech).
	UnitPerCharacter = "per_character"
	// UnitPerImage is USD per generated image (images API).
	UnitPerImage = "per_image"
)

// UnitEntry is one unit rate: USD per one unit of the metering axis.
type UnitEntry struct {
	Provider string  `json:"provider"`
	Model    string  `json:"model"`
	Unit     string  `json:"unit"`
	Rate     float64 `json:"rate"`
}

// UnitFile is the versioned, self-describing unit-rate format: an immutable
// snapshot {source, date, currency, units[]}. Like PriceFile it is validated
// and fingerprinted by SHA256 when loaded.
type UnitFile struct {
	Source   string      `json:"source"`
	Date     string      `json:"date"`
	Currency string      `json:"currency"`
	Units    []UnitEntry `json:"units"`
}

// UnitProvenance identifies the snapshot in reports (parity with
// FileProvenance).
type UnitProvenance struct {
	Source   string
	Date     string
	Currency string
	SHA256   string
	Entries  int
}

// UnitFileError is a validation failure for a unit file. All problems are
// reported at once; the file is rejected if any is present.
type UnitFileError struct {
	Problems []string
}

func (e *UnitFileError) Error() string {
	return fmt.Sprintf("invalid unit file: %s", strings.Join(e.Problems, "; "))
}

// unitKinds is the closed set of metering axes the gateway and estimator
// understand. Unknown kinds in a file are a validation error: silently
// ignoring one would price a billable axis at zero.
var unitKinds = map[string]struct{}{
	UnitPerAudioSecond: {},
	UnitPerCharacter:   {},
	UnitPerImage:       {},
}

// ValidateUnitFile checks structural and numeric soundness of a unit file:
//   - Source, Date, Currency must be non-empty; currency must be USD;
//   - every entry needs a non-empty provider and model name;
//   - Unit must be one of the supported metering axes;
//   - every rate must be a finite, non-negative number (an explicit priced
//     zero is legitimate, parity with the token catalog);
//   - duplicate (provider, model) pairs are rejected — the import collapses
//     size-class variants into one entry beforehand.
func ValidateUnitFile(uf UnitFile) error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(uf.Source) == "" {
		add("source is required")
	}
	if strings.TrimSpace(uf.Date) == "" {
		add("date is required")
	}
	if c := strings.ToUpper(strings.TrimSpace(uf.Currency)); c != "USD" {
		add("currency must be USD, got %q", uf.Currency)
	}
	if len(uf.Units) == 0 {
		add("units list is empty")
	}

	seen := make(map[string]struct{}, len(uf.Units))
	for i, e := range uf.Units {
		where := fmt.Sprintf("units[%d]", i)
		if strings.TrimSpace(e.Provider) == "" {
			add("%s: provider is required", where)
		}
		if strings.TrimSpace(e.Model) == "" {
			add("%s: model is required", where)
			continue
		}
		key := e.Provider + ":" + e.Model
		if _, dup := seen[key]; dup {
			add("%s: duplicate entry for %s", where, key)
		}
		seen[key] = struct{}{}
		if _, known := unitKinds[e.Unit]; !known {
			add("%s: unknown unit kind %q", where, e.Unit)
		}
		if math.IsNaN(e.Rate) || math.IsInf(e.Rate, 0) {
			add("%s: rate is not a finite number (%v)", where, e.Rate)
		} else if e.Rate < 0 {
			add("%s: negative rate %v", where, e.Rate)
		}
	}

	if len(problems) > 0 {
		return &UnitFileError{Problems: problems}
	}
	return nil
}

// ParseUnitFile reads and validates a unit file from r. It returns the
// validated file and the SHA256 hex of the raw bytes (provenance
// fingerprint).
func ParseUnitFile(r io.Reader) (UnitFile, string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return UnitFile{}, "", fmt.Errorf("read unit file: %w", err)
	}
	var uf UnitFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&uf); err != nil {
		return UnitFile{}, "", fmt.Errorf("parse unit file: %w", err)
	}
	if err := ValidateUnitFile(uf); err != nil {
		return UnitFile{}, "", err
	}
	return uf, sha256Hex(data), nil
}

// UnitImportStats counts how ImportLiteLLMUnits classified each catalog
// entry (parity with LiteLLMImportStats).
type UnitImportStats struct {
	Total, Imported, SkippedMode, SkippedNoPrice, SkippedInvalid, Duplicates int
}

// ImportLiteLLMUnits extracts the non-token metering rates from LiteLLM's
// model_prices_and_context_window.json into a UnitFile. Import rules (all
// rates verbatim from the catalog — D2):
//
//   - mode=audio_transcription → UnitPerAudioSecond at
//     max(input_cost_per_second, output_cost_per_second) (whichever axes the
//     entry prices; a 0 on one axis with the other present is honored);
//   - mode=audio_speech → UnitPerCharacter at input_cost_per_character only
//     (no per-character field → unpriced: token-billed TTS such as
//     gpt-4o-mini-tts is NOT re-priced from its token rates here);
//   - mode=image_generation → UnitPerImage at
//     max(input_cost_per_image, output_cost_per_image); per-pixel or
//     per-token-only variants (azure size classes) are skipped;
//   - every other mode is SkippedMode.
//
// Model name is the LAST "/" segment of the catalog key so size-class keys
// ("1024-x-1024/gpt-image-1.5") collapse onto the registry model name; when
// the same (provider, model) is seen again the maximum rate is kept — the
// bound must cover the most expensive catalog variant of the model.
func ImportLiteLLMUnits(r io.Reader, source, date string) (UnitFile, UnitImportStats, error) {
	var root map[string]json.RawMessage
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return UnitFile{}, UnitImportStats{}, fmt.Errorf("parse litellm catalog: %w", err)
	}
	if root == nil {
		// Valid JSON that is not a flat object (null) is a layout
		// violation, not an empty catalog (parity with ImportLiteLLM).
		return UnitFile{}, UnitImportStats{}, fmt.Errorf("parse litellm catalog: top level must be a JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		// Decode consumes only the FIRST JSON value; without this check a
		// catalog with trailing data imports silently truncated (parity
		// with ImportLiteLLM).
		return UnitFile{}, UnitImportStats{}, fmt.Errorf("parse litellm catalog: trailing data after the top-level object")
	}

	keys := make([]string, 0, len(root))
	for key := range root {
		if key == "sample_spec" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var stats UnitImportStats
	stats.Total = len(keys)
	entries := make([]UnitEntry, 0, len(keys))
	best := make(map[string]int, len(keys)) // "provider:model" → index in entries

	for _, key := range keys {
		var obj map[string]any
		if err := json.Unmarshal(root[key], &obj); err != nil {
			stats.SkippedInvalid++
			continue
		}
		mode, _ := obj["mode"].(string)
		unit, fields, ok := litellmUnitFields(mode)
		if !ok {
			stats.SkippedMode++
			continue
		}
		provider := normalizeLiteLLMProvider(stringField(obj, "litellm_provider"))
		if strings.TrimSpace(provider) == "" {
			stats.SkippedInvalid++
			continue
		}
		model := key
		if i := strings.LastIndexByte(key, '/'); i >= 0 {
			model = key[i+1:]
		}
		if strings.TrimSpace(model) == "" {
			stats.SkippedInvalid++
			continue
		}
		rate, present, ok := litellmMaxRate(obj, fields)
		if !ok {
			stats.SkippedInvalid++
			continue
		}
		if !present || rate <= 0 {
			stats.SkippedNoPrice++
			continue
		}
		id := provider + "\x00" + model
		if idx, dup := best[id]; dup {
			stats.Duplicates++
			if rate > entries[idx].Rate {
				entries[idx].Rate = rate
			}
			continue
		}
		best[id] = len(entries)
		entries = append(entries, UnitEntry{
			Provider: provider,
			Model:    model,
			Unit:     unit,
			Rate:     roundUnitPrice(rate),
		})
		stats.Imported++
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Provider != entries[j].Provider {
			return entries[i].Provider < entries[j].Provider
		}
		return entries[i].Model < entries[j].Model
	})

	return UnitFile{
		Source:   source,
		Date:     date,
		Currency: "USD",
		Units:    entries,
	}, stats, nil
}

// litellmUnitFields maps a catalog mode onto the metering unit and the
// catalog fields that price it. ok=false for modes without a non-token axis.
func litellmUnitFields(mode string) (unit string, fields []string, ok bool) {
	switch mode {
	case "audio_transcription":
		return UnitPerAudioSecond, []string{"input_cost_per_second", "output_cost_per_second"}, true
	case "audio_speech":
		return UnitPerCharacter, []string{"input_cost_per_character"}, true
	case "image_generation":
		return UnitPerImage, []string{"input_cost_per_image", "output_cost_per_image"}, true
	default:
		return "", nil, false
	}
}

// litellmMaxRate returns the maximum over the PRESENT fields (an absent
// field means the entry does not price that axis; an explicit 0.0 counts as
// a present zero). present=false when none of the fields exist — a
// "catalog does not price this axis" signal, not an error. ok=false marks a
// field present with a malformed or negative number (invalid entry).
func litellmMaxRate(obj map[string]any, fields []string) (rate float64, present, ok bool) {
	for _, field := range fields {
		raw, exists := obj[field]
		if !exists || raw == nil {
			continue
		}
		v, valid := litellmUSD(obj, field)
		if !valid {
			return 0, true, false
		}
		present = true
		if v > rate {
			rate = v
		}
	}
	return rate, present, true
}

// roundUnitPrice keeps catalog rates byte-stable at 12 decimal places —
// tighter than the token import's 1e-6 because per-unit rates are 3-5 orders
// of magnitude smaller.
func roundUnitPrice(v float64) float64 {
	return math.Round(v*1e12) / 1e12
}

// UnitPricer resolves the non-token metering rate for a model. ok=false
// means unpriced (fail-closed: never a zero-cost bypass).
type UnitPricer interface {
	LookupUnit(provider, model string) (UnitEntry, bool)
}

// UnitFilePricer serves unit rates from a validated UnitFile snapshot.
type UnitFilePricer struct {
	file       UnitFile
	provenance UnitProvenance
	byKey      map[string]UnitEntry
}

// NewUnitFilePricer validates the file defensively (a caller may have built
// it by hand) and indexes it.
func NewUnitFilePricer(uf UnitFile, sha256 string) (*UnitFilePricer, error) {
	if err := ValidateUnitFile(uf); err != nil {
		return nil, err
	}
	byKey := make(map[string]UnitEntry, len(uf.Units))
	for _, e := range uf.Units {
		byKey[e.Provider+":"+e.Model] = e
	}
	return &UnitFilePricer{
		file: uf,
		provenance: UnitProvenance{
			Source:   uf.Source,
			Date:     uf.Date,
			Currency: uf.Currency,
			SHA256:   sha256,
			Entries:  len(uf.Units),
		},
		byKey: byKey,
	}, nil
}

// LookupUnit implements UnitPricer: exact (provider, model) first, then the
// catalog provider alias (azure-openai → azure), mirroring the token
// pricers.
func (p *UnitFilePricer) LookupUnit(provider, model string) (UnitEntry, bool) {
	if e, ok := p.byKey[provider+":"+model]; ok {
		return e, true
	}
	if c := CanonicalProvider(provider); c != provider {
		if e, ok := p.byKey[c+":"+model]; ok {
			return e, true
		}
	}
	return UnitEntry{}, false
}

// Provenance returns the snapshot's provenance for embedding in reports.
func (p *UnitFilePricer) Provenance() UnitProvenance { return p.provenance }

// File returns the loaded unit file (for export / diffing).
func (p *UnitFilePricer) File() UnitFile { return p.file }

// LoadBundledUnits preserves the loader API but returns an empty pricer:
// no non-token price data is distributed. User files still require the full
// ParseUnitFile/NewUnitFilePricer validation, including a nonempty unit list.
func LoadBundledUnits() (*UnitFilePricer, error) {
	return &UnitFilePricer{}, nil
}

// defaultUnitPricer starts empty and can be replaced at startup via
// SetDefaultUnitPricer.
var (
	defaultUnitPricer     *UnitFilePricer
	defaultUnitPricerOnce sync.Once
	defaultUnitPricerMu   sync.RWMutex
)

// DefaultUnitPricer returns the current unit pricer, initializing it to the
// empty default on first use.
func DefaultUnitPricer() *UnitFilePricer {
	defaultUnitPricerMu.RLock()
	p := defaultUnitPricer
	defaultUnitPricerMu.RUnlock()
	if p != nil {
		return p
	}
	defaultUnitPricerOnce.Do(func() {
		b, err := LoadBundledUnits()
		if err != nil {
			// Keep absence explicit if the compatibility loader ever fails;
			// no fallback dataset or invented rate is available.
			b = &UnitFilePricer{}
		}
		defaultUnitPricerMu.Lock()
		defaultUnitPricer = b
		defaultUnitPricerMu.Unlock()
	})
	defaultUnitPricerMu.RLock()
	defer defaultUnitPricerMu.RUnlock()
	return defaultUnitPricer
}

// SetDefaultUnitPricer replaces the process-wide unit pricer (call at
// startup after loading an operator-provided snapshot).
func SetDefaultUnitPricer(p *UnitFilePricer) {
	defaultUnitPricerMu.Lock()
	defaultUnitPricer = p
	defaultUnitPricerMu.Unlock()
}
