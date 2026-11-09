package pricing

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
)

// PriceFile is the versioned, self-describing price-list format (A03).
// A price file is an immutable snapshot: {source, date, currency, units,
// models[]}. The file's SHA256 (computed by the loader) plus its Source and
// Date form the provenance that cost reports carry, so an operator can always
// answer "which prices produced this number, and when were they verified".
//
// The primary-source reference projection is the offline default; the external
// source (github.com/Portkey-AI/models, commit-pinned) can be loaded and
// written out as a new snapshot.
type PriceFile struct {
	// Source identifies where the prices came from (e.g.
	// "github.com/Portkey-AI/models@<commit>" or
	// "operator-maintained prices").
	Source string `json:"source"`
	// Date is the upstream verification / publication date (RFC 3339 or
	// YYYY-MM-DD). "unknown" when the source does not record one.
	Date string `json:"date"`
	// Currency is the ISO-4217 code the unit prices are quoted in ("USD").
	Currency string `json:"currency"`
	// Units describes the denominator the per-model prices use
	// ("per_1m_tokens").
	Units string `json:"units"`
	// Models is the per-model price list.
	Models []PriceFileModel `json:"models"`
}

// PriceFileModel is one model entry in a PriceFile.
type PriceFileModel struct {
	Provider string  `json:"provider"`
	Model    string  `json:"model"`
	Input    float64 `json:"input"`   // per 1M prompt tokens
	Output   float64 `json:"output"`  // per 1M completion tokens
	CacheW   float64 `json:"cache_w"` // per 1M cache-write tokens (0 = unsupported)
	CacheR   float64 `json:"cache_r"` // per 1M cache-read tokens (0 = unsupported)
}

// ToPrice converts a file entry to the runtime Price type.
func (m PriceFileModel) ToPrice() Price {
	return Price{
		InputPerM:      m.Input,
		OutputPerM:     m.Output,
		CacheWritePerM: m.CacheW,
		CacheReadPerM:  m.CacheR,
	}
}

// PriceFileError is a validation failure for a price file. One error is
// returned per malformed entry so the operator can fix the whole file at
// once; the file is rejected if any error is present.
type PriceFileError struct {
	Problems []string
}

func (e *PriceFileError) Error() string {
	return fmt.Sprintf("invalid price file: %s", strings.Join(e.Problems, "; "))
}

// ValidatePriceFile checks structural and numeric soundness of a price file:
//   - Source, Date, Currency, Units must be non-empty;
//   - currency must be a 3-letter ISO code; units must be "per_1m_tokens";
//   - every model needs a non-empty provider and model name;
//   - every price must be a finite, non-negative number (reject NaN/Inf and
//     negative values);
//   - duplicate (provider, model) pairs are rejected.
//
// Unknown models are NOT an error: a price file may legitimately cover a
// subset of models. "Unknown" is a runtime lookup concept (a model absent
// from the file), not a file-validation one.
func ValidatePriceFile(pf PriceFile) error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(pf.Source) == "" {
		add("source is required")
	}
	if strings.TrimSpace(pf.Date) == "" {
		add("date is required")
	}
	if c := strings.ToUpper(strings.TrimSpace(pf.Currency)); c != "USD" {
		add("currency must be USD, got %q", pf.Currency)
	}
	if pf.Units != "per_1m_tokens" {
		add("units must be %q, got %q", "per_1m_tokens", pf.Units)
	}
	if len(pf.Models) == 0 {
		add("models list is empty")
	}

	seen := make(map[string]struct{}, len(pf.Models))
	for i, m := range pf.Models {
		where := fmt.Sprintf("models[%d]", i)
		if strings.TrimSpace(m.Provider) == "" {
			add("%s: provider is required", where)
		}
		if strings.TrimSpace(m.Model) == "" {
			add("%s: model is required", where)
			continue
		}
		key := m.Provider + ":" + m.Model
		if _, dup := seen[key]; dup {
			add("%s: duplicate entry for %s", where, key)
		}
		seen[key] = struct{}{}
		for field, v := range map[string]float64{
			"input":   m.Input,
			"output":  m.Output,
			"cache_w": m.CacheW,
			"cache_r": m.CacheR,
		} {
			if math.IsNaN(v) || math.IsInf(v, 0) {
				add("%s.%s: not a finite number (%v)", where, field, v)
			} else if v < 0 {
				add("%s.%s: negative price %v", where, field, v)
			}
		}
	}

	if len(problems) > 0 {
		return &PriceFileError{Problems: problems}
	}
	return nil
}

// ParsePriceFile reads and validates a price file from r. It returns the
// validated file and the SHA256 hex of the raw bytes (the provenance
// fingerprint). Any validation problem rejects the whole file.
func ParsePriceFile(r io.Reader) (PriceFile, string, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return PriceFile{}, "", fmt.Errorf("read price file: %w", err)
	}
	var pf PriceFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&pf); err != nil {
		return PriceFile{}, "", fmt.Errorf("parse price file: %w", err)
	}
	if err := ValidatePriceFile(pf); err != nil {
		return PriceFile{}, "", err
	}
	return pf, sha256Hex(data), nil
}
