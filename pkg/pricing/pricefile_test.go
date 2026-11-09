package pricing

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// validFile returns a minimal valid price file for mutation in tests.
func validFile() PriceFile {
	return PriceFile{
		Source:   "test-source",
		Date:     "2026-01-01",
		Currency: "USD",
		Units:    "per_1m_tokens",
		Models: []PriceFileModel{
			{Provider: "openai", Model: "gpt-4o", Input: 2.5, Output: 10.0, CacheW: 3.125, CacheR: 1.25},
			{Provider: "anthropic", Model: "claude-3-opus", Input: 15.0, Output: 75.0},
		},
	}
}

func TestValidatePriceFile_Valid(t *testing.T) {
	if err := ValidatePriceFile(validFile()); err != nil {
		t.Fatalf("valid file rejected: %v", err)
	}
}

func TestValidatePriceFile_RequiredFields(t *testing.T) {
	cases := map[string]func(*PriceFile){
		"missing source":   func(pf *PriceFile) { pf.Source = "" },
		"missing date":     func(pf *PriceFile) { pf.Date = "" },
		"missing currency": func(pf *PriceFile) { pf.Currency = "" },
		"missing units":    func(pf *PriceFile) { pf.Units = "" },
		"empty models":     func(pf *PriceFile) { pf.Models = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			pf := validFile()
			mutate(&pf)
			err := ValidatePriceFile(pf)
			if err == nil {
				t.Fatalf("expected rejection")
			}
			if _, ok := err.(*PriceFileError); !ok {
				t.Fatalf("expected *PriceFileError, got %T", err)
			}
		})
	}
}

func TestValidatePriceFile_BadCurrency(t *testing.T) {
	pf := validFile()
	pf.Currency = "EUR"
	if err := ValidatePriceFile(pf); err == nil {
		t.Fatal("expected rejection for non-USD currency")
	}
}

func TestValidatePriceFile_BadUnits(t *testing.T) {
	pf := validFile()
	pf.Units = "per_token"
	if err := ValidatePriceFile(pf); err == nil {
		t.Fatal("expected rejection for wrong units")
	}
}

func TestValidatePriceFile_NegativePrice(t *testing.T) {
	pf := validFile()
	pf.Models[0].Input = -1.0
	err := ValidatePriceFile(pf)
	if err == nil {
		t.Fatal("expected rejection for negative price")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Fatalf("error should mention negative: %v", err)
	}
}

func TestValidatePriceFile_NanInf(t *testing.T) {
	for name, v := range map[string]float64{
		"NaN": math.NaN(),
		"Inf": math.Inf(1),
	} {
		t.Run(name, func(t *testing.T) {
			pf := validFile()
			pf.Models[0].Output = v
			err := ValidatePriceFile(pf)
			if err == nil {
				t.Fatal("expected rejection for non-finite price")
			}
			if !strings.Contains(err.Error(), "finite") {
				t.Fatalf("error should mention finite: %v", err)
			}
		})
	}
}

func TestValidatePriceFile_DuplicateModel(t *testing.T) {
	pf := validFile()
	pf.Models = append(pf.Models, pf.Models[0])
	err := ValidatePriceFile(pf)
	if err == nil {
		t.Fatal("expected rejection for duplicate model")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error should mention duplicate: %v", err)
	}
}

func TestValidatePriceFile_MissingProviderOrModel(t *testing.T) {
	pf := validFile()
	pf.Models[0].Provider = ""
	if err := ValidatePriceFile(pf); err == nil {
		t.Fatal("expected rejection for missing provider")
	}
	pf = validFile()
	pf.Models[0].Model = ""
	if err := ValidatePriceFile(pf); err == nil {
		t.Fatal("expected rejection for missing model")
	}
}

func TestValidatePriceFile_MultipleProblems(t *testing.T) {
	pf := validFile()
	pf.Source = ""
	pf.Models[0].Input = -5
	pf.Models[0].Output = math.NaN()
	err := ValidatePriceFile(pf)
	pfe, ok := err.(*PriceFileError)
	if !ok {
		t.Fatalf("expected *PriceFileError, got %T", err)
	}
	if len(pfe.Problems) < 3 {
		t.Fatalf("expected >=3 problems, got %d: %v", len(pfe.Problems), PfeProblems(pfe))
	}
}

func PfeProblems(e *PriceFileError) []string { return e.Problems }

func TestParsePriceFile_Valid(t *testing.T) {
	data, _ := json.Marshal(validFile())
	pf, sum, err := ParsePriceFile(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parse valid: %v", err)
	}
	if pf.Source != "test-source" {
		t.Errorf("source = %q", pf.Source)
	}
	if !strings.HasPrefix(sum, "sha256:") {
		t.Errorf("sha256 = %q, want sha256: prefix", sum)
	}
}

func TestParsePriceFile_MalformedJSON(t *testing.T) {
	_, _, err := ParsePriceFile(strings.NewReader("{not json"))
	if err == nil {
		t.Fatal("expected parse error for malformed JSON")
	}
}

func TestParsePriceFile_InvalidRejected(t *testing.T) {
	pf := validFile()
	pf.Models[0].Input = -1
	data, _ := json.Marshal(pf)
	_, _, err := ParsePriceFile(strings.NewReader(string(data)))
	if err == nil {
		t.Fatal("expected validation rejection")
	}
}

func TestParsePriceFile_UnknownModelIsFine(t *testing.T) {
	// A file covering a subset of models is valid; "unknown" is a lookup
	// concept, not a file error.
	pf := validFile()
	pf.Models = pf.Models[:1]
	data, _ := json.Marshal(pf)
	if _, _, err := ParsePriceFile(strings.NewReader(string(data))); err != nil {
		t.Fatalf("subset file should be valid: %v", err)
	}
}
