package builtins

import (
	"context"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/pipeline"
)

// scanConfidence is the confidence threshold inherited from
// guardhooks.Hook.Scan: only checksum-confirmed (1.0) and strict-format
// (0.9) hits are reported. Sub-threshold guardhooks hits (format-only INN at
// 0.6, phone/email at 0.8) stay out of pipeline findings, preserving the
// recall/precision contract the gateway guard mode already ships.
const scanConfidence = 0.9

// evidence redaction tokens for secret-material findings: the matched text is
// the secret itself and must never be quoted into evidence.
const (
	evidenceSecret = "[REDACTED_SECRET]"
	//nolint:gosec // G101 false positive: fixed redaction label, not a credential (same pattern as pkg/guardhooks/credkeys.go)
	evidenceCredential = "[REDACTED_CREDENTIAL]"
)

// detectorCore is the shared implementation of the three guardhooks-port
// steps. It is immutable after construction (goroutine-safe) and appends one
// pipeline.Finding per guardhooks finding of the configured categories.
type detectorCore struct {
	pipeline.DetectorBase
	name  string
	cats  map[guardhooks.Category]bool
	cred  bool // also detect credential-keyed JSON values (MC-2) via Hook.Scan
	kinds map[pipeline.PayloadKind]bool
	act   pipeline.Action
}

// Name returns the step implementation name.
func (d *detectorCore) Name() string { return d.name }

// Run scans the payload text and appends spanned findings per detected
// category, every one carrying the step's configured action.
func (d *detectorCore) Run(ctx context.Context, p *pipeline.Pipeline, in *pipeline.Payload, out *pipeline.Result) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if in == nil || !d.kinds[in.Kind] {
		return nil
	}
	text := payloadText(in)
	if text == "" {
		return nil
	}
	// guardhooks.FindAll runs the compile-once linear detector set and
	// returns matches ordered by start, overlaps of one category deduped.
	// It is uninterruptible but linear in input; the policy's per-step
	// timeout bounds the call.
	for _, f := range guardhooks.FindAll(text, guardhooks.DefaultDetectors()) {
		if f.Confidence < scanConfidence || !d.cats[f.Category] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		ev := clipEvidence(text[f.Start:f.End], maxEvidence)
		if f.Category == guardhooks.CatSecret {
			ev = evidenceSecret
		}
		out.Findings = append(out.Findings, finding(
			p.StepID(), string(f.Category), severityFor(f.Confidence, d.name),
			span(f.Start, f.End), ev, d.act,
		))
	}
	// Credential-keyed values (e.g. "authorization": "…") are secret material
	// by their KEY (MC-2). guardhooks exposes the check through Hook.Scan;
	// the hit is reported without a span (the whole pair is sensitive).
	if d.cred {
		for _, h := range guardhooks.New(guardhooks.ModeLog).Scan(text) {
			if h.Category != guardhooks.CatCredential {
				continue
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			out.Findings = append(out.Findings, finding(
				p.StepID(), string(h.Category), sevHigh,
				"", evidenceCredential, d.act,
			))
		}
	}
	return nil
}

// severityFor maps detector confidence to the builtin severity scale:
// checksum-confirmed identity data (1.0) is high; strict-format hits (0.9)
// are medium; secret/injection regex hits (0.9) are high by class, handled
// via the name check.
func severityFor(confidence float64, name string) string {
	if name == "builtin/secrets" || name == "builtin/injection" {
		return sevHigh
	}
	if confidence >= 1.0 {
		return sevHigh
	}
	return sevMedium
}

// NewNationalPII builds the builtin/national-pii detector: Russian PII
// (INN/SNILS checksum-validated, PAN by Luhn, RU passport / OGRN at strict
// format confidence) plus the I18N-13 jurisdictions BR, IN, MY, AE, ZA, NG,
// KE, EG. Detection is delegated to guardhooks (compile-once linear regexes
// + checksum validators); the step only maps hits to pipeline findings.
func NewNationalPII(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	return &detectorCore{
		name:  "builtin/national-pii",
		cats:  nationalPIICategories(),
		kinds: kinds,
		act:   act,
	}, nil
}

// nationalPIICategories is the national-pii category set: RU identity
// numbers (passport and OGRN at ≥0.9 confidence; phone/email are
// sub-threshold in guardhooks and not reported) and the nine jurisdictions.
func nationalPIICategories() map[guardhooks.Category]bool {
	return map[guardhooks.Category]bool{
		guardhooks.CatINNSNILS:   true,
		guardhooks.CatPAN:        true,
		guardhooks.CatRUPassport: true,
		guardhooks.CatOGRN:       true,
		guardhooks.CatBR:         true,
		guardhooks.CatIN:         true,
		guardhooks.CatMY:         true,
		guardhooks.CatAE:         true,
		guardhooks.CatZA:         true,
		guardhooks.CatNG:         true,
		guardhooks.CatKE:         true,
		guardhooks.CatEG:         true,
	}
}

// NewSecrets builds the builtin/secrets detector: provider API keys and
// token shapes (sk-…, AKIA…, ghp_/gho_/ghs_/ghr_, github_pat, xox…, AIza…,
// JWT-shaped eyJ…), PEM private-key headers and credential-keyed JSON values
// (MC-2). Secret material is never quoted into evidence.
func NewSecrets(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	return &detectorCore{
		name:  "builtin/secrets",
		cats:  map[guardhooks.Category]bool{guardhooks.CatSecret: true},
		cred:  true,
		kinds: kinds,
		act:   act,
	}, nil
}

// NewInjection builds the builtin/injection detector: prompt-injection
// phrases RU + EN (case-insensitive fixed-phrase alternation from
// guardhooks).
func NewInjection(params map[string]any) (pipeline.Step, error) {
	kinds, err := parseKinds(params)
	if err != nil {
		return nil, err
	}
	act, err := parseAction(params)
	if err != nil {
		return nil, err
	}
	return &detectorCore{
		name:  "builtin/injection",
		cats:  map[guardhooks.Category]bool{guardhooks.CatInjection: true},
		kinds: kinds,
		act:   act,
	}, nil
}

// compile-time guard: the ported steps are read-only Detectors (parallel
// group participation) and satisfy the Step interface.
var _ pipeline.Detector = (*detectorCore)(nil)
