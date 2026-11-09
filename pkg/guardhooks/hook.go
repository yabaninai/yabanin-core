package guardhooks

import (
	"context"
	"errors"
	"fmt"
	stdregexp "regexp"
	"strings"
)

// ErrDenied is returned by the gateway when the active guard mode is "deny"
// and a sensitive category is detected in the egress body. The gateway maps it
// to a 400 response and does not forward the request upstream.
var ErrDenied = errors.New("guard: sensitive data detected in request (mode=deny)")

// Mode is the guard-hooks operating mode.
type Mode string

// The guard-hooks operating modes.
const (
	// ModeOff disables the hooks entirely (default).
	ModeOff Mode = "off"
	// ModeLog detects and counts sensitive data but forwards unchanged.
	ModeLog Mode = "log"
	// ModeRedact detects and replaces matched text in the egress body.
	ModeRedact Mode = "redact"
	// ModeDeny detects and rejects the request (400, no forward).
	ModeDeny Mode = "deny"
)

// ParseMode validates a raw mode string. Invalid values fall back to off with
// ok=false so the gateway can Warn and disable (fail-safe to off).
func ParseMode(raw string) (Mode, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "off":
		return ModeOff, true
	case "log":
		return ModeLog, true
	case "redact":
		return ModeRedact, true
	case "deny":
		return ModeDeny, true
	default:
		return ModeOff, false
	}
}

// Hook is a configured guard-hooks instance. It is immutable and safe for
// concurrent use: all state is the mode + the package-level compiled regexes.
type Hook struct {
	mode      Mode
	evaluator *Evaluator
}

// New builds a Hook for the given mode. modeOff returns a no-op hook.
func New(mode Mode) *Hook {
	return &Hook{mode: mode, evaluator: builtinEvaluator}
}

// NewWithEvaluator configures the same Hook action semantics with an
// evaluator containing built-in and user-provided versioned detectors.
func NewWithEvaluator(mode Mode, evaluator *Evaluator) *Hook {
	if evaluator == nil {
		evaluator = builtinEvaluator
	}
	return &Hook{mode: mode, evaluator: evaluator}
}

// Enabled reports whether the hook does any work (mode != off).
func (h *Hook) Enabled() bool { return h.mode != ModeOff }

// Mode returns the active mode.
func (h *Hook) Mode() Mode { return h.mode }

// Scan detects sensitive categories in text under the active mode and returns
// one Hit per category with the outcome that mode prescribes. In off mode it
// returns nil (no work). It never modifies text.
func (h *Hook) Scan(text string) []Hit {
	if h.mode == ModeOff {
		return nil
	}
	_, hits, err := h.evaluate(text)
	if err != nil {
		return nil
	}
	return hits
}

func (h *Hook) evaluate(text string) (Evaluation, []Hit, error) {
	evaluation, err := h.evaluator.Evaluate(Invocation{
		Context: context.Background(), Version: RuntimeVersion, Phase: PhaseBefore, Kind: ContentText, Text: text,
	})
	if err != nil {
		return Evaluation{}, nil, err
	}
	found := map[Category]bool{}
	for _, f := range evaluation.Findings {
		if f.Confidence < scanConfidence {
			continue
		}
		// The 12-digit card checksum is not the legacy INN check. A number the
		// existing detector rejects must stay a non-hit so guard recall and the
		// decoy corpus do not move.
		if (f.Detector == "ru:inn10" || f.Detector == "ru:inn12") && !validateINN(text[f.Start:f.End]) {
			continue
		}
		found[f.Category] = true
	}
	outcome := h.mode
	hits := make([]Hit, 0, len(found))
	// Stable order for deterministic metrics/logs.
	order := []Category{
		CatINNSNILS, CatRUPassport, CatOGRN, CatPhone, CatEmail,
		CatPAN, CatSecret, CatCredential, CatInjection,
		CatBR, CatIN, CatMY, CatAE, CatZA, CatNG, CatKE, CatEG,
	}
	for _, c := range order {
		if found[c] {
			hits = append(hits, Hit{Category: c, Outcome: Outcome(outcome)})
		}
	}
	return evaluation, hits, nil
}

// Apply evaluates the active hook and applies its legacy mode through the
// common guardrail verdict model. The returned text is nil when unchanged.
func (h *Hook) Apply(text string) ([]byte, []Hit, error) {
	if h == nil || h.mode == ModeOff {
		return nil, nil, nil
	}
	evaluation, hits, err := h.evaluate(text)
	if err != nil {
		if h.mode == ModeDeny || h.mode == ModeRedact {
			return nil, []Hit{{Category: CatDetectorFailure, Outcome: OutcomeDeny}}, ErrDenied
		}
		return nil, []Hit{{Category: CatDetectorFailure, Outcome: OutcomeLog}}, nil
	}
	if len(hits) == 0 {
		return nil, nil, nil
	}
	// Redact mode mutates by the validated evaluator spans first so custom
	// pack findings are actually removed; the legacy built-in regex pass then
	// runs on the mutated text for credential-keyed values (key-preserving,
	// MC-2) and sub-threshold formats. An unsafe span set fails closed: the
	// request is denied rather than forwarded with a reported-but-unredacted
	// secret (FIX-01, CA-01).
	mutateText := text
	if h.mode == ModeRedact {
		// MC-2 (owner decision 2026-10-24): a credential-category finding the
		// built-in key-value mutator cannot fully address would otherwise ship
		// under a credential:redact hit. Fail closed — deny the whole request,
		// never forward a reported-but-unredacted secret.
		if unsafeCredentialFindings(text, evaluation.Findings) {
			return nil, denyHits(hits),
				fmt.Errorf("%w: credential finding outside the built-in key-value shape (fail closed, MC-2)", ErrDenied)
		}
		redacted, redactErr := redactByFindings(text, evaluation.Findings)
		if redactErr != nil {
			return nil, []Hit{{Category: CatDetectorFailure, Outcome: OutcomeDeny}},
				fmt.Errorf("%w: safe span redaction failed: %w", ErrDenied, redactErr)
		}
		mutateText = redacted
	}
	var action Verdict
	switch h.mode {
	case ModeDeny:
		action = VerdictDeny
	case ModeRedact:
		action = VerdictRedact
	default:
		action = VerdictAuditOnly
	}
	mutated, verdict, err := Apply(evaluation, action, func() []byte {
		return []byte(h.Redact(mutateText))
	})
	if err != nil {
		return nil, hits, err
	}
	if verdict == VerdictDeny {
		return nil, hits, ErrDenied
	}
	return mutated, hits, nil
}

// denyHits re-outcomes every detection hit to deny so downstream metrics and
// audit show the real reason the request was refused (the categories, each at
// outcome deny), and guarantees the credential hit carries the deny outcome
// even if hit accounting ever diverges from the unsafe-finding check (MC-2
// fail-closed path). Hits carry categories only — never content.
func denyHits(hits []Hit) []Hit {
	out := make([]Hit, 0, len(hits)+1)
	sawCredential := false
	for _, hit := range hits {
		if hit.Category == CatCredential {
			sawCredential = true
		}
		out = append(out, Hit{Category: hit.Category, Outcome: OutcomeDeny})
	}
	if !sawCredential {
		out = append(out, Hit{Category: CatCredential, Outcome: OutcomeDeny})
	}
	return out
}

// Redact returns a copy of text with matched categories replaced (only the
// matched substrings, not whole lines). It is a no-op in off/log mode.
// INN/SNILS/PAN are redacted only when the checksum validates, so an innocent
// digit run is never rewritten.
func (h *Hook) Redact(text string) string {
	if h.mode != ModeRedact {
		return text
	}
	text = redactRU(text)
	text = redactValidated(text, snilsRe, validateSNILS, redactions[CatINNSNILS])
	text = redactValidated(text, innRe, validateINN, redactions[CatINNSNILS])
	text = redactValidated(text, panRe, func(s string) bool { _, ok := validatePAN(s); return ok }, redactions[CatPAN])
	// I18N-13 national PII: redact only checksum/format-validated matches so an
	// innocent digit run is never rewritten.
	text = redactValidated(text, cpfRe, validateCPF, redactions[CatBR])
	text = redactValidated(text, cnpjRe, validateCNPJ, redactions[CatBR])
	text = redactValidated(text, aadhaarRe, validateAadhaar, redactions[CatIN])
	text = redactValidated(text, panINRe, func(s string) bool { _, ok := validatePANIN(s); return ok }, redactions[CatIN])
	text = redactValidated(text, mykadRe, validateMyKad, redactions[CatMY])
	text = redactValidated(text, iqamaRe, validateIqama, redactions[CatAE])
	text = redactValidated(text, zaNINRe, validateZANIN, redactions[CatZA])
	text = redactValidated(text, ngNINRe, validateNGNIN, redactions[CatNG])
	text = redactValidated(text, keNINRe, validateKENIN, redactions[CatKE])
	text = redactValidated(text, egNINRe, validateEGNIN, redactions[CatEG])
	text = secretRe.ReplaceAllString(text, redactions[CatSecret])
	text = pemRe.ReplaceAllString(text, redactions[CatSecret])
	// MC-2: credential-keyed values keep their key, lose their value.
	text = redactCredentialKeys(text)
	text = injectionRe.ReplaceAllString(text, redactions[CatInjection])
	return text
}

// redactValidated replaces every match of re for which valid(match) is true.
func redactValidated(text string, re *stdregexp.Regexp, valid func(string) bool, repl string) string {
	return re.ReplaceAllStringFunc(text, func(m string) string {
		if valid(m) {
			return repl
		}
		return m
	})
}

// ResolveMode is the config-time helper: it parses the raw guard_mode string
// and returns the resolved Mode plus a human note for the Warn log when the
// value was invalid (resolved to off).
func ResolveMode(raw string) (Mode, string) {
	mode, ok := ParseMode(raw)
	if !ok {
		return ModeOff, fmt.Sprintf("invalid guard_mode %q — falling back to off", raw)
	}
	return mode, ""
}
