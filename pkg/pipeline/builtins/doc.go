// Package builtins provides the deterministic builtin steps of the Yabanin
// Policy Pipeline (YPP): the guardhooks port (national-pii, secrets,
// injection), the rule-based detectors (counters, contains, regex,
// json-schema, json-keys, url-check, code-detect, language, model-whitelist,
// metadata-required) and the mutators (redact, pseudonymize, header-rewrite,
// model-rewrite, partials-substitute). Detectors are pure offline
// inspection: they append Findings and never mutate the payload, call the
// network or touch an LLM. Mutators edit the run's payload clone in place.
//
// WIRING: Registry() returns the step-name → factory map; OP-8 owns wiring it
// into engine registries. The package has no init side effects and no global
// state: Registry() builds a fresh map on every call and every factory builds
// an immutable step value, so steps are goroutine-safe by construction.
//
// COMMON STEP CONTRACT (all builtins):
//
//   - Optional "kinds" param (list of payload kinds) selects which payloads a
//     step inspects; the default is per step family — every kind for
//     detectors (json-schema defaults to the output kinds response |
//     stream_prefix | stream_final) and for the span mutators
//     redact/pseudonymize (a stream policy with a kinds-less span mutator
//     header-rewrite (narrowable) and model-rewrite/partials-substitute
//     (model-rewrite rejects the param outright). A payload whose kind is not
//     selected is skipped silently (traced as ran, no findings).
//   - Optional "action" param (flag | mask | deny; default flag) is the
//     strictness carried by EVERY finding a DETECTOR emits — transcategory
//     consistent by construction: one step, one action. "allow" is rejected
//     at factory time (an allowing detector finding is inert noise; use a
//     shadow-mode policy instead). Invalid values are factory errors, i.e.
//     policy LOAD errors — fail-closed at load, never at request time.
//     Mutators do not take "action": their findings (redact pattern notes,
//     the model-rewrite trace note) are fixed-flag observations.
//   - Text extraction ("текст по kind"): Messages joined with "\n"; when no
//     message has content, Body; when both are absent, StreamChunk. JSON
//     steps (json-schema, json-keys) prefer Body over the message text.
//   - Findings carry Category, Severity (low | medium | high), Span
//     ("start:end" byte offsets into the inspected text, when meaningful) and
//     a bounded Evidence excerpt. Secret values are never quoted into
//     evidence — only a redaction token.
//   - Context: cooperative. Steps check ctx between phases and inside result
//     loops; a single regex scan / JSON decode is atomic but bounded (linear
//     algorithms, input caps, and the policy's per-step timeout).
//
// MUTATOR CONTRACT (redact, pseudonymize, header-rewrite, model-rewrite,
// partials-substitute):
//
//   - Spans: redact/pseudonymize consume the run's findings with Span
//     "start:end" byte offsets into the CURRENT payloadText layout and
//     validate them (bounds, rune boundaries, one message segment per span).
//     A stale span — the text changed between detector and mutator — fails
//     the step (fail_closed by default): order detector→mutator adjacently.
//     Spans overlapping an existing [REDACTED:…] / {{YPP_n}} token are
//     skipped: re-running or stacking span mutators never corrupts already-
//     substituted text (the idempotency boundary).
//   - Composition: mutators apply in pipeline order (org → key → model
//     attachment priority at the Engine); detectors always observe the latest
//     mutated text. redact→pseudonymize and pseudonymize→redact on the SAME
//     findings degrade to safe no-ops for the later span consumer.
//   - Pseudonymize map lifecycle: request_only (owner decision 2026-10-06).
//     The original→alias map lives only within the Engine run, rebuilt
//     deterministically per run; with carry=session it travels through
//     Meta.Labels[PseudonymCarrierLabel] for OP-8 session handling — see the
//     label contract in mutate_spans.go. Substitutions never flow back into
//     responses.
//   - header-rewrite is the only Payload.Headers writer; names/values are
//     validated at load (MIME tokens, no CR/LF/NUL — header injection is a
//     policy LOAD error).
//
// SEVERITY SCALE: high — direct security weight (leaked credential, prompt
// injection, checksum-confirmed identity number); medium — rule violation
// with policy weight (format-only PII hit, counter/contains/regex/schema
// violation, URL policy violation); low — observation (code detected,
// language detected, model rewrite note).
//
// REGEX SAFETY (builtin/regex and mutator "patterns"): Go's regexp is RE2 —
// matching is linear in input for any accepted pattern, so classic
// backtracking ReDoS is structurally impossible. The remaining cost blowup
// is COMPILE-time expansion of nested counted repeats. The factory therefore
// audits the parsed syntax tree and rejects (a) patterns longer than the
// cap, (b) nested quantifiers, (c) repeat-expansion products above the cap.
// Bad patterns are load errors, not runtime hazards.
package builtins
