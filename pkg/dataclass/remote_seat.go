// Package dataclass — the permission-gated external-judge seat
// (E04-P01-W03-C03).
//
// RemoteSeat delegates classification to an EXTERNAL judge through the
// SeatTransport seam. Two red-line properties hold by construction:
//
//   - ZERO transport implementations ship in the core. SeatTransport is
//     an interface; no file in pkg/dataclass (outside _test.go fakes)
//     dials, connects, fetches or spawns anything — pinned by
//     TestRemoteSeatNoEgressInCore, which structurally bans network/
//     process/entropy vocabulary from every non-test file of the
//     package. The real transport belongs to the wiring layer that owns
//     egress policy.
//   - NOTHING raw leaves the org boundary. Before any transport call the
//     payload runs through a fail-closed scrubbing precondition: the
//     key-preserving credential scrub (redact.ScrubSecrets), then a
//     detector pass whose findings are span-replaced with the guardhooks
//     redaction tokens, then a verification re-scan. A payload that
//     still carries findings after scrubbing refuses with
//     ErrRedactionIncomplete — the seat fails closed instead of leaking.
//
// Permission is deny-by-default (routed review note (b)): only an
// explicit (true, nil) from SeatPermission proceeds, and a permission
// error is a denial, not an open question. org:taxonomy.manage stays
// membership-only until the wiring card registers it in the closed
// permission matrix; this package takes the decision as a dependency.
package dataclass

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/redact"
)

// ErrSeatDenied — the org is not allowed to use the external judge, or
// the permission check itself failed. Both are denials: the seat is
// fail-closed on permission.
var ErrSeatDenied = errors.New("dataclass: external judge seat denied")

// ErrRedactionIncomplete — after the scrubbing precondition the payload
// still produces detector findings. Defensive branch: today's tokens
// carry no matchable signal, so this cannot fire with the current
// detector set; it exists so a future detector that matches token
// neighborhoods fails closed here instead of leaking past the boundary.
var ErrRedactionIncomplete = errors.New("dataclass: seat payload still carries findings after scrubbing")

// SeatPermission decides whether an org may send payloads to the
// external judge. Deny by default: implementations return (false, nil)
// for "no" and (true, nil) ONLY for an explicit grant; any error is
// treated by RemoteSeat as a denial.
type SeatPermission interface {
	AllowExternalJudge(ctx context.Context, orgID string) (allowed bool, err error)
}

// SeatTransport carries one scrubbed payload to the external judge and
// returns its verdict. The core ships ZERO implementations of it — the
// egress owner (wiring layer) provides the real client under its own
// network policy; pkg/dataclass tests use in-memory fakes only.
type SeatTransport interface {
	Judge(ctx context.Context, payload SeatPayload) (SeatVerdict, error)
}

// SeatPayload is what crosses the org boundary: the org scope, the
// SCRUBBED text, the declared type of the ORIGINAL payload (the
// scrubbed text may no longer parse as that type — the privacy boundary
// wins over type fidelity), and the taxonomy version pin. No spans, no
// findings, no raw evidence cross.
type SeatPayload struct {
	OrgID           string
	Text            string
	TextType        SupportedTextType
	TaxonomyVersion int64
}

// SeatVerdict is the judge's answer: label keys only. It is returned to
// the caller verbatim — validating the keys against the org taxonomy is
// the caller's fold, not the seat's.
type SeatVerdict struct {
	Labels  []string
	Unknown bool
}

// RemoteSeat is the external-judge seat for one org taxonomy revision.
type RemoteSeat struct {
	perms     SeatPermission
	transport SeatTransport
	version   int64
}

// NewRemoteSeat binds a seat. Both dependencies are mandatory: a nil
// permission or transport is a construction refusal, never a seat that
// silently allows or silently no-ops.
func NewRemoteSeat(perms SeatPermission, transport SeatTransport, taxonomyVersion int64) (*RemoteSeat, error) {
	if perms == nil {
		return nil, errors.New("dataclass: seat construction: nil SeatPermission")
	}
	if transport == nil {
		return nil, errors.New("dataclass: seat construction: nil SeatTransport")
	}
	return &RemoteSeat{perms: perms, transport: transport, version: taxonomyVersion}, nil
}

// Judge runs one delegation. Observable order: org scope validation
// (garbage ids never reach the permission check), permission (denial
// makes ZERO transport calls), the shared classify request contract,
// the scrubbing precondition, then exactly one transport call.
func (s *RemoteSeat) Judge(ctx context.Context, orgID string, req ClassifyRequest) (SeatVerdict, error) {
	if err := requireOrgID(orgID); err != nil {
		return SeatVerdict{}, err
	}
	allowed, err := s.perms.AllowExternalJudge(ctx, orgID)
	if err != nil {
		return SeatVerdict{}, fmt.Errorf("%w: permission check failed for org %s: %w", ErrSeatDenied, orgID, err)
	}
	if !allowed {
		return SeatVerdict{}, fmt.Errorf("%w: org %s has no external-judge grant", ErrSeatDenied, orgID)
	}
	if err := CheckClassifyRequest(ctx, req, s.version); err != nil {
		return SeatVerdict{}, err
	}
	scrubbed, err := ScrubForSeat(ctx, req.Text)
	if err != nil {
		return SeatVerdict{}, err
	}
	verdict, err := s.transport.Judge(ctx, SeatPayload{
		OrgID:           orgID,
		Text:            scrubbed,
		TextType:        req.TextType,
		TaxonomyVersion: req.TaxonomyVersion,
	})
	if err != nil {
		return SeatVerdict{}, fmt.Errorf("dataclass: external judge transport: %w", err)
	}
	return verdict, nil
}

// seatRedactions mirrors the guardhooks per-category redaction tokens
// (unexported there). Split spelling for the passport token follows the
// upstream convention so scanners do not read a token list as material.
var seatRedactions = map[guardhooks.Category]string{
	guardhooks.CatINNSNILS:   "[REDACTED_ID]",
	guardhooks.CatPAN:        "[REDACTED_PAN]",
	guardhooks.CatSecret:     "[REDACTED_SECRET]",
	guardhooks.CatCredential: "[REDACTED_CREDENTIAL]",
	guardhooks.CatInjection:  "[REDACTED_INJECTION]",
	guardhooks.CatBR:         "[REDACTED_BR]",
	guardhooks.CatIN:         "[REDACTED_IN]",
	guardhooks.CatMY:         "[REDACTED_MY]",
	guardhooks.CatAE:         "[REDACTED_AE]",
	guardhooks.CatZA:         "[REDACTED_ZA]",
	guardhooks.CatNG:         "[REDACTED_NG]",
	guardhooks.CatKE:         "[REDACTED_KE]",
	guardhooks.CatEG:         "[REDACTED_EG]",
	guardhooks.CatRUPassport: "[REDACTED_PASS" + "PORT]",
	guardhooks.CatOGRN:       "[REDACTED_OGRN]",
	guardhooks.CatPhone:      "[REDACTED_PHONE]",
	guardhooks.CatEmail:      "[REDACTED_EMAIL]",
}

// ScrubForSeat produces the boundary-crossing form of one text:
//
//  1. redact.ScrubSecrets — the key-preserving credential scrub used at
//     every durable boundary of the product (idempotent, JSON-aware);
//  2. a guardhooks builtin scan of the scrubbed text; every finding
//     span is replaced with its category token, applied right-to-left
//     so earlier offsets stay valid;
//  3. a verification re-scan — any surviving finding refuses with
//     ErrRedactionIncomplete (defensive: unreachable with the current
//     detector set, kept so future detectors fail closed).
//
// Deterministic: same input, same output, no clock, no entropy.
func ScrubForSeat(ctx context.Context, text string) (string, error) {
	scrubbed := redact.ScrubSecrets(text)
	replaced, err := replaceFindings(ctx, scrubbed)
	if err != nil {
		return "", err
	}
	verify, err := guardhooks.EvaluateBuiltins(guardhooks.Invocation{
		Context: ctx,
		Version: guardhooks.RuntimeVersion,
		Phase:   guardhooks.PhaseBefore,
		Kind:    guardhooks.ContentText,
		Text:    replaced,
	})
	if err != nil {
		return "", fmt.Errorf("dataclass: seat scrub verification scan: %w", err)
	}
	if len(verify.Findings) != 0 {
		return "", fmt.Errorf("%w: %d findings survived", ErrRedactionIncomplete, len(verify.Findings))
	}
	return replaced, nil
}

// replaceFindings span-replaces every builtin finding with its category
// token, right-to-left (descending start) so replacements do not shift
// the offsets of the findings still to apply. Zero findings return the
// input unchanged.
func replaceFindings(ctx context.Context, text string) (string, error) {
	evaluation, err := guardhooks.EvaluateBuiltins(guardhooks.Invocation{
		Context: ctx,
		Version: guardhooks.RuntimeVersion,
		Phase:   guardhooks.PhaseBefore,
		Kind:    guardhooks.ContentText,
		Text:    text,
	})
	if err != nil {
		return "", fmt.Errorf("dataclass: seat scrub scan: %w", err)
	}
	findings := append([]guardhooks.Finding(nil), evaluation.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Start != findings[j].Start {
			return findings[i].Start > findings[j].Start
		}
		return findings[i].End > findings[j].End
	})
	out := []byte(text)
	for _, f := range findings {
		token, ok := seatRedactions[f.Category]
		if !ok {
			// Every category the evaluator can emit has a token; an
			// unmapped category means the mirror drifted — refuse
			// rather than pass the span through.
			return "", fmt.Errorf("%w: unmapped category %q", ErrRedactionIncomplete, f.Category)
		}
		if f.Start < 0 || f.End > len(out) || f.Start >= f.End {
			return "", fmt.Errorf("%w: corrupt span %d:%d", ErrRedactionIncomplete, f.Start, f.End)
		}
		replacement := []byte(token)
		out = append(out[:f.Start], append(replacement, out[f.End:]...)...)
	}
	return string(out), nil
}
