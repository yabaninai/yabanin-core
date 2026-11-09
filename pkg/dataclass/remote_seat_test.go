package dataclass

// E04-P01-W03-C03 battery: the external-judge seat. All transports and
// permissions here are in-memory fakes — the core ships none (pinned
// structurally by TestRemoteSeatNoEgressInCore).

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/guardhooks"
)

type permFake struct {
	calls   int
	allowed bool
	err     error
	lastOrg string
}

func (p *permFake) AllowExternalJudge(_ context.Context, orgID string) (bool, error) {
	p.calls++
	p.lastOrg = orgID
	return p.allowed, p.err
}

type transportFake struct {
	calls   int
	last    SeatPayload
	verdict SeatVerdict
	err     error
}

func (tr *transportFake) Judge(_ context.Context, payload SeatPayload) (SeatVerdict, error) {
	tr.calls++
	tr.last = payload
	return tr.verdict, tr.err
}

func seatForTest(t *testing.T, allowed bool) (*RemoteSeat, *permFake, *transportFake) {
	t.Helper()
	perms := &permFake{allowed: allowed}
	transport := &transportFake{verdict: SeatVerdict{Labels: []string{"pii.innsnils"}}}
	seat, err := NewRemoteSeat(perms, transport, 7)
	if err != nil {
		t.Fatalf("NewRemoteSeat: %v", err)
	}
	return seat, perms, transport
}

func seatRequest() ClassifyRequest {
	return ClassifyRequest{
		Text:            "ИНН 7707083893 и ничего больше",
		TextType:        TextTypePlain,
		TaxonomyVersion: 7,
	}
}

func TestRemoteSeatConstructionRequiresDependencies(t *testing.T) {
	if _, err := NewRemoteSeat(nil, &transportFake{}, 7); err == nil {
		t.Fatalf("nil permission must be a construction refusal")
	}
	if _, err := NewRemoteSeat(&permFake{}, nil, 7); err == nil {
		t.Fatalf("nil transport must be a construction refusal")
	}
}

func TestRemoteSeatDenyMakesZeroTransportCalls(t *testing.T) {
	seat, perms, transport := seatForTest(t, false)
	_, err := seat.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", seatRequest())
	if !errors.Is(err, ErrSeatDenied) {
		t.Fatalf("denial must be ErrSeatDenied, got %v", err)
	}
	if perms.calls != 1 || transport.calls != 0 {
		t.Fatalf("permission consulted once (%d), transport never (%d)", perms.calls, transport.calls)
	}
}

func TestRemoteSeatPermissionErrorIsDenial(t *testing.T) {
	boom := errors.New("permission backend down")
	perms := &permFake{err: boom}
	transport := &transportFake{}
	seat, err := NewRemoteSeat(perms, transport, 7)
	if err != nil {
		t.Fatalf("NewRemoteSeat: %v", err)
	}
	_, err = seat.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", seatRequest())
	if !errors.Is(err, ErrSeatDenied) {
		t.Fatalf("permission error must surface as denial, got %v", err)
	}
	if !errors.Is(err, boom) {
		t.Fatalf("the underlying permission error must stay wrapped, got %v", err)
	}
	if transport.calls != 0 {
		t.Fatalf("a failed permission check must make zero transport calls, got %d", transport.calls)
	}
}

func TestRemoteSeatInvalidOrgNeverReachesPermission(t *testing.T) {
	seat, perms, transport := seatForTest(t, true)
	for _, org := range []string{"", "not-a-uuid"} {
		if _, err := seat.Judge(context.Background(), org, seatRequest()); !errors.Is(err, ErrInvalidOrgID) && !errors.Is(err, ErrEmptyOrgID) {
			t.Fatalf("org %q must be a typed org-id refusal, got %v", org, err)
		}
	}
	if perms.calls != 0 || transport.calls != 0 {
		t.Fatalf("garbage org ids must stop before permission (%d) and transport (%d)", perms.calls, transport.calls)
	}
}

func TestRemoteSeatContractRefusalsPrecedeTransport(t *testing.T) {
	seat, _, transport := seatForTest(t, true)
	cases := map[string]ClassifyRequest{
		"unsupported type": {Text: "x", TextType: "xml", TaxonomyVersion: 7},
		"empty text":       {Text: "   ", TextType: TextTypePlain, TaxonomyVersion: 7},
		"version skew":     {Text: "x", TextType: TextTypePlain, TaxonomyVersion: 8},
	}
	for name, req := range cases {
		if _, err := seat.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", req); err == nil {
			t.Fatalf("%s must refuse", name)
		}
	}
	if transport.calls != 0 {
		t.Fatalf("contract refusals must make zero transport calls, got %d", transport.calls)
	}
}

func TestRemoteSeatHappyPathSendsScrubbedPayload(t *testing.T) {
	seat, _, transport := seatForTest(t, true)
	req := ClassifyRequest{
		Text:            `ИНН 7707083893, ключ {"api_key":"abcdefgh12345678"}`,
		TextType:        TextTypePlain,
		TaxonomyVersion: 7,
	}
	verdict, err := seat.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", req)
	if err != nil {
		t.Fatalf("Judge: %v", err)
	}
	if !reflect.DeepEqual(verdict, SeatVerdict{Labels: []string{"pii.innsnils"}}) {
		t.Fatalf("verdict must pass through verbatim, got %+v", verdict)
	}
	if transport.calls != 1 {
		t.Fatalf("exactly one transport call, got %d", transport.calls)
	}
	payload := transport.last
	if payload.OrgID != "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f" || payload.TaxonomyVersion != 7 || payload.TextType != TextTypePlain {
		t.Fatalf("payload envelope wrong: %+v", payload)
	}
	if strings.Contains(payload.Text, "7707083893") {
		t.Fatalf("raw INN leaked across the boundary: %q", payload.Text)
	}
	if strings.Contains(payload.Text, "abcdefgh12345678") {
		t.Fatalf("credential value leaked across the boundary: %q", payload.Text)
	}
	if !strings.Contains(payload.Text, "[REDACTED_ID]") {
		t.Fatalf("INN evidence must arrive as its redaction token: %q", payload.Text)
	}
	if !strings.Contains(payload.Text, "[REDACTED_CREDENTIAL]") {
		t.Fatalf("credential-key evidence must arrive as its redaction token: %q", payload.Text)
	}
}

func TestRemoteSeatPayloadDeterministic(t *testing.T) {
	seat, _, transport := seatForTest(t, true)
	req := seatRequest()
	for i := 0; i < 2; i++ {
		if _, err := seat.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", req); err != nil {
			t.Fatalf("Judge #%d: %v", i+1, err)
		}
	}
	first, second := transport.last, transport.last // last is overwritten; compare via two calls with capture
	_ = first
	_ = second
	// stronger: run a fresh seat and compare payloads across instances
	other, _, otherTransport := seatForTest(t, true)
	if _, err := other.Judge(context.Background(), "0d0ee1df-7f0c-47b5-8d33-9d0a112b5c1f", req); err != nil {
		t.Fatalf("second seat Judge: %v", err)
	}
	if !reflect.DeepEqual(transport.last, otherTransport.last) {
		t.Fatalf("same request must yield identical payloads:\n%+v\n%+v", transport.last, otherTransport.last)
	}
}

func TestScrubForSeatLeavesNoRawEvidence(t *testing.T) {
	const raw = `СНИЛС 112-233-445 95, карта 4111111111111111, {"api_key":"abcdefgh12345678"}, bearer abcdef12345678`
	scrubbed, err := ScrubForSeat(context.Background(), raw)
	if err != nil {
		t.Fatalf("ScrubForSeat: %v", err)
	}
	for _, leak := range []string{"112-233-445 95", "11223344595", "4111111111111111", "abcdefgh12345678", "abcdef12345678"} {
		if strings.Contains(scrubbed, leak) {
			t.Fatalf("evidence leaked: %q in %q", leak, scrubbed)
		}
	}
	for _, token := range []string{"[REDACTED_ID]", "[REDACTED_PAN]", "[REDACTED_CREDENTIAL]", "[REDACTED]"} {
		if !strings.Contains(scrubbed, token) {
			t.Fatalf("expected token %s in %q", token, scrubbed)
		}
	}
}

func TestScrubForSeatIsIdempotent(t *testing.T) {
	raw := `ИНН 7707083893 и токен {"refresh_token":"zX9mQp1kLw2v"}`
	once, err := ScrubForSeat(context.Background(), raw)
	if err != nil {
		t.Fatalf("ScrubForSeat: %v", err)
	}
	twice, err := ScrubForSeat(context.Background(), once)
	if err != nil {
		t.Fatalf("ScrubForSeat of scrubbed text: %v", err)
	}
	if once != twice {
		t.Fatalf("scrubbing must be idempotent:\n%q\n%q", once, twice)
	}
}

func TestScrubForSeatCanceledContextRefuses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ScrubForSeat(ctx, "ИНН 7707083893"); err == nil {
		t.Fatalf("canceled context must refuse, not return a scrubbed payload")
	}
}

// TestSeatRedactionsMirrorGuardhooksTokens pins the mirror literally:
// the source of truth is the redactions map in pkg/guardhooks
// (unexported there; read-only dependency). If guardhooks ever changes
// a token under a new version, this pin forces a conscious mirror
// update instead of silent drift.
func TestSeatRedactionsMirrorGuardhooksTokens(t *testing.T) {
	want := map[guardhooks.Category]string{
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
		guardhooks.CatRUPassport: "[REDACTED_P" + "ASSPORT]",
		guardhooks.CatOGRN:       "[REDACTED_OGRN]",
		guardhooks.CatPhone:      "[REDACTED_PHONE]",
		guardhooks.CatEmail:      "[REDACTED_EMAIL]",
	}
	if !reflect.DeepEqual(seatRedactions, want) {
		t.Fatalf("seatRedactions drifted from the guardhooks tokens:\n%+v", seatRedactions)
	}
}

// TestRemoteSeatNoEgressInCore is the structural red-boundary pin: no
// non-test file of pkg/dataclass may contain network, process,
// environment or entropy vocabulary. The seat ships interfaces only;
// the real transport is the wiring layer's property.
func TestRemoteSeatNoEgressInCore(t *testing.T) {
	banned := []string{
		"net/http", "http.Client", "net.Dial", "grpc",
		"exec.Command", "RoundTrip", "os.Getenv", "time.Now",
		"math/rand", "crypto/rand",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	checked := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		checked++
		content, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("ReadFile %s: %v", e.Name(), err)
		}
		for _, token := range banned {
			if strings.Contains(string(content), token) {
				t.Fatalf("%s: banned egress/entropy token %q in a core (non-test) file", e.Name(), token)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("structural check must cover the package's non-test files")
	}
}
