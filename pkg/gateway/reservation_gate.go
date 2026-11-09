package cli

// Gateway-side reservation embedding (NEXT-18c, ADR-0001 rev. 3 §5.1): the
// endpoint pipelines call reservationPlan (pre-check, before any cache
// lookup), reservationGate.reserve (after a cache miss), and the finalize
// helpers at every request end. The gate rides the request context so
// serveStream and the native finishers pick it up without signature churn.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/metrics"
	"github.com/reireirei/yabanin/pkg/money"
	"github.com/reireirei/yabanin/pkg/resolver"
)

// reservationGateCtxKey carries the request's gate through the pipeline.
type reservationGateCtxKey struct{}

// reservationGate is one request's admission state.
type reservationGate struct {
	gw   *gateway
	w    http.ResponseWriter
	plan *budget.Plan
	rsv  *budget.Reservation
	// endpoint names the pipeline for logs (chat.completions, embeddings…).
	endpoint string
	// done guards the single finalize per request (several paths can
	// terminate one request — e.g. drain error after an answered stream).
	done bool
}

// withReservationGate stores the gate on the context (nil-safe).
func withReservationGate(ctx context.Context, g *reservationGate) context.Context {
	if g == nil {
		return ctx
	}
	return context.WithValue(ctx, reservationGateCtxKey{}, g)
}

// reservationGateFrom retrieves the gate (nil when absent/off).
func reservationGateFrom(ctx context.Context) *reservationGate {
	g, _ := ctx.Value(reservationGateCtxKey{}).(*reservationGate)
	return g
}

// off reports whether reservations are inactive for this request.
func (g *reservationGate) off() bool {
	return g == nil || g.plan == nil || g.plan.Mode == budget.ModeOff
}

// reservationScopeLabel maps a denial to its metric label; an empty scope
// (estimation refused the whole request) reports as "unpriced".
func reservationScopeLabel(scope budget.ScopeKind) string {
	if scope == "" {
		return "unpriced"
	}
	return string(scope)
}

// writeReservationDenial answers an enforce-mode refusal with the §9
// envelope: 402 for the wallet, 429 for budget areas, 403 model_unpriced
// for unpriced chains (I3), fail-closed 403 for missing capacity rows
// (D14), 503 when the reservation store itself is unavailable — and 503
// history_unavailable for the N10-P04-T03 durable-history outage (I40),
// which is a deployment-level condition, not a wallet or budget refusal.
func writeReservationDenial(w http.ResponseWriter, d *budget.Denial) {
	switch {
	case d == nil:
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"reservation admission failed")
	case errors.Is(d.Err, budget.ErrHistoryUnavailable):
		apierrors.WriteWithCode(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"durable request history temporarily unavailable — new requests are refused until history writes are guaranteed (I40; see YABANIN_HISTORY_MODE)", "history_unavailable")
	case errors.Is(d.Err, budget.ErrUnpricedModel):
		apierrors.WriteWithCode(w, http.StatusForbidden, apierrors.ErrorCodePermissionDenied,
			fmt.Sprintf("model pricing unavailable: %v", d.Err), "model_unpriced")
	case errors.Is(d.Err, budget.ErrInvalidEstimate):
		apierrors.Write(w, http.StatusBadRequest, apierrors.ErrorCodeInvalidRequest,
			fmt.Sprintf("request cannot be cost-bounded: %v", d.Err))
	case errors.Is(d.Err, budget.ErrInsufficientCapacity):
		switch d.Scope {
		case budget.ScopeWallet:
			apierrors.Write(w, http.StatusPaymentRequired, "insufficient_credits",
				"insufficient credits for this request")
		case budget.ScopeTeamMonth:
			apierrors.Write(w, http.StatusTooManyRequests, "budget_exceeded",
				"team budget limit reached")
		case budget.ScopeAgentDay:
			apierrors.Write(w, http.StatusTooManyRequests, "agent_budget_exceeded",
				"agent daily budget limit reached")
		case budget.ScopeSession:
			apierrors.Write(w, http.StatusTooManyRequests, "session_budget_exceeded",
				"session budget limit reached")
		default:
			apierrors.Write(w, http.StatusTooManyRequests, "budget_exceeded",
				"budget limit reached")
		}
	case errors.Is(d.Err, budget.ErrNoCapacitySource):
		switch d.Scope {
		case budget.ScopeTeamMonth:
			apierrors.Write(w, http.StatusForbidden, "budget_not_configured",
				"team has no budget configured — spending is disabled until a budget is set")
		case budget.ScopeAgentDay:
			apierrors.Write(w, http.StatusForbidden, "agent_budget_not_configured",
				"agent has no budget configured — spending is disabled until a budget is set")
		case budget.ScopeSession:
			apierrors.Write(w, http.StatusForbidden, "session_budget_not_configured",
				"session key has no cost limit configured")
		default:
			apierrors.Write(w, http.StatusPaymentRequired, "insufficient_credits",
				"no credit wallet for this organization")
		}
	default:
		apierrors.Write(w, http.StatusServiceUnavailable, apierrors.ErrorCodeServiceUnavailable,
			"reservation admission temporarily unavailable")
	}
}

// reservationChain builds the billable planned chain (§4.3): the primary
// candidate plus every RESOLVABLE failover model (an unresolvable hop can
// never be called and never spends, so it stays out of the bound). nil when
// the resolver is not wired (tests): the caller's single primary hop is
// then used verbatim.
func (gw *gateway) reservationChain(ctx context.Context, info resolver.ModelInfo) []budget.ChainHop {
	if info.ModelName == "" {
		return nil
	}
	chain := []budget.ChainHop{{Provider: info.Provider, Model: info.ModelName}}
	if gw.res == nil || len(info.FailoverModels) == 0 {
		return chain
	}
	for _, name := range info.FailoverModels {
		if name == "" || name == info.ModelName {
			continue
		}
		mi, err := gw.res.ResolveChecked(ctx, name)
		if err != nil || mi.ModelName == "" {
			continue
		}
		chain = append(chain, budget.ChainHop{Provider: mi.Provider, Model: mi.ModelName})
	}
	return chain
}

// Image payload detection (D4): data URIs (OpenAI image_url, Responses
// input_image) and Anthropic base64 source blocks each price
// ImageTokenEstimate flat; long base64 runs never reach the model as text
// tokens and are stripped from the byte estimate.
var (
	reservationDataURL = regexp.MustCompile(`data:image/[a-zA-Z0-9.+-]+;base64,`)
	reservationAnthImg = regexp.MustCompile(`"media_type"\s*:\s*"image/[a-zA-Z0-9.+-]+"`)
	reservationB64Run  = regexp.MustCompile(`[A-Za-z0-9+/=]{256,}`)
)

// reservationInputProfile estimates the priced input: body bytes excluding
// base64 payload spans plus the flat per-image estimate count (D4/§14).
func reservationInputProfile(body []byte) (inputBytes int64, images int64) {
	total := int64(len(body))
	stripped := int64(0)
	for _, m := range reservationB64Run.FindAllIndex(body, -1) {
		stripped += int64(m[1] - m[0])
	}
	if stripped > total {
		stripped = total
	}
	images = int64(len(reservationDataURL.FindAllIndex(body, -1)) +
		len(reservationAnthImg.FindAllIndex(body, -1)))
	return total - stripped, images
}

// reservationPlan runs the §5.1 pre-check (after route+policy, BEFORE the
// cache lookup) and returns the request's gate. ok is false when the
// request was denied terminally in enforce mode (the response is already
// written; D7 — even a would-be cache hit is denied here). In shadow the
// request always proceeds; refusals land on would_deny metrics. A nil gate
// with ok=true means reservations are off for this request.
func (gw *gateway) reservationPlan(w http.ResponseWriter, r *http.Request, endpoint string, req budget.Request) (*reservationGate, bool) {
	adm := gw.admission
	if adm == nil {
		return nil, true
	}
	plan, err := adm.Plan(r.Context(), req)
	if plan != nil {
		for _, d := range plan.WouldDeny {
			metrics.ReservationsWouldDenyTotal.WithLabelValues(reservationScopeLabel(d.Scope)).Inc()
		}
		plan.WouldDeny = nil
	}
	if err != nil {
		denial := asDenial(err)
		scope := denial.Scope
		if errors.Is(err, budget.ErrHistoryUnavailable) {
			// The history gate is deployment-level (I40): its refusal is
			// not a wallet exhaustion — report the dedicated history scope
			// so the reservations_denied_total label vocabulary stays
			// truthful (§9 scopes plus "history").
			scope = budget.HistoryDenialScope
		}
		metrics.ReservationsDeniedTotal.WithLabelValues(reservationScopeLabel(scope)).Inc()
		writeReservationDenial(w, denial)
		return nil, false
	}
	if plan == nil || plan.Mode == budget.ModeOff {
		return nil, true
	}
	return &reservationGate{gw: gw, w: w, plan: plan, endpoint: endpoint}, true
}

// asDenial normalizes a Plan/Reserve failure into a *Denial: typed denials
// pass through; estimation failures (unpriced — I3, invalid estimate) and
// any other failure surface as wallet-scope denials so the §9 envelope can
// answer them (403/400/503 by the wrapped error).
func asDenial(err error) *budget.Denial {
	var d *budget.Denial
	if errors.As(err, &d) {
		return d
	}
	return &budget.Denial{Scope: budget.ScopeWallet, Err: err}
}

// reserve applies the plan after a cache miss (§5.1). It returns false when
// the request was denied terminally (the response is already written).
func (g *reservationGate) reserve(ctx context.Context) bool {
	if g.off() || g.done {
		return true
	}
	rsv, err := g.gw.admission.Reserve(ctx, g.plan)
	if rsv == nil && g.plan != nil {
		for _, d := range g.plan.WouldDeny { // reserve-time shadow refusals
			metrics.ReservationsWouldDenyTotal.WithLabelValues(reservationScopeLabel(d.Scope)).Inc()
		}
		g.plan.WouldDeny = nil
	}
	if err != nil && !errors.Is(err, budget.ErrNotReserved) {
		denial := asDenial(err)
		metrics.ReservationsDeniedTotal.WithLabelValues(reservationScopeLabel(denial.Scope)).Inc()
		writeReservationDenial(g.w, denial)
		return false
	}
	g.rsv = rsv
	return true
}

// attach stamps the reserve tuples and termination on the event.
func (g *reservationGate) attach(ev *eventpub.Event, termination budget.Termination) {
	if g == nil || g.rsv == nil || ev == nil {
		return
	}
	ev.Reservations = g.rsv.TuplesJSON()
	if budget.ValidTermination(termination) {
		ev.Termination = string(termination)
	}
}

// finalize records the finished request's actual spend in the local escrow
// and attaches the tuples to the event (§5.3 Finalize). resaleUSD/costUSD
// are the event's own resale/estimated-cost floats, so the local ledger
// stays in step with the settlement worker's per-scope charges.
func (g *reservationGate) finalize(ev *eventpub.Event, resaleUSD, costUSD float64, termination budget.Termination) {
	if g.off() || g.done {
		g.attach(ev, termination)
		return
	}
	g.done = true
	if g.rsv != nil {
		walletActual, budgetActual := reservationActuals(resaleUSD, costUSD)
		g.gw.admission.Finalize(g.rsv, walletActual, budgetActual)
	}
	g.attach(ev, termination)
}

// finalizeNoEvent records the accounting for request ends that publish no
// analytics event (gate denials, breaker rejections): the in-flight bound
// releases with zero spend and the idle return sweeps the escrow.
func (g *reservationGate) finalizeNoEvent(termination budget.Termination) {
	g.finalize(nil, 0, 0, termination)
}

// reservationActuals mirrors the consumer's per-scope charge resolution
// (NEXT-18d resaleDeductionMicro + costQuote): the wallet bills the resale
// quote (positive only), the budget areas bill the base quote. Unknown
// quotes are never zeros — they contribute no local spend either.
func reservationActuals(resaleUSD, costUSD float64) (wallet, budget money.MicroUSD) {
	resale, resaleState := money.QuoteFromUSD(resaleUSD, true)
	if resaleState == money.QuotePositive {
		wallet = resale
	} else if cost, costState := money.QuoteFromUSD(costUSD, true); costState == money.QuotePositive {
		wallet = cost
	}
	if base, baseState := money.QuoteFromUSD(costUSD, true); baseState == money.QuotePositive || baseState == money.QuoteZero {
		budget = base
	}
	return wallet, budget
}

// reservationSessionKey resolves the session scope key: only keys with a
// money cap get a session reservation (D14 — the store refuses uncapped
// keys, so the gateway never requests that scope for them).
func reservationSessionKey(ctx context.Context, sessionKeyID string) string {
	if sessionKeyID == "" {
		return ""
	}
	if p, ok := principalFrom(ctx); ok && p.SessionKeyID == sessionKeyID && p.SessionMaxCostUSD != nil {
		return sessionKeyID
	}
	return ""
}

// reservationMaxTokens projects an int token cap to the estimator's int64.
func reservationMaxTokens(tokens *int) *int64 {
	if tokens == nil || *tokens <= 0 {
		return nil
	}
	t := int64(*tokens)
	return &t
}

// reservationRequest assembles the §4.3 estimation input for one request.
func (gw *gateway) reservationRequest(ctx context.Context, orgID, teamID, agentID, sessionKeyID string, info resolver.ModelInfo, body []byte, maxTokens *int64, embeddings bool) budget.Request {
	inputBytes, images := reservationInputProfile(body)
	return budget.Request{
		OrgID:        orgID,
		TeamID:       teamID,
		AgentID:      agentID,
		SessionKeyID: reservationSessionKey(ctx, sessionKeyID),
		Chain:        gw.reservationChain(ctx, info),
		InputBytes:   inputBytes,
		ImageCount:   images,
		MaxTokens:    maxTokens,
		Embeddings:   embeddings,
	}
}

// reservationOrgLoader reads an organization's reservation settings for the
// admission controller: the §9 mode and the D3a default output cap. Any
// failure (missing org row, schema without the column, transient error)
// degrades to off — the mode only ever tightens admission for orgs that
// opted in, so failing to legacy can never deny an unopted request.
func reservationOrgLoader(dbPool *pgxpool.Pool) budget.OrgLoader {
	return func(ctx context.Context, orgID string) (budget.OrgSettings, error) {
		if dbPool == nil || orgID == "" {
			return budget.OrgSettings{Mode: budget.ModeOff}, nil
		}
		var mode string
		var outCap *int64
		if err := dbPool.QueryRow(ctx,
			`SELECT COALESCE(reservations_mode, 'off'), default_output_cap_tokens
			 FROM organizations WHERE id = $1`, orgID).Scan(&mode, &outCap); err != nil {
			return budget.OrgSettings{Mode: budget.ModeOff}, err
		}
		capTokens := int64(0)
		if outCap != nil && *outCap > 0 {
			capTokens = *outCap
		}
		return budget.OrgSettings{Mode: budget.ResolveMode(mode), DefaultOutCapTokens: capTokens}, nil
	}
}
