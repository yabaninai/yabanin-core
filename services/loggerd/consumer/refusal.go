package consumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// Typed pre-dispatch refusal history (request.invalid with a
// producer-stamped status): no dispatch ever happened — no provider call,
// no reservation, no terminal fact, no charge. The row carries the EXACT
// wire status so refused demand stays visible in spend analytics and drain
// comparisons, the contract QG2-D2 established for budget refusals.
//
// Scope: only the unknown-model reject producer stamps a status. Policy
// denials, tool-gate denials and chat validation publish without one and
// keep the legacy generic behavior here (logged, acknowledged, no row).
//
// The refusal producer never mints an invocation identity — the refusal
// precedes admission. A stamped refusal that claims one is contradictory:
// the invocation DO NOTHING dedupe would let it hijack a paid dispatch's
// history slot and silently suppress the genuine terminal row. Such events
// park before any read or write; refusal rows are therefore always
// legacy-domain and never resolve admissions.
//
// Privacy: no response or upstream capture is bound under any content
// profile; the refused payload contributes only its prompt digest.

// errRefusalInvocationConflict parks a stamped refusal that claims an
// invocation identity: no such event exists upstream, and the claim must
// never take over a paid invocation's history slot.
var errRefusalInvocationConflict = errors.New("stamped refusal claims an invocation identity")

// handleRequestInvalidProfile routes one request.invalid event: a stamped
// status makes it a refusal-history record; an unstamped event keeps the
// legacy generic behavior.
func (c *StreamConsumer) handleRequestInvalidProfile(ctx context.Context, msg redis.XMessage, policy deliveryPolicy) error {
	ev := parseRequestEventPolicy(msg.Values, policy)
	if ev.statusCode <= 0 {
		c.logger.Info("generic event received",
			slog.String("event_type", "request.invalid"),
			slog.String("source", fmt.Sprintf("%v", msg.Values["source"])),
		)
		return nil
	}
	if ev.invocationIDValue != nil {
		c.logger.Error("stamped refusal claims an invocation identity — parking",
			slog.String("request_id", ev.requestID),
			slog.String("invocation_id", fmt.Sprintf("%v", ev.invocationIDValue)),
		)
		return errRefusalInvocationConflict
	}
	return c.persistRefusalHistory(ctx, msg, ev, policy)
}

// persistRefusalHistory writes the refusal row inside the claimed delivery
// transaction and commits it. No admission resolution runs: identity-bearing
// refusals park upstream of this path, so every row is legacy-domain.
func (c *StreamConsumer) persistRefusalHistory(ctx context.Context, msg redis.XMessage, ev requestEvent, policy deliveryPolicy) error {
	if c.dbPool == nil {
		c.logger.Error("DB pool not configured — cannot write request.invalid refusal history")
		return fmt.Errorf("DB is required but not configured")
	}

	c.markDeliverySeen(ctx, msg.ID)

	tx, claimed, err := c.beginDelivery(ctx, msg.ID)
	if err != nil || !claimed {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit

	// assembly: resolveSessionID moves to (value, error) — propagate here.
	sessionIDStr := c.resolveSessionID(ctx, tx, ev.orgID, ev.sessionID)
	row := refusalRequestLogRow(ev, sessionIDStr, ev.statusCode)
	row.setAttribution(c.attributionID(msg.Values, "api_key_id"), c.attributionID(msg.Values, "session_key_id"))

	if _, err := tx.Exec(ctx, row.insertSQL(), row.args()...); err != nil {
		return fmt.Errorf("insert request_log for request.invalid refusal: %w", err)
	}

	// OP-9 parity: commit a carried policy decision with the log (absent
	// policy skips silently).
	if err := c.insertPolicyDecision(ctx, tx, ev); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delivery transaction: %w", err)
	}

	c.logger.Warn("refused request logged",
		slog.String("request_id", ev.requestID),
		slog.String("org_id", ev.orgID),
		slog.Int64("status", ev.statusCode),
		slog.String("error", safeDiagnostic(policy.profile, ev.errorMsg)),
	)
	return nil
}
