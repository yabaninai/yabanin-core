package lineage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// L02: durable evidence outbox. The gateway writes each attestation into the
// lineage_outbox table (durable, committed before Append returns) and a
// background relay consumer moves pending rows into request_lineage,
// idempotently (on request_id). This removes the in-memory queue's hard-kill
// loss window (the L01 decision).
//
// Loss properties:
//   - Hard kill: the outbox row is already committed → 0 lost; the relay
//     resumes from pending rows after restart.
//   - DB outage: Append fails loudly (error returned to the caller) — no false
//     success, nothing silently buffered in memory.
//   - Relay delay: a committed-but-not-yet-relayed row is a *delay*, not a
//     *loss*; the consumer is idempotent and resumes from pending rows.
//
// Single-writer invariant: the relay is the ONLY writer of chained
// request_lineage rows (guarded by relayMu), so per-org prev_hash links can
// never interleave with another writer.

// ErrRelayInProgress is returned when a relay pass is already running, so
// callers cannot double-run the consumer.
var ErrRelayInProgress = errors.New("lineage outbox relay already in progress")

// dbtx is the minimal database surface the outbox needs. *pgxpool.Pool
// implements it, allowing injection of test doubles.
type dbtx interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Outbox is the lineage_outbox table + relay consumer.
type Outbox struct {
	db     dbtx
	log    *slog.Logger
	mu     *relayMu
	maxRel int // per-relay-batch cap (bounded work per pass)
}

// relayMu guards the single-writer invariant of the relay (one pass at a
// time). It is a pointer so it can be shared in tests.
type relayMu struct {
	lock chan struct{}
}

func newRelayMu() *relayMu { return &relayMu{lock: make(chan struct{}, 1)} }

func (m *relayMu) tryLock() bool {
	select {
	case m.lock <- struct{}{}:
		return true
	default:
		return false
	}
}

func (m *relayMu) unlock() { <-m.lock }

// NewOutbox builds a lineage outbox over the database handle.
func NewOutbox(db dbtx, l *slog.Logger) *Outbox {
	return &Outbox{db: db, log: l.With("component", "lineage-outbox"), mu: newRelayMu(), maxRel: 500}
}

// Enqueue inserts one attestation into the outbox. The write is durable when
// this returns nil — that is the loss guarantee. A duplicate request_id is a
// no-op (idempotent re-send), not an error.
func (o *Outbox) Enqueue(ctx context.Context, att Attestation, sigB64, keyID string) error {
	raw, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation for outbox: %w", err)
	}
	hash, err := att.Hash()
	if err != nil {
		return err
	}
	_, err = o.db.Exec(ctx, `
		INSERT INTO lineage_outbox (
			request_id, org_id, model_used, inference_region, model_origin_country,
			log_storage_region, provider_entity_jurisdiction, region_evidence,
			attestation_hash, attestation_signature, attestation_key_id, raw_attestation
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (request_id) DO NOTHING
	`, att.RequestID, att.OrgID, att.ModelUsed, att.InferenceRegion, att.ModelOrigin,
		att.LogStorageRegion, att.ProviderEntity, att.RegionEvidence,
		hash, nullIfEmpty(sigB64), nullIfEmpty(keyID), raw)
	if err != nil {
		return fmt.Errorf("enqueue lineage outbox: %w", err)
	}
	return nil
}

// pendingEntry is one claimed outbox row plus its table id.
type pendingEntry struct {
	id  int64
	row pendingRow
}

// pendingRow is the outbox payload of one row to relay.
type pendingRow struct {
	requestID          string
	orgID              string
	modelUsed          string
	inferenceRegion    string
	modelOriginCountry string
	logStorageRegion   string
	providerEntity     string
	regionEvidence     string
	attHash            string
	sigB64             string
	keyID              string
	raw                []byte
}

// RelayPass relays up to maxRel pending rows into request_lineage, marking them
// relayed. It is idempotent: a row already present in request_lineage (same
// request_id) is marked relayed without re-inserting. A per-row failure leaves
// the row pending (it will be retried on the next pass). Returns the number of
// rows relayed.
func (o *Outbox) RelayPass(ctx context.Context) (int, error) {
	if !o.mu.tryLock() {
		return 0, ErrRelayInProgress
	}
	defer o.mu.unlock()

	// Claim a bounded set of pending rows (id-ordered, oldest first).
	rows, err := o.db.Query(ctx, `
		SELECT id, request_id, org_id, model_used, inference_region, model_origin_country,
		       log_storage_region, provider_entity_jurisdiction, region_evidence,
		       attestation_hash, attestation_signature, attestation_key_id, raw_attestation
		FROM lineage_outbox
		WHERE relayed_at IS NULL
		ORDER BY id
		LIMIT $1
	`, o.maxRel)
	if err != nil {
		return 0, fmt.Errorf("claim outbox rows: %w", err)
	}
	var pending []pendingEntry
	for rows.Next() {
		var p pendingEntry
		var sig, keyID any
		if err := rows.Scan(&p.id, &p.row.requestID, &p.row.orgID, &p.row.modelUsed,
			&p.row.inferenceRegion, &p.row.modelOriginCountry, &p.row.logStorageRegion,
			&p.row.providerEntity, &p.row.regionEvidence, &p.row.attHash,
			&sig, &keyID, &p.row.raw); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan outbox row: %w", err)
		}
		p.row.sigB64, _ = sig.(string)
		p.row.keyID, _ = keyID.(string)
		pending = append(pending, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("iterate outbox rows: %w", err)
	}

	relayed := 0
	for _, p := range pending {
		att, err := attestationFromRaw(p.row.raw)
		if err != nil {
			// Malformed row: mark relayed so it does not wedge the pipeline,
			// but log loudly (evidence integrity is an ops incident).
			o.log.Error("outbox row has malformed raw_attestation; skipping", "request_id", p.row.requestID, "error", err)
			o.markRelayed(ctx, p.id)
			continue
		}
		if err := o.relayOne(ctx, p.id, att, p.row.sigB64, p.row.keyID, p.row.attHash); err != nil {
			// Leave it pending; the next pass retries. Do not fail the whole
			// pass on one bad row.
			o.log.Warn("outbox relay row failed, leaving pending", "request_id", p.row.requestID, "error", err)
			continue
		}
		relayed++
	}
	return relayed, nil
}

// relayOne inserts the attestation into request_lineage (idempotent on
// request_id) and, on success, marks the outbox row relayed.
func (o *Outbox) relayOne(ctx context.Context, outboxID int64, att Attestation, sigB64, keyID, attHash string) error {
	recHash, prev, err := o.chainLinks(ctx, att, sigB64, keyID)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(att)
	if err != nil {
		return fmt.Errorf("marshal attestation for relay: %w", err)
	}
	// INSERT … ON CONFLICT DO NOTHING makes the relay idempotent: if
	// request_lineage already has this request_id (e.g. a relay that committed
	// the insert but crashed before marking relayed), we skip the insert and
	// just mark the outbox row relayed.
	_, err = o.db.Exec(ctx, `
		INSERT INTO request_lineage (
			request_id, org_id, model_used, inference_region,
			model_origin_country, log_storage_region, provider_entity_jurisdiction,
			region_evidence, attestation_hash, attestation_signature, attestation_key_id,
			raw_attestation, record_hash, prev_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
		ON CONFLICT (request_id) DO NOTHING
	`, att.RequestID, att.OrgID, att.ModelUsed, att.InferenceRegion,
		att.ModelOrigin, att.LogStorageRegion, att.ProviderEntity,
		att.RegionEvidence, attHash, sigB64, keyID, raw, recHash, nullIfEmpty(prev))
	if err != nil {
		return fmt.Errorf("relay insert lineage: %w", err)
	}
	o.markRelayed(ctx, outboxID)
	return nil
}

// chainLinks computes the per-org record_hash + prev_hash for the row, reusing
// the exact H1 formula. The ON CONFLICT DO NOTHING in relayOne guards the
// insert against a duplicate request_id (already relayed).
func (o *Outbox) chainLinks(ctx context.Context, att Attestation, sigB64, keyID string) (recHash, prev string, err error) {
	prev, err = o.lastRecordHash(ctx, att.OrgID)
	if err != nil {
		return "", "", err
	}
	h, err := att.Hash()
	if err != nil {
		return "", "", err
	}
	return rowHash(prev, canonicalRecord(att, h, sigB64, keyID)), prev, nil
}

// lastRecordHash mirrors LedgerStore.lastRecordHash: the record_hash of the
// most recent chained row for the org (chain head), "" when none.
func (o *Outbox) lastRecordHash(ctx context.Context, orgID string) (string, error) {
	var prev string
	err := o.db.QueryRow(ctx, `
		SELECT record_hash FROM request_lineage
		WHERE org_id = $1 AND record_hash <> ''
		ORDER BY ts DESC LIMIT 1
	`, orgID).Scan(&prev)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("lookup last lineage hash for org %s: %w", orgID, err)
	}
	return prev, nil
}

func (o *Outbox) markRelayed(ctx context.Context, outboxID int64) {
	if _, err := o.db.Exec(ctx, `UPDATE lineage_outbox SET relayed_at = now() WHERE id = $1`, outboxID); err != nil {
		o.log.Error("mark outbox row relayed failed", "outbox_id", outboxID, "error", err)
	}
}

// attestationFromRaw decodes the stored raw_attestation JSONB.
func attestationFromRaw(raw []byte) (Attestation, error) {
	var att Attestation
	if err := json.Unmarshal(raw, &att); err != nil {
		return Attestation{}, err
	}
	return att, nil
}

// RelayLoop runs RelayPass on an interval until ctx is done, then drains one
// final pass. Returns when ctx is cancelled.
func (o *Outbox) RelayLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Final drain pass before exit. The loop's ctx is cancelled, but
			// the drain must run to completion — inherit values, drop the
			// cancellation.
			drainCtx := context.WithoutCancel(ctx)
			if n, err := o.RelayPass(drainCtx); err != nil {
				o.log.Error("final outbox relay pass failed", "error", err, "relayed", n)
			}
			return
		case <-ticker.C:
			if _, err := o.RelayPass(ctx); err != nil && !errors.Is(err, ErrRelayInProgress) {
				o.log.Warn("outbox relay pass failed", "error", err)
			}
		}
	}
}
