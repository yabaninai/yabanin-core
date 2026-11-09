package adminstore

// The policy store persists versioned policy pipelines. The YAML content is
// stored verbatim; syntactic validation happens at the admin API boundary and
// full compilation happens gateway-side when the version is loaded. This store
// deliberately knows nothing about the pipeline schema.
//
// Concurrency/RLS contract (orgcredentials.go parity):
//   - every operation runs inside withPolicyTx: one transaction with the
//     app.current_org GUC pinned to the org — the org_isolation contract of
//     the policy_* RLS policies (migration 0008, ENABLE+FORCE). Without the
//     GUC the FORCE policy denies every row (fail-closed); a cross-org
//     resource id therefore reads as ErrNotFound, never as a leak.
//   - version-key invalidation: after every successful mutation the store
//     bumps the org's policy version via the optional PolicyVersionBumper
//     (wired with NewPolicyVersionCache over the shared Redis). The exact
//     Redis contract is documented on PolicyVersionKeyPrefix below. A failed
//     bump never fails the mutation — OP-8's TTL fallback bounds staleness.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Policy version labels (policy_versions.label).
const (
	PolicyLabelDraft  = "draft"
	PolicyLabelActive = "active"
	PolicyLabelCanary = "canary"
)

// PolicyPipeline is one org-scoped named policy pipeline (migration 0008).
type PolicyPipeline struct {
	ID string `json:"id"`
	// OrgID is immutable: pipelines never move between orgs.
	OrgID string `json:"org_id"`
	Name  string `json:"name"`
	// Enabled is the mode flag: false = detached (draft/kill-switched), true
	// = attached. The per-policy shadow|enforce nuance lives in the YAML.
	Enabled bool `json:"enabled"`
	// CurrentVersion is the version attachments resolve to (0 = none yet).
	CurrentVersion int       `json:"current_version"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// PolicyVersion is one immutable YAML version of a pipeline. YAML is the
// full document text — opaque to this store by design (full compilation is
// the gateway's job at load time, not the admin plane's).
type PolicyVersion struct {
	ID       string `json:"id"`
	PolicyID string `json:"policy_id"`
	OrgID    string `json:"org_id"`
	Version  int    `json:"version"`
	YAML     string `json:"yaml"`
	// GitSHA records the source revision for git-reconciled policies
	// ("" = authored via the UI / API).
	GitSHA    string    `json:"git_sha"`
	Label     string    `json:"label"` // draft | active | canary
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// PolicyAttachment binds a pipeline to (key label, model pattern, endpoint).
// KeyLabel "" maps to SQL NULL = every key of the org. Priority: smaller
// runs earlier (plan §2.2 — the engine executes ALL matching policies by
// priority, deny beats mask).
type PolicyAttachment struct {
	ID           string `json:"id"`
	PolicyID     string `json:"policy_id"`
	OrgID        string `json:"org_id"`
	KeyLabel     string `json:"key_label"`
	ModelPattern string `json:"model_pattern"`
	Endpoint     string `json:"endpoint"`
	Priority     int    `json:"priority"`
}

// PolicyPipelineSnapshot is one complete, org-scoped view of the policy
// pipelines, their selected active versions, and persisted attachments.
// LoadPolicySnapshot returns either the complete value or an error.
type PolicyPipelineSnapshot struct {
	Policies    []PolicyPipeline
	Versions    map[string]PolicyVersion
	Attachments map[string][]PolicyAttachment
	PromptPins  map[string]map[string]PromptPin
}

// PromptPin is the immutable prompt payload resolved for an active policy version.
type PromptPin struct {
	Ref     string `json:"ref"`
	Version string `json:"version"`
	Body    string `json:"body"`
}

// PolicyPipelineStore is the persistence contract for versioned policy
// pipelines. Every operation is scoped by the org-isolation GUC (FORCE RLS
// on policy_*), so callers must supply the org they are allowed to act on; a
// pipeline of another org is ErrNotFound.
type PolicyPipelineStore interface {
	// CreatePolicy creates the pipeline and its FIRST version (label draft).
	// current_version stays 0 until SetActivePolicyVersion.
	CreatePolicy(ctx context.Context, orgID, name, yaml, gitSHA, createdBy string) (PolicyPipeline, PolicyVersion, error)
	GetPolicy(ctx context.Context, orgID, policyID string) (PolicyPipeline, error)
	ListPolicies(ctx context.Context, orgID string) ([]PolicyPipeline, error)
	// UpdatePolicy flips the enabled mode flag only. Content changes are
	// versions (CreatePolicyVersion), never in-place edits — an immutable
	// version history is the whole point of the table.
	UpdatePolicy(ctx context.Context, orgID, policyID string, enabled bool) (PolicyPipeline, error)
	// CreatePolicyVersion appends the next draft version (max+1 per policy).
	CreatePolicyVersion(ctx context.Context, orgID, policyID, yaml, gitSHA, createdBy string) (PolicyVersion, error)
	ListPolicyVersions(ctx context.Context, orgID, policyID string) ([]PolicyVersion, error)
	GetPolicyVersion(ctx context.Context, orgID, policyID string, version int) (PolicyVersion, error)
	// SetActivePolicyVersion points current_version at version, flips its
	// label to active and demotes the previously active label to draft
	// (canaries untouched) — one transaction.
	SetActivePolicyVersion(ctx context.Context, orgID, policyID string, version int) (PolicyPipeline, error)
	// SetPolicyAttachments replace-all: the given rows become the pipeline's
	// whole attachment set in one transaction.
	SetPolicyAttachments(ctx context.Context, orgID, policyID string, atts []PolicyAttachment) ([]PolicyAttachment, error)
	ListPolicyAttachments(ctx context.Context, orgID, policyID string) ([]PolicyAttachment, error)
	// DeletePolicy removes the pipeline; versions and attachments cascade.
	DeletePolicy(ctx context.Context, orgID, policyID string) error
	// ONE transaction under an optimistic-concurrency token: expectVersion is
	// compared against the pipeline's current_version (0 = never activated)
	// with the row locked FOR UPDATE, so a concurrent writer between the
	// check and the write is impossible by construction (cas.go contract).
	// A mismatch applies NOTHING and returns ErrPreconditionFailed together
	// with the row's current state for the 409 body. nil expectVersion keeps
	// the plain (unconditional) semantics of the field-by-field methods.
	UpdatePolicyCAS(ctx context.Context, orgID, policyID string, upd PolicyUpdate, expectVersion *int, createdBy string) (PolicyPipeline, PolicyVersion, error)
}

// PolicyUpdate is the field-scoped PUT body of UpdatePolicyCAS — exactly the
// handlers' update surface (nil fields keep the stored value). Validation of
// the YAML SYNTAX stays at the API boundary; the store enforces its own
// storage invariants (non-empty yaml, attachment required fields).
type PolicyUpdate struct {
	YAML          *string
	GitSHA        *string
	Enabled       *bool
	ActiveVersion *int
	Attachments   *[]PolicyAttachment
}

// Empty reports whether the update carries no recognized field (the PUT's
// "nothing to update" 400).
func (u PolicyUpdate) Empty() bool {
	return u.YAML == nil && u.GitSHA == nil && u.Enabled == nil && u.ActiveVersion == nil && u.Attachments == nil
}

var _ PolicyPipelineStore = (*Store)(nil)

const policyPipelineTable = `policy_pipelines`
const policyVersionTable = `policy_versions`
const policyAttachmentTable = `policy_attachments`

// policyPipelineColumns is the canonical SELECT list for pipeline reads.
const policyPipelineColumns = `id::text, org_id::text, name, enabled, COALESCE(current_version, 0), created_at, updated_at`

// policyVersionColumns is the canonical SELECT list for version reads (yaml
// included: policy content is not secret material — it is admin-authored
// configuration, and the version endpoints must render it back verbatim).
const policyVersionColumns = `id::text, policy_id::text, org_id::text, version, yaml, git_sha, label, created_by, created_at`

// policyAttachmentColumns is the canonical SELECT list for attachment reads
// (key_label NULL reads as "" = every key of the org).
const policyAttachmentColumns = `id::text, policy_id::text, org_id::text, COALESCE(key_label, ''), model_pattern, endpoint, priority`

// PolicyVersionBumper is the gateway cache-invalidation hook (OP-0b → OP-8
// contract): after every successful policy mutation the store bumps the
// org's policy version so the gateway drops its compiled-pipeline cache
// entries immediately. Failure to bump never fails the mutation — OP-8's
// TTL fallback bounds the staleness.
type PolicyVersionBumper interface {
	SetPolicyVersion(ctx context.Context, orgID string, version int64) error
}

// PolicyVersionKeyPrefix is the Redis key namespace of the OP-8 version-key
// pkg/gateway orgcreds:ver: / mcpcreds:ver:):
//
//   - KEY:   "policystore:ver:<orgID>" (this exact prefix + the org id);
//   - VALUE: decimal int64 — the recommended value is time.Now().UnixNano()
//     (monotonic per org, no read-modify-write race between concurrent
//     admin mutations);
//   - TTL:   7 days, refreshed on every Set (abandoned orgs do not
//     accumulate keys); a MISSING key reads as version 0, not an error.
//
// The gateway (OP-8) reads the key to drop compiled-pipeline caches; with an
// unreachable Redis it degrades to its own hard TTL instead.
const PolicyVersionKeyPrefix = "policystore:ver:"

// PolicyVersionTTL bounds the Redis retention of one org's policy version
// key; every Set refreshes it (OrgCredsVersionStore parity).
const PolicyVersionTTL = 7 * 24 * time.Hour

// PolicyVersionRedis is the Redis surface the version cache needs
// (*redis.Client satisfies it — the same structural seam
// pkg/gateway.OrgCredsRedis uses).
type PolicyVersionRedis interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
}

// redisPolicyVersions is the production PolicyVersionBumper (and reader for
// OP-8's tests). Values are decimal int64 nanos.
type redisPolicyVersions struct {
	rdb PolicyVersionRedis
	log *slog.Logger
}

// NewPolicyVersionCache builds the Redis-backed policy version store. Wired
// in services/run/admin.go over the shared Redis; OP-8 reads the same keys.
func NewPolicyVersionCache(rdb PolicyVersionRedis, l *slog.Logger) *redisPolicyVersions {
	return &redisPolicyVersions{rdb: rdb, log: l}
}

func (s *redisPolicyVersions) key(orgID string) string {
	return PolicyVersionKeyPrefix + orgID
}

// GetPolicyVersion reads the org's current policy version. A missing key is
// version 0, not an error (fresh org / expired key / flushed cache).
func (s *redisPolicyVersions) GetPolicyVersion(ctx context.Context, orgID string) (int64, error) {
	v, err := s.rdb.Get(ctx, s.key(orgID)).Result()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read policy version: %w", err)
	}
	version, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse policy version %q: %w", v, err)
	}
	return version, nil
}

// SetPolicyVersion records a new policy version for the org. Called by the
// adminstore after every policy mutation (contract above).
func (s *redisPolicyVersions) SetPolicyVersion(ctx context.Context, orgID string, version int64) error {
	if err := s.rdb.Set(ctx, s.key(orgID), strconv.FormatInt(version, 10), PolicyVersionTTL).Err(); err != nil {
		return fmt.Errorf("write policy version: %w", err)
	}
	return nil
}

// SetPolicyVersionBumper wires the version-key invalidation (nil = skip; the
// gateway TTL bounds staleness). Production: NewPolicyVersionCache over the
// shared Redis.
func (s *Store) SetPolicyVersionBumper(b PolicyVersionBumper) {
	s.policyVersions = b
}

// bumpPolicyVersion invalidates the gateway's compiled-pipeline cache after
// a successful mutation. Fail-soft: a bump failure is a warning — OP-8's TTL
// bounds staleness either way, and the mutation itself already committed.
func (s *Store) bumpPolicyVersion(ctx context.Context, orgID string) {
	if s.policyVersions == nil {
		return
	}
	if err := s.policyVersions.SetPolicyVersion(ctx, orgID, time.Now().UnixNano()); err != nil && s.log != nil {
		s.log.Warn("policy version bump failed; gateway pipeline cache expires via TTL",
			"org_id", orgID, "error", err.Error())
	}
}

// withPolicyTx runs fn inside one transaction whose app.current_org GUC is
// pinned to orgID (withCredentialTx parity — see the RLS contract above).
func (s *Store) withPolicyTx(ctx context.Context, orgID string, fn func(tx auditTx) error) error {
	if s.db == nil {
		return fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return fmt.Errorf("begin policy tx: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("set policy isolation GUC: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit policy tx: %w", err)
	}
	return nil
}

// validatePolicyName applies the shared display-name bound (1..256 chars).
func validatePolicyName(name string) error {
	if n := len(name); n == 0 || n > 256 {
		return fmt.Errorf("policy name must be 1 to 256 characters")
	}
	return nil
}

// validatePolicyYAMLStored rejects an empty stored document. (Syntactic
// YAML validation is the admin API's job; the store only refuses the
// degenerate write the CHECK constraint would reject anyway.)
func validatePolicyYAMLStored(yaml string) error {
	if yaml == "" {
		return fmt.Errorf("policy yaml is required")
	}
	return nil
}

// CreatePolicy creates the pipeline and its first version (v1, draft) in one
// transaction. current_version stays 0 until SetActivePolicyVersion.
func (s *Store) CreatePolicy(ctx context.Context, orgID, name, yamlDoc, gitSHA, createdBy string) (PolicyPipeline, PolicyVersion, error) {
	if orgID == "" {
		return PolicyPipeline{}, PolicyVersion{}, fmt.Errorf("org id is required")
	}
	if err := validatePolicyName(name); err != nil {
		return PolicyPipeline{}, PolicyVersion{}, err
	}
	if err := validatePolicyYAMLStored(yamlDoc); err != nil {
		return PolicyPipeline{}, PolicyVersion{}, err
	}

	var p PolicyPipeline
	var v PolicyVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+policyPipelineTable+` (org_id, name) VALUES ($1::uuid, $2)
			 RETURNING `+policyPipelineColumns,
			orgID, name,
		).Scan(scanPolicyPipelineDests(&p)...); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("policy name %q already exists in this org: %w", name, err)
			}
			return fmt.Errorf("create policy pipeline: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+policyVersionTable+` (policy_id, org_id, version, yaml, git_sha, label, created_by)
			 VALUES ($1::uuid, $2::uuid, 1, $3, $4, $5, $6)
			 RETURNING `+policyVersionColumns,
			p.ID, orgID, yamlDoc, gitSHA, PolicyLabelDraft, createdBy,
		).Scan(scanPolicyVersionDests(&v)...); err != nil {
			return fmt.Errorf("create policy version: %w", err)
		}
		return nil
	})
	if err != nil {
		return PolicyPipeline{}, PolicyVersion{}, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return p, v, nil
}

// GetPolicy returns the pipeline row; a foreign/missing id is ErrNotFound.
func (s *Store) GetPolicy(ctx context.Context, orgID, policyID string) (PolicyPipeline, error) {
	var p PolicyPipeline
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+policyPipelineColumns+` FROM `+policyPipelineTable+
				` WHERE id = $1::uuid AND org_id = $2::uuid`,
			policyID, orgID,
		).Scan(scanPolicyPipelineDests(&p)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get policy pipeline: %w", err)
		}
		return nil
	})
	if err != nil {
		return PolicyPipeline{}, err
	}
	return p, nil
}

// ListPolicies returns all pipelines of one org, oldest first (stable
// creation order for the dashboard list).
func (s *Store) ListPolicies(ctx context.Context, orgID string) ([]PolicyPipeline, error) {
	var out []PolicyPipeline
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+policyPipelineColumns+` FROM `+policyPipelineTable+
				` WHERE org_id = $1::uuid ORDER BY created_at ASC, id ASC`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list policy pipelines: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p PolicyPipeline
			if err := rows.Scan(scanPolicyPipelineDests(&p)...); err != nil {
				return fmt.Errorf("scan policy pipeline: %w", err)
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoadPolicySnapshot reads all policy inputs from one repeatable-read
// transaction. Isolation is set before the transaction-local RLS GUC and any
// data query, so activation cannot mix pipeline, version, and attachment
// rows from different database snapshots.
func (s *Store) LoadPolicySnapshot(ctx context.Context, orgID string) (PolicyPipelineSnapshot, error) {
	if s.db == nil {
		return PolicyPipelineSnapshot{}, fmt.Errorf("database not available")
	}
	tx, err := s.db.BeginAuditTx(ctx)
	if err != nil {
		return PolicyPipelineSnapshot{}, fmt.Errorf("begin policy snapshot tx: %w", err)
	}
	rollback := func() { _ = tx.Rollback(ctx) }
	if _, err := tx.Exec(ctx, "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"); err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("set policy snapshot isolation: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_org', $1, true)", orgID); err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("set policy snapshot org: %w", err)
	}

	snapshot := PolicyPipelineSnapshot{
		Policies:    make([]PolicyPipeline, 0),
		Versions:    make(map[string]PolicyVersion),
		Attachments: make(map[string][]PolicyAttachment),
		PromptPins:  make(map[string]map[string]PromptPin),
	}
	policies, err := tx.Query(ctx,
		`SELECT `+policyPipelineColumns+` FROM `+policyPipelineTable+
			` WHERE org_id = $1::uuid ORDER BY created_at ASC, id ASC`,
		orgID,
	)
	if err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot list policy pipelines: %w", err)
	}
	for policies.Next() {
		var p PolicyPipeline
		if err := policies.Scan(scanPolicyPipelineDests(&p)...); err != nil {
			policies.Close()
			rollback()
			return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot scan policy pipeline: %w", err)
		}
		snapshot.Policies = append(snapshot.Policies, p)
	}
	if err := policies.Err(); err != nil {
		policies.Close()
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot iterate policy pipelines: %w", err)
	}
	policies.Close()

	versions, err := tx.Query(ctx,
		`SELECT pv.id::text, pv.policy_id::text, pv.org_id::text, pv.version, pv.yaml, pv.git_sha, pv.label, pv.created_by, pv.created_at
		 FROM `+policyVersionTable+` pv
		 JOIN `+policyPipelineTable+` pp ON pp.id = pv.policy_id AND pp.org_id = pv.org_id AND pp.current_version = pv.version
		 WHERE pp.org_id = $1::uuid AND pp.enabled AND pp.current_version > 0
		 ORDER BY pp.created_at ASC, pp.id ASC`, orgID,
	)
	if err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot list active policy versions: %w", err)
	}
	for versions.Next() {
		var v PolicyVersion
		if err := versions.Scan(scanPolicyVersionDests(&v)...); err != nil {
			versions.Close()
			rollback()
			return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot scan active policy version: %w", err)
		}
		snapshot.Versions[v.PolicyID] = v
	}
	if err := versions.Err(); err != nil {
		versions.Close()
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot iterate active policy versions: %w", err)
	}
	versions.Close()

	attachments, err := tx.Query(ctx,
		`SELECT pa.id::text, pa.policy_id::text, pa.org_id::text, COALESCE(pa.key_label, ''), pa.model_pattern, pa.endpoint, pa.priority
		 FROM `+policyAttachmentTable+` pa
		 JOIN `+policyPipelineTable+` pp ON pp.id = pa.policy_id AND pp.org_id = pa.org_id
		 WHERE pp.org_id = $1::uuid
		 ORDER BY pp.created_at ASC, pp.id ASC, pa.priority ASC, pa.id ASC`, orgID,
	)
	if err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot list policy attachments: %w", err)
	}
	for attachments.Next() {
		var a PolicyAttachment
		if err := attachments.Scan(scanPolicyAttachmentDests(&a)...); err != nil {
			attachments.Close()
			rollback()
			return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot scan policy attachment: %w", err)
		}
		snapshot.Attachments[a.PolicyID] = append(snapshot.Attachments[a.PolicyID], a)
	}
	if err := attachments.Err(); err != nil {
		attachments.Close()
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot iterate policy attachments: %w", err)
	}
	attachments.Close()

	pins, err := tx.Query(ctx, `SELECT policy_id::text, policy_version, ref, prompt_version, body FROM policy_prompt_pins WHERE org_id = $1::uuid ORDER BY policy_id, policy_version, ref`, orgID)
	if err != nil {
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot list policy prompt pins: %w", err)
	}
	for pins.Next() {
		var policyID string
		var version int
		var pin PromptPin
		if err := pins.Scan(&policyID, &version, &pin.Ref, &pin.Version, &pin.Body); err != nil {
			pins.Close()
			rollback()
			return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot scan policy prompt pin: %w", err)
		}
		key := fmt.Sprintf("%s@%d", policyID, version)
		if snapshot.PromptPins[key] == nil {
			snapshot.PromptPins[key] = make(map[string]PromptPin)
		}
		snapshot.PromptPins[key][pin.Ref] = pin
	}
	if err := pins.Err(); err != nil {
		pins.Close()
		rollback()
		return PolicyPipelineSnapshot{}, fmt.Errorf("snapshot iterate policy prompt pins: %w", err)
	}
	pins.Close()

	if err := tx.Commit(ctx); err != nil {
		return PolicyPipelineSnapshot{}, fmt.Errorf("commit policy snapshot tx: %w", err)
	}
	return snapshot, nil
}

// SavePolicyPromptPins writes a version's resolved prompt set once. A retry
// can never replace the activated version's pins with a moved label target.
func (s *Store) SavePolicyPromptPins(ctx context.Context, orgID, policyID string, version int, pins map[string]PromptPin) error {
	return s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		for _, pin := range pins {
			_, err := tx.Exec(ctx, `INSERT INTO policy_prompt_pins (org_id, policy_id, policy_version, ref, prompt_version, body) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6) ON CONFLICT (org_id, policy_id, policy_version, ref) DO NOTHING`, orgID, policyID, version, pin.Ref, pin.Version, pin.Body)
			if err != nil {
				return fmt.Errorf("save policy prompt pin: %w", err)
			}
		}
		return nil
	})
}

// UpdatePolicy flips the enabled mode flag. Everything else about a pipeline
// is either immutable (org, name semantics move through create/delete) or
// versioned.
func (s *Store) UpdatePolicy(ctx context.Context, orgID, policyID string, enabled bool) (PolicyPipeline, error) {
	var p PolicyPipeline
	// WHERE pins BOTH id and org: the org-isolation GUC plus the explicit
	// predicate make a cross-org id a clean ErrNotFound.
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		var err error
		p, err = updatePolicyEnabledTx(ctx, tx, orgID, policyID, enabled)
		return err
	})
	if err != nil {
		return PolicyPipeline{}, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return p, nil
}

// updatePolicyEnabledTx is the in-tx core of the enabled flip.
func updatePolicyEnabledTx(ctx context.Context, tx auditTx, orgID, policyID string, enabled bool) (PolicyPipeline, error) {
	var p PolicyPipeline
	err := tx.QueryRow(ctx,
		`UPDATE `+policyPipelineTable+` SET enabled = $3
		 WHERE id = $1::uuid AND org_id = $2::uuid
		 RETURNING `+policyPipelineColumns,
		policyID, orgID, enabled,
	).Scan(scanPolicyPipelineDests(&p)...)
	if err != nil {
		if IsNotFound(err) {
			return PolicyPipeline{}, ErrNotFound
		}
		return PolicyPipeline{}, fmt.Errorf("update policy pipeline: %w", err)
	}
	return p, nil
}

// CreatePolicyVersion appends the next draft version (max+1 per policy,
// enforced by ux_policy_versions_policy_version). A concurrent append that
// loses the race surfaces as a unique-violation error the caller can retry.
func (s *Store) CreatePolicyVersion(ctx context.Context, orgID, policyID, yamlDoc, gitSHA, createdBy string) (PolicyVersion, error) {
	if err := validatePolicyYAMLStored(yamlDoc); err != nil {
		return PolicyVersion{}, err
	}
	var v PolicyVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		var err error
		v, err = createPolicyVersionTx(ctx, tx, orgID, policyID, yamlDoc, gitSHA, createdBy)
		return err
	})
	if err != nil {
		return PolicyVersion{}, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return v, nil
}

// createPolicyVersionTx is the in-tx core of the version append (existence
// probe under the pinned GUC included).
func createPolicyVersionTx(ctx context.Context, tx auditTx, orgID, policyID, yamlDoc, gitSHA, createdBy string) (PolicyVersion, error) {
	// The pipeline must exist IN THIS ORG before appending (the SELECT
	// under the pinned GUC makes a foreign id ErrNotFound).
	if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
		return PolicyVersion{}, err
	}
	var v PolicyVersion
	err := tx.QueryRow(ctx,
		`INSERT INTO `+policyVersionTable+` (policy_id, org_id, version, yaml, git_sha, label, created_by)
		 SELECT $1::uuid, $2::uuid, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6
		 FROM `+policyVersionTable+` WHERE policy_id = $1::uuid
		 RETURNING `+policyVersionColumns,
		policyID, orgID, yamlDoc, gitSHA, PolicyLabelDraft, createdBy,
	).Scan(scanPolicyVersionDests(&v)...)
	if err != nil {
		if isUniqueViolation(err) {
			return PolicyVersion{}, fmt.Errorf("concurrent policy update, retry: %w", err)
		}
		return PolicyVersion{}, fmt.Errorf("create policy version: %w", err)
	}
	return v, nil
}

// ListPolicyVersions returns the pipeline's versions, newest first.
func (s *Store) ListPolicyVersions(ctx context.Context, orgID, policyID string) ([]PolicyVersion, error) {
	var out []PolicyVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+policyVersionColumns+` FROM `+policyVersionTable+
				` WHERE policy_id = $1::uuid AND org_id = $2::uuid ORDER BY version DESC`,
			policyID, orgID,
		)
		if err != nil {
			return fmt.Errorf("list policy versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v PolicyVersion
			if err := rows.Scan(scanPolicyVersionDests(&v)...); err != nil {
				return fmt.Errorf("scan policy version: %w", err)
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetPolicyVersion returns one version of the pipeline.
func (s *Store) GetPolicyVersion(ctx context.Context, orgID, policyID string, version int) (PolicyVersion, error) {
	var v PolicyVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx,
			`SELECT `+policyVersionColumns+` FROM `+policyVersionTable+
				` WHERE policy_id = $1::uuid AND org_id = $2::uuid AND version = $3`,
			policyID, orgID, version,
		).Scan(scanPolicyVersionDests(&v)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get policy version: %w", err)
		}
		return nil
	})
	if err != nil {
		return PolicyVersion{}, err
	}
	return v, nil
}

// SetActivePolicyVersion points current_version at version in one
// transaction: the target must exist, the previously active label demotes to
// draft, the target's label becomes active (canaries untouched), and the
// pipeline row carries the new current_version.
func (s *Store) SetActivePolicyVersion(ctx context.Context, orgID, policyID string, version int) (PolicyPipeline, error) {
	var p PolicyPipeline
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		var err error
		p, err = setActivePolicyVersionTx(ctx, tx, orgID, policyID, version)
		return err
	})
	if err != nil {
		return PolicyPipeline{}, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return p, nil
}

// setActivePolicyVersionTx is the in-tx core of activate/rollback.
func setActivePolicyVersionTx(ctx context.Context, tx auditTx, orgID, policyID string, version int) (PolicyPipeline, error) {
	if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
		return PolicyPipeline{}, err
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM `+policyVersionTable+
			` WHERE policy_id = $1::uuid AND org_id = $2::uuid AND version = $3)`,
		policyID, orgID, version,
	).Scan(&exists); err != nil {
		return PolicyPipeline{}, fmt.Errorf("check policy version: %w", err)
	}
	if !exists {
		return PolicyPipeline{}, ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE `+policyVersionTable+` SET label = $4
		 WHERE policy_id = $1::uuid AND org_id = $2::uuid AND label = $3`,
		policyID, orgID, PolicyLabelActive, PolicyLabelDraft,
	); err != nil {
		return PolicyPipeline{}, fmt.Errorf("demote active policy version: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE `+policyVersionTable+` SET label = $4
		 WHERE policy_id = $1::uuid AND org_id = $2::uuid AND version = $3`,
		policyID, orgID, version, PolicyLabelActive,
	); err != nil {
		return PolicyPipeline{}, fmt.Errorf("activate policy version: %w", err)
	}
	var p PolicyPipeline
	err := tx.QueryRow(ctx,
		`UPDATE `+policyPipelineTable+` SET current_version = $3
		 WHERE id = $1::uuid AND org_id = $2::uuid
		 RETURNING `+policyPipelineColumns,
		policyID, orgID, version,
	).Scan(scanPolicyPipelineDests(&p)...)
	if err != nil {
		return PolicyPipeline{}, fmt.Errorf("set active policy version: %w", err)
	}
	return p, nil
}

// SetPolicyAttachments replaces the pipeline's whole attachment set in one
// transaction (replace-all semantics: the request body is the source of
// truth). KeyLabel "" is stored as SQL NULL (= every key of the org).
func (s *Store) SetPolicyAttachments(ctx context.Context, orgID, policyID string, atts []PolicyAttachment) ([]PolicyAttachment, error) {
	if err := validatePolicyAttachmentsStored(atts); err != nil {
		return nil, err
	}
	var out []PolicyAttachment
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		var err error
		out, err = setPolicyAttachmentsTx(ctx, tx, orgID, policyID, atts)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return out, nil
}

// validatePolicyAttachmentsStored enforces the storage invariants of an
// attachment set (shared by the plain and CAS paths).
func validatePolicyAttachmentsStored(atts []PolicyAttachment) error {
	for i := range atts {
		if atts[i].ModelPattern == "" {
			return fmt.Errorf("attachment model_pattern is required")
		}
		if atts[i].Endpoint == "" {
			return fmt.Errorf("attachment endpoint is required")
		}
		if atts[i].Priority < 0 {
			return fmt.Errorf("attachment priority must be >= 0")
		}
	}
	return nil
}

// setPolicyAttachmentsTx is the in-tx core of the replace-all write.
func setPolicyAttachmentsTx(ctx context.Context, tx auditTx, orgID, policyID string, atts []PolicyAttachment) ([]PolicyAttachment, error) {
	if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM `+policyAttachmentTable+` WHERE policy_id = $1::uuid AND org_id = $2::uuid`,
		policyID, orgID,
	); err != nil {
		return nil, fmt.Errorf("clear policy attachments: %w", err)
	}
	out := make([]PolicyAttachment, 0, len(atts))
	for i := range atts {
		var a PolicyAttachment
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+policyAttachmentTable+` (policy_id, org_id, key_label, model_pattern, endpoint, priority)
			 VALUES ($1::uuid, $2::uuid, NULLIF($3, ''), $4, $5, $6)
			 RETURNING `+policyAttachmentColumns,
			policyID, orgID, atts[i].KeyLabel, atts[i].ModelPattern, atts[i].Endpoint, atts[i].Priority,
		).Scan(scanPolicyAttachmentDests(&a)...); err != nil {
			return nil, fmt.Errorf("create policy attachment: %w", err)
		}
		out = append(out, a)
	}
	return out, nil
}

// ListPolicyAttachments returns the pipeline's attachments, priority first.
func (s *Store) ListPolicyAttachments(ctx context.Context, orgID, policyID string) ([]PolicyAttachment, error) {
	var out []PolicyAttachment
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPolicyTx(ctx, tx, orgID, policyID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+policyAttachmentColumns+` FROM `+policyAttachmentTable+
				` WHERE policy_id = $1::uuid AND org_id = $2::uuid ORDER BY priority ASC, id ASC`,
			policyID, orgID,
		)
		if err != nil {
			return fmt.Errorf("list policy attachments: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var a PolicyAttachment
			if err := rows.Scan(scanPolicyAttachmentDests(&a)...); err != nil {
				return fmt.Errorf("scan policy attachment: %w", err)
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeletePolicy removes the pipeline; versions and attachments cascade
// (FK ON DELETE CASCADE). Deleting a missing/foreign pipeline is ErrNotFound.
func (s *Store) DeletePolicy(ctx context.Context, orgID, policyID string) error {
	var deleted int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+policyPipelineTable+` WHERE id = $1::uuid AND org_id = $2::uuid`,
			policyID, orgID,
		)
		if err != nil {
			return fmt.Errorf("delete policy pipeline: %w", err)
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if deleted == 0 {
		return ErrNotFound
	}
	s.bumpPolicyVersion(ctx, orgID)
	return nil
}

// getPolicyTx is the in-tx existence+visibility probe shared by the
// version/attachment operations: under the pinned GUC a foreign pipeline is
// invisible, so a missing row is ErrNotFound — the cross-org 404 semantics.
func getPolicyTx(ctx context.Context, tx auditTx, orgID, policyID string) (PolicyPipeline, error) {
	var p PolicyPipeline
	err := tx.QueryRow(ctx,
		`SELECT `+policyPipelineColumns+` FROM `+policyPipelineTable+
			` WHERE id = $1::uuid AND org_id = $2::uuid`,
		policyID, orgID,
	).Scan(scanPolicyPipelineDests(&p)...)
	if err != nil {
		if IsNotFound(err) {
			return PolicyPipeline{}, ErrNotFound
		}
		return PolicyPipeline{}, fmt.Errorf("get policy pipeline: %w", err)
	}
	return p, nil
}

// getPolicyTxLocked is getPolicyTx plus SELECT … FOR UPDATE: the row stays
// locked until the surrounding transaction commits, which is what makes the
// UpdatePolicyCAS token comparison race-free (the cas.go "comparison inside
// the same statement" contract, expressed as a lock).
func getPolicyTxLocked(ctx context.Context, tx auditTx, orgID, policyID string) (PolicyPipeline, error) {
	var p PolicyPipeline
	err := tx.QueryRow(ctx,
		`SELECT `+policyPipelineColumns+` FROM `+policyPipelineTable+
			` WHERE id = $1::uuid AND org_id = $2::uuid FOR UPDATE`,
		policyID, orgID,
	).Scan(scanPolicyPipelineDests(&p)...)
	if err != nil {
		if IsNotFound(err) {
			return PolicyPipeline{}, ErrNotFound
		}
		return PolicyPipeline{}, fmt.Errorf("get policy pipeline (locked): %w", err)
	}
	return p, nil
}

// UpdatePolicyCAS applies changes under the optimistic-concurrency token. Semantics:
//
//   - expectVersion nil → unconditional (the legacy field-by-field PUT).
//   - expectVersion non-nil → the pipeline row is locked FOR UPDATE and its
//     current_version (COALESCE'd: NULL reads as 0 = never activated) must
//     equal *expectVersion. A mismatch applies NOTHING and returns
//     ErrPreconditionFailed together with the CURRENT row (for the 409 body
//     the editor rebases on). The token is the pipeline's current_version —
//     the exact state the runtime evaluates — so a concurrent activation is
//     APPENDS do not move current_version by design: versions are immutable
//     append-only rows, and the editor re-reads after every save.
//
// Field application order matches the HTTP handler's: yaml (append a NEW
// draft version) → enabled → active_version → attachments. All fields land
// in ONE transaction; the gateway version key bumps once on success.
func (s *Store) UpdatePolicyCAS(ctx context.Context, orgID, policyID string, upd PolicyUpdate, expectVersion *int, createdBy string) (PolicyPipeline, PolicyVersion, error) {
	if upd.YAML != nil {
		if err := validatePolicyYAMLStored(*upd.YAML); err != nil {
			return PolicyPipeline{}, PolicyVersion{}, err
		}
	}
	if upd.Attachments != nil {
		if err := validatePolicyAttachmentsStored(*upd.Attachments); err != nil {
			return PolicyPipeline{}, PolicyVersion{}, err
		}
	}
	var p PolicyPipeline
	var appended PolicyVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		var err error
		p, err = getPolicyTxLocked(ctx, tx, orgID, policyID)
		if err != nil {
			return err
		}
		if expectVersion != nil && p.CurrentVersion != *expectVersion {
			// Precondition mismatch: report the live row, apply nothing.
			return ErrPreconditionFailed
		}
		if upd.YAML != nil {
			gitSHA := ""
			if upd.GitSHA != nil {
				gitSHA = *upd.GitSHA
			}
			appended, err = createPolicyVersionTx(ctx, tx, orgID, policyID, *upd.YAML, gitSHA, createdBy)
			if err != nil {
				return err
			}
		}
		if upd.Enabled != nil && *upd.Enabled != p.Enabled {
			p, err = updatePolicyEnabledTx(ctx, tx, orgID, policyID, *upd.Enabled)
			if err != nil {
				return err
			}
		}
		if upd.ActiveVersion != nil {
			p, err = setActivePolicyVersionTx(ctx, tx, orgID, policyID, *upd.ActiveVersion)
			if err != nil {
				return err
			}
		}
		if upd.Attachments != nil {
			if _, err = setPolicyAttachmentsTx(ctx, tx, orgID, policyID, *upd.Attachments); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrPreconditionFailed) {
			return p, PolicyVersion{}, err
		}
		return PolicyPipeline{}, PolicyVersion{}, err
	}
	s.bumpPolicyVersion(ctx, orgID)
	return p, appended, nil
}

func scanPolicyPipelineDests(p *PolicyPipeline) []any {
	return []any{
		&p.ID, &p.OrgID, &p.Name, &p.Enabled, &p.CurrentVersion, &p.CreatedAt, &p.UpdatedAt,
	}
}

func scanPolicyVersionDests(v *PolicyVersion) []any {
	return []any{
		&v.ID, &v.PolicyID, &v.OrgID, &v.Version, &v.YAML, &v.GitSHA, &v.Label, &v.CreatedBy, &v.CreatedAt,
	}
}

func scanPolicyAttachmentDests(a *PolicyAttachment) []any {
	return []any{
		&a.ID, &a.PolicyID, &a.OrgID, &a.KeyLabel, &a.ModelPattern, &a.Endpoint, &a.Priority,
	}
}
