package adminstore

// prompts, named label bindings (draft|active|canary|custom) and partials,
// backed by migration 0010 (RLS posture identical to 0008/0009).
//
// Concurrency/RLS contract (policystore.go / orgcredentials.go parity):
//   - every operation runs inside withPolicyTx: one transaction with the
//     app.current_org GUC pinned to the org — the org_isolation contract of
//     the prompts/prompt_versions/prompt_labels/partials RLS policies
//     (migration 0010, ENABLE+FORCE). Without the GUC the FORCE policy denies
//     every row (fail-closed); a cross-org resource id therefore reads as
//     ErrNotFound, never as a leak.
//   - versions are immutable: an edit APPENDS the next version (max+1 per
//     prompt, enforced by ux_prompt_versions_prompt_version); a concurrent
//     append that loses the race surfaces as a unique-violation error.
//   - labels are movable pointers (UNIQUE (prompt_id, label), composite FK
//     into prompt_versions): promote = upsert, and a label can never point
//     at a version that does not exist.
//
// CONSUMERS (this file also ships the two provider seams other lanes coded
// against):
//   - RenderTemplate: the pure single-pass renderer for prompt templates
//     ({{var}} + {{partials.name}}; missing names are render errors).
//   - Store.PartialsLookup(orgID): satisfies the OP-5 builtins.PartialsSource
//     seam structurally (pkg/pipeline/builtins/mutate_partials.go) — the
//     gateway passes it as the step's "source" param at wiring time.
//   - Store.JudgePromptSource(orgID): satisfies the OP-3 llmjudge.PromptSource
//     seam (pkg/pipeline/llmjudge/prompt.go); refs "org:<name>@<label>" resolve
//     through the label bindings, everything else delegates to the embedded
//     judges. The llmjudge import is one-directional (storage → judge lib);
//     no pipeline package imports adminstore, so no cycle exists.
//
// is the resolution the label→key/canary binding (OP-2 wave/glue) will call
// to render prompt refs at request time.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/reireirei/yabanin/pkg/pipeline/llmjudge"
)

// Prompt label names (prompt_labels.label).
const (
	PromptLabelDraft  = "draft"
	PromptLabelActive = "active"
	PromptLabelCanary = "canary"
	PromptLabelCustom = "custom"
)

// promptLabels is the closed label set (mirrors the 0010 CHECK constraint).
var promptLabels = map[string]bool{
	PromptLabelDraft: true, PromptLabelActive: true, PromptLabelCanary: true, PromptLabelCustom: true,
}

// OrgPromptRefPrefix marks an org prompt reference inside a policy
// prompt_ref ("org:<name>@<label>"). Everything else keeps the embedded
// "judges/<name>@<version>" grammar (OP-3).
const OrgPromptRefPrefix = "org:"

// Prompt is one org-scoped named prompt (migration 0010).
type Prompt struct {
	ID string `json:"id"`
	// OrgID is immutable: prompts never move between orgs.
	OrgID string `json:"org_id"`
	// Name is ref-safe ([A-Za-z0-9_.-]+): it is the <name> part of the
	// "org:<name>@<label>" prompt_ref grammar.
	Name string `json:"name"`
	// Description is free display metadata for the library UI.
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// PromptVersion is one immutable template version of a prompt.
type PromptVersion struct {
	ID       string `json:"id"`
	PromptID string `json:"prompt_id"`
	OrgID    string `json:"org_id"`
	Version  int    `json:"version"`
	// Template is the raw text with {{var}} / {{partials.name}} placeholders
	// (rendered by RenderTemplate, never by SQL).
	Template string `json:"template"`
	// Params is the raw JSON object carried next to the template
	// (model/temperature/max_tokens/...). Opaque to this store beyond the
	// object check — the caller (UI playground, gateway modifier) owns the
	// schema.
	Params    json.RawMessage `json:"params"`
	CreatedBy string          `json:"created_by"`
	CreatedAt time.Time       `json:"created_at"`
}

// PromptLabel binds one label of a prompt to one of its versions.
type PromptLabel struct {
	PromptID  string    `json:"prompt_id"`
	OrgID     string    `json:"org_id"`
	Label     string    `json:"label"` // draft | active | canary | custom
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Partial is one org-scoped named partial body. Each version is append-only.
type Partial struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	Body      string    `json:"body"`
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// later the gateway render seam (the HTTP layer pins the narrow capability —
// services/admin/handlers/prompt_studio.go).

const promptTable = `prompts`
const promptVersionTable = `prompt_versions`
const promptLabelTable = `prompt_labels`
const partialTable = `partials`

// promptColumns is the canonical SELECT list for prompt reads.
const promptColumns = `id::text, org_id::text, name, description, created_at, updated_at`

// promptVersionColumns is the canonical SELECT list for version reads
// (template included: prompt content is admin-authored configuration, not
// secret material — the version endpoints must render it back verbatim).
const promptVersionColumns = `id::text, prompt_id::text, org_id::text, version, template, params, created_by, created_at`

// promptLabelColumns is the canonical SELECT list for label reads.
const promptLabelColumns = `prompt_id::text, org_id::text, label, version, updated_at`

// partialColumns is the canonical SELECT list for partial reads (body
// included: partials are prompt building blocks, not secret material).
const partialColumns = `id::text, org_id::text, name, body, version, created_at, updated_at`

// promptNameRe is the ref-safe name grammar shared by prompts and partials:
// the exact charset the {{partials.NAME}} token regex and the
// "org:<name>@<label>" ref parser accept, so every stored name is
// referenceable from a template or a policy.
var promptNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// maxPromptParamsBytes bounds one params document (a DoS bound; the handler
// body cap is the outer limit).
const maxPromptParamsBytes = 16 << 10

// maxPartialBodyBytes bounds one partial body. MUST stay in sync with
// builtins.maxPartialBytes (64KB): a partial the substitution step would
// refuse must never be storable.
const maxPartialBodyBytes = 64 << 10

// validatePromptName applies the ref-safe name grammar (1..256 chars,
// [A-Za-z0-9_.-]+ — no '@', no whitespace, so prompt_ref parsing stays
// unambiguous).
func validatePromptName(name string) error {
	if name == "" || len(name) > 256 {
		return fmt.Errorf("name must be 1 to 256 characters")
	}
	if !promptNameRe.MatchString(name) {
		return fmt.Errorf("name must match [A-Za-z0-9_.-]+ (it is the prompt_ref / partials token key)")
	}
	return nil
}

// validatePromptTemplateStored rejects the degenerate empty write the CHECK
// constraint would reject anyway (deeper validation is the renderer's job).
func validatePromptTemplateStored(template string) error {
	if template == "" {
		return fmt.Errorf("template is required")
	}
	return nil
}

// validatePromptParamsStored requires params to be a JSON object (the shape
// the CHECK constraint enforces for out-of-band writers too).
func validatePromptParamsStored(params json.RawMessage) error {
	if len(params) == 0 {
		return nil // stored as '{}'
	}
	if len(params) > maxPromptParamsBytes {
		return fmt.Errorf("params must be at most %d bytes", maxPromptParamsBytes)
	}
	var obj map[string]any
	if err := json.Unmarshal(params, &obj); err != nil || obj == nil {
		return fmt.Errorf("params must be a JSON object")
	}
	return nil
}

// validatePromptLabel applies the closed label set.
func validatePromptLabel(label string) error {
	if !promptLabels[label] {
		return fmt.Errorf("label must be one of draft|active|canary|custom")
	}
	return nil
}

// validatePartialName applies the same ref-safe grammar as prompt names
// (partials are referenced from templates by this exact key).
func validatePartialName(name string) error {
	return validatePromptName(name)
}

// validatePartialBodyStored rejects the degenerate write and enforces the
// substitution-step size bound.
func validatePartialBodyStored(body string) error {
	if body == "" {
		return fmt.Errorf("body is required")
	}
	if len(body) > maxPartialBodyBytes {
		return fmt.Errorf("body must be at most %d bytes", maxPartialBodyBytes)
	}
	return nil
}

// CreatePrompt creates the prompt, its FIRST version (v1) and the initial
// draft binding in one transaction.
func (s *Store) CreatePrompt(ctx context.Context, orgID, name, description, template string, params json.RawMessage, createdBy string) (Prompt, PromptVersion, error) {
	if orgID == "" {
		return Prompt{}, PromptVersion{}, fmt.Errorf("org id is required")
	}
	if err := validatePromptName(name); err != nil {
		return Prompt{}, PromptVersion{}, err
	}
	if len(description) > 1024 {
		return Prompt{}, PromptVersion{}, fmt.Errorf("description must be at most 1024 characters")
	}
	if err := validatePromptTemplateStored(template); err != nil {
		return Prompt{}, PromptVersion{}, err
	}
	if err := validatePromptParamsStored(params); err != nil {
		return Prompt{}, PromptVersion{}, err
	}

	var p Prompt
	var v PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+promptTable+` (org_id, name, description) VALUES ($1::uuid, $2, $3)
			 RETURNING `+promptColumns,
			orgID, name, description,
		).Scan(scanPromptDests(&p)...); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("prompt name %q already exists in this org: %w", name, err)
			}
			return fmt.Errorf("create prompt: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`INSERT INTO `+promptVersionTable+` (prompt_id, org_id, version, template, params, created_by)
			 VALUES ($1::uuid, $2::uuid, 1, $3, $4::jsonb, $5)
			 RETURNING `+promptVersionColumns,
			p.ID, orgID, template, paramsJSON(params), createdBy,
		).Scan(scanPromptVersionDests(&v)...); err != nil {
			return fmt.Errorf("create prompt version: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO `+promptLabelTable+` (prompt_id, org_id, label, version)
			 VALUES ($1::uuid, $2::uuid, $3, $4)`,
			p.ID, orgID, PromptLabelDraft, v.Version,
		); err != nil {
			return fmt.Errorf("bind draft label: %w", err)
		}
		return nil
	})
	if err != nil {
		return Prompt{}, PromptVersion{}, err
	}
	return p, v, nil
}

// GetPrompt returns the prompt row; a foreign/missing id is ErrNotFound.
func (s *Store) GetPrompt(ctx context.Context, orgID, promptID string) (Prompt, error) {
	var p Prompt
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+promptColumns+` FROM `+promptTable+
				` WHERE id = $1::uuid AND org_id = $2::uuid`,
			promptID, orgID,
		).Scan(scanPromptDests(&p)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get prompt: %w", err)
		}
		return nil
	})
	if err != nil {
		return Prompt{}, err
	}
	return p, nil
}

// ListPrompts returns all prompts of one org, oldest first (stable creation
// order for the library list; use GetPrompt for versions and labels).
func (s *Store) ListPrompts(ctx context.Context, orgID string) ([]Prompt, error) {
	var out []Prompt
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+promptColumns+` FROM `+promptTable+
				` WHERE org_id = $1::uuid ORDER BY created_at ASC, id ASC`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list prompts: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p Prompt
			if err := rows.Scan(scanPromptDests(&p)...); err != nil {
				return fmt.Errorf("scan prompt: %w", err)
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

// UpdatePrompt appends the NEXT version (max+1 per prompt) and moves the
// draft label to it in one transaction — draft always follows the latest
// saved version; active/canary/custom labels only move through PromoteLabel.
// A concurrent append that loses the race surfaces as a unique-violation
// error the caller can retry.
func (s *Store) UpdatePrompt(ctx context.Context, orgID, promptID, template string, params json.RawMessage, createdBy string, expectedVersion int) (PromptVersion, error) {
	if err := validatePromptTemplateStored(template); err != nil {
		return PromptVersion{}, err
	}
	if err := validatePromptParamsStored(params); err != nil {
		return PromptVersion{}, err
	}
	var v PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		// The prompt must exist IN THIS ORG before appending (the SELECT
		// under the pinned GUC makes a foreign id ErrNotFound).
		if _, err := getPromptTx(ctx, tx, orgID, promptID); err != nil {
			return err
		}
		var current int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM `+promptVersionTable+` WHERE prompt_id = $1::uuid AND org_id = $2::uuid`, promptID, orgID).Scan(&current); err != nil {
			return fmt.Errorf("read current prompt version: %w", err)
		}
		if expectedVersion != current {
			return ErrPreconditionFailed
		}
		err := tx.QueryRow(ctx,
			`INSERT INTO `+promptVersionTable+` (prompt_id, org_id, version, template, params, created_by)
			 SELECT $1::uuid, $2::uuid, COALESCE(MAX(version), 0) + 1, $3, $4::jsonb, $5
			 FROM `+promptVersionTable+` WHERE prompt_id = $1::uuid
			 RETURNING `+promptVersionColumns,
			promptID, orgID, template, paramsJSON(params), createdBy,
		).Scan(scanPromptVersionDests(&v)...)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrPreconditionFailed
			}
			return fmt.Errorf("create prompt version: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO `+promptLabelTable+` (prompt_id, org_id, label, version)
			 VALUES ($1::uuid, $2::uuid, $3, $4)
			 ON CONFLICT (prompt_id, label) DO UPDATE SET version = EXCLUDED.version`,
			promptID, orgID, PromptLabelDraft, v.Version,
		); err != nil {
			return fmt.Errorf("move draft label: %w", err)
		}
		return nil
	})
	if err != nil {
		return PromptVersion{}, err
	}
	return v, nil
}

// PromoteLabel points label at version (upsert: the previous binding of the
// same label moves; other labels are untouched). The version must belong to
// the prompt; a foreign prompt/version is ErrNotFound.
func (s *Store) PromoteLabel(ctx context.Context, orgID, promptID, label string, version int) (PromptLabel, error) {
	if err := validatePromptLabel(label); err != nil {
		return PromptLabel{}, err
	}
	if version < 1 {
		return PromptLabel{}, fmt.Errorf("version must be >= 1")
	}
	var l PromptLabel
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPromptTx(ctx, tx, orgID, promptID); err != nil {
			return err
		}
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM `+promptVersionTable+
				` WHERE prompt_id = $1::uuid AND org_id = $2::uuid AND version = $3)`,
			promptID, orgID, version,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check prompt version: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
		err := tx.QueryRow(ctx,
			`INSERT INTO `+promptLabelTable+` (prompt_id, org_id, label, version)
			 VALUES ($1::uuid, $2::uuid, $3, $4)
			 ON CONFLICT (prompt_id, label) DO UPDATE SET version = EXCLUDED.version
			 RETURNING `+promptLabelColumns,
			promptID, orgID, label, version,
		).Scan(scanPromptLabelDests(&l)...)
		if err != nil {
			return fmt.Errorf("promote prompt label: %w", err)
		}
		return nil
	})
	if err != nil {
		return PromptLabel{}, err
	}
	return l, nil
}

// ListPromptLabels returns the prompt's label bindings (draft|active|canary|
// custom — at most one row per label).
func (s *Store) ListPromptLabels(ctx context.Context, orgID, promptID string) ([]PromptLabel, error) {
	var out []PromptLabel
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPromptTx(ctx, tx, orgID, promptID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+promptLabelColumns+` FROM `+promptLabelTable+
				` WHERE prompt_id = $1::uuid AND org_id = $2::uuid ORDER BY label ASC`,
			promptID, orgID,
		)
		if err != nil {
			return fmt.Errorf("list prompt labels: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var l PromptLabel
			if err := rows.Scan(scanPromptLabelDests(&l)...); err != nil {
				return fmt.Errorf("scan prompt label: %w", err)
			}
			out = append(out, l)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListPromptVersions returns the prompt's versions, newest first.
func (s *Store) ListPromptVersions(ctx context.Context, orgID, promptID string) ([]PromptVersion, error) {
	var out []PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPromptTx(ctx, tx, orgID, promptID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx,
			`SELECT `+promptVersionColumns+` FROM `+promptVersionTable+
				` WHERE prompt_id = $1::uuid AND org_id = $2::uuid ORDER BY version DESC`,
			promptID, orgID,
		)
		if err != nil {
			return fmt.Errorf("list prompt versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v PromptVersion
			if err := rows.Scan(scanPromptVersionDests(&v)...); err != nil {
				return fmt.Errorf("scan prompt version: %w", err)
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

// GetPromptVersion returns one version of the prompt.
func (s *Store) GetPromptVersion(ctx context.Context, orgID, promptID string, version int) (PromptVersion, error) {
	var v PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		if _, err := getPromptTx(ctx, tx, orgID, promptID); err != nil {
			return err
		}
		err := tx.QueryRow(ctx,
			`SELECT `+promptVersionColumns+` FROM `+promptVersionTable+
				` WHERE prompt_id = $1::uuid AND org_id = $2::uuid AND version = $3`,
			promptID, orgID, version,
		).Scan(scanPromptVersionDests(&v)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get prompt version: %w", err)
		}
		return nil
	})
	if err != nil {
		return PromptVersion{}, err
	}
	return v, nil
}

// GetActiveByLabel resolves a prompt BY NAME and label to its bound version:
// the gateway render seam (label→key/canary binding, OP-2 wave/glue) and the
// judge prompt source (org:<name>@<label>) both resolve through this. A
// missing prompt, label or binding is ErrNotFound.
func (s *Store) GetActiveByLabel(ctx context.Context, orgID, promptName, label string) (PromptVersion, error) {
	if err := validatePromptLabel(label); err != nil {
		return PromptVersion{}, err
	}
	var v PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		// The join spans three tables that all have an id column, so the
		// SELECT list is qualified (promptVersionColumns is unqualified and
		// shared with the single-table reads).
		err := tx.QueryRow(ctx,
			`SELECT v.id::text, v.prompt_id::text, v.org_id::text, v.version, v.template, v.params, v.created_by, v.created_at
			 FROM `+promptVersionTable+` v
			 JOIN `+promptLabelTable+` l ON l.prompt_id = v.prompt_id AND l.version = v.version
			 JOIN `+promptTable+` p ON p.id = v.prompt_id
			 WHERE v.org_id = $1::uuid AND p.name = $2 AND l.label = $3`,
			orgID, promptName, label,
		).Scan(scanPromptVersionDests(&v)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("resolve prompt by label: %w", err)
		}
		return nil
	})
	if err != nil {
		return PromptVersion{}, err
	}
	return v, nil
}

// GetPromptVersionByName resolves one immutable prompt version by name within
// an organization. A foreign or missing name/version is ErrNotFound.
func (s *Store) GetPromptVersionByName(ctx context.Context, orgID, promptName string, version int) (PromptVersion, error) {
	if version < 1 {
		return PromptVersion{}, ErrNotFound
	}
	var v PromptVersion
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx, `SELECT v.id::text, v.prompt_id::text, v.org_id::text, v.version, v.template, v.params, v.created_by, v.created_at FROM `+promptVersionTable+` v JOIN `+promptTable+` p ON p.id = v.prompt_id WHERE v.org_id = $1::uuid AND p.name = $2 AND v.version = $3`, orgID, promptName, version).Scan(scanPromptVersionDests(&v)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("resolve immutable prompt version: %w", err)
		}
		return nil
	})
	if err != nil {
		return PromptVersion{}, err
	}
	return v, nil
}

// DeletePrompt removes the prompt; versions and labels cascade
// (FK ON DELETE CASCADE). Deleting a missing/foreign prompt is ErrNotFound.
func (s *Store) DeletePrompt(ctx context.Context, orgID, promptID string) error {
	var deleted int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+promptTable+` WHERE id = $1::uuid AND org_id = $2::uuid`,
			promptID, orgID,
		)
		if err != nil {
			return fmt.Errorf("delete prompt: %w", err)
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
	return nil
}

// CreatePartial stores a new named partial (duplicate name in the org is a
// unique-violation error the caller maps to 409).
func (s *Store) CreatePartial(ctx context.Context, orgID, name, body string) (Partial, error) {
	if orgID == "" {
		return Partial{}, fmt.Errorf("org id is required")
	}
	if err := validatePartialName(name); err != nil {
		return Partial{}, err
	}
	if err := validatePartialBodyStored(body); err != nil {
		return Partial{}, err
	}
	var p Partial
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO `+partialTable+` (org_id, name, body) VALUES ($1::uuid, $2, $3)
			 RETURNING `+partialColumns,
			orgID, name, body,
		).Scan(scanPartialDests(&p)...)
		if err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("partial name %q already exists in this org: %w", name, err)
			}
			return fmt.Errorf("create partial: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO partial_versions (org_id, partial_id, version, body) VALUES ($1::uuid, $2::uuid, $3, $4)`, orgID, p.ID, p.Version, p.Body); err != nil {
			return fmt.Errorf("create partial version: %w", err)
		}
		return nil
	})
	if err != nil {
		return Partial{}, err
	}
	return p, nil
}

// UpdatePartial replaces the body of an existing partial and bumps its
// version. A missing/foreign name is ErrNotFound.
func (s *Store) UpdatePartial(ctx context.Context, orgID, name, body string, expectedVersion int) (Partial, error) {
	if err := validatePartialBodyStored(body); err != nil {
		return Partial{}, err
	}
	var p Partial
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`UPDATE `+partialTable+` SET body = $3, version = version + 1
			 WHERE org_id = $1::uuid AND name = $2 AND version = $4
			 RETURNING `+partialColumns,
			orgID, name, body, expectedVersion,
		).Scan(scanPartialDests(&p)...)
		if err != nil {
			if IsNotFound(err) {
				var exists bool
				if checkErr := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+partialTable+` WHERE org_id = $1::uuid AND name = $2)`, orgID, name).Scan(&exists); checkErr != nil {
					return fmt.Errorf("check partial version: %w", checkErr)
				}
				if exists {
					return ErrPreconditionFailed
				}
				return ErrNotFound
			}
			return fmt.Errorf("update partial: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO partial_versions (org_id, partial_id, version, body) VALUES ($1::uuid, $2::uuid, $3, $4)`, orgID, p.ID, p.Version, p.Body); err != nil {
			return fmt.Errorf("append partial version: %w", err)
		}
		return nil
	})
	if err != nil {
		return Partial{}, err
	}
	return p, nil
}

// SetPartial is the idempotent upsert (create, or bump version on conflict):
// the convenience write for seeding and glue paths; the HTTP surface uses
// CreatePartial/UpdatePartial for crisp 409/404 semantics.
func (s *Store) SetPartial(ctx context.Context, orgID, name, body string) (Partial, error) {
	if orgID == "" {
		return Partial{}, fmt.Errorf("org id is required")
	}
	if err := validatePartialName(name); err != nil {
		return Partial{}, err
	}
	if err := validatePartialBodyStored(body); err != nil {
		return Partial{}, err
	}
	var p Partial
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`INSERT INTO `+partialTable+` (org_id, name, body) VALUES ($1::uuid, $2, $3)
			 ON CONFLICT (org_id, name) DO UPDATE SET body = EXCLUDED.body, version = `+partialTable+`.version + 1
			 RETURNING `+partialColumns,
			orgID, name, body,
		).Scan(scanPartialDests(&p)...)
		if err != nil {
			return fmt.Errorf("upsert partial: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO partial_versions (org_id, partial_id, version, body) VALUES ($1::uuid, $2::uuid, $3, $4) ON CONFLICT (partial_id, version) DO NOTHING`, orgID, p.ID, p.Version, p.Body); err != nil {
			return fmt.Errorf("append partial version: %w", err)
		}
		return nil
	})
	if err != nil {
		return Partial{}, err
	}
	return p, nil
}

// GetPartial returns one partial by name; a foreign/missing name is
// ErrNotFound.
func (s *Store) GetPartial(ctx context.Context, orgID, name string) (Partial, error) {
	var p Partial
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		err := tx.QueryRow(ctx,
			`SELECT `+partialColumns+` FROM `+partialTable+
				` WHERE org_id = $1::uuid AND name = $2`,
			orgID, name,
		).Scan(scanPartialDests(&p)...)
		if err != nil {
			if IsNotFound(err) {
				return ErrNotFound
			}
			return fmt.Errorf("get partial: %w", err)
		}
		return nil
	})
	if err != nil {
		return Partial{}, err
	}
	return p, nil
}

// ListPartials returns all partials of one org, name-ordered (stable list
// for the library UI).
func (s *Store) ListPartials(ctx context.Context, orgID string) ([]Partial, error) {
	var out []Partial
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+partialColumns+` FROM `+partialTable+
				` WHERE org_id = $1::uuid ORDER BY name ASC`,
			orgID,
		)
		if err != nil {
			return fmt.Errorf("list partials: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p Partial
			if err := rows.Scan(scanPartialDests(&p)...); err != nil {
				return fmt.Errorf("scan partial: %w", err)
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

// DeletePartial removes the partial by name. Deleting a missing/foreign
// partial is ErrNotFound.
func (s *Store) DeletePartial(ctx context.Context, orgID, name string) error {
	var deleted int64
	err := s.withPolicyTx(ctx, orgID, func(tx auditTx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM `+partialTable+` WHERE org_id = $1::uuid AND name = $2`,
			orgID, name,
		)
		if err != nil {
			return fmt.Errorf("delete partial: %w", err)
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
	return nil
}

// getPromptTx is the in-tx existence+visibility probe shared by the
// version/label operations: under the pinned GUC a foreign prompt is
// invisible, so a missing row is ErrNotFound — the cross-org 404 semantics.
func getPromptTx(ctx context.Context, tx auditTx, orgID, promptID string) (Prompt, error) {
	var p Prompt
	err := tx.QueryRow(ctx,
		`SELECT `+promptColumns+` FROM `+promptTable+
			` WHERE id = $1::uuid AND org_id = $2::uuid`,
		promptID, orgID,
	).Scan(scanPromptDests(&p)...)
	if err != nil {
		if IsNotFound(err) {
			return Prompt{}, ErrNotFound
		}
		return Prompt{}, fmt.Errorf("get prompt: %w", err)
	}
	return p, nil
}

// paramsJSON normalizes an empty params document to '{}' (the default the
// column carries; pgx encodes a nil []byte as NULL, which the jsonb NOT NULL
// column would reject).
func paramsJSON(params json.RawMessage) string {
	if len(params) == 0 {
		return "{}"
	}
	return string(params)
}

func scanPromptDests(p *Prompt) []any {
	return []any{&p.ID, &p.OrgID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt}
}

func scanPromptVersionDests(v *PromptVersion) []any {
	return []any{&v.ID, &v.PromptID, &v.OrgID, &v.Version, &v.Template, &v.Params, &v.CreatedBy, &v.CreatedAt}
}

func scanPromptLabelDests(l *PromptLabel) []any {
	return []any{&l.PromptID, &l.OrgID, &l.Label, &l.Version, &l.UpdatedAt}
}

func scanPartialDests(p *Partial) []any {
	return []any{&p.ID, &p.OrgID, &p.Name, &p.Body, &p.Version, &p.CreatedAt, &p.UpdatedAt}
}

// ─── Render (pure; no SQL) ──────────────────────────────────────────────

// PartialsSource is the adminstore-side twin of the OP-5 seam
// (pkg/pipeline/builtins.PartialsSource): identical method set, so values of
// either interface type are mutually assignable without either package
// importing the other. found=false means the partial does not exist; err
// aborts the render.
type PartialsSource interface {
	Get(ctx context.Context, name string) (body string, found bool, err error)
}

// templateTokenRe matches the two placeholder grammars of a prompt template
// in one scan (partials alternative FIRST — the bare-name group would
// otherwise swallow the "partials.x" key):
//
//	{{ partials.NAME }}  → partial lookup (group 1)
//	{{ NAME }}           → variable lookup (group 2)
//
// NAME is [A-Za-z0-9_.-]+ — the same grammar the store enforces on partial
// names. The "partials." namespace is reserved (a partials-prefixed VARIABLE
// is unreachable; a malformed "{{partials.}}" stays verbatim — see the
// RenderTemplate loop). Other malformed braces (e.g. "{{a b}}") match
// nothing and stay verbatim, like the builtins substitution step.
var templateTokenRe = regexp.MustCompile(`\{\{\s*(?:partials\.([A-Za-z0-9_.-]+(?:@[1-9][0-9]*)?)|([A-Za-z0-9_.-]+))\s*\}\}`)

// partialsTokenPrefix is the reserved token namespace of partial references.
const partialsTokenPrefix = "partials."

// RenderTemplate renders variables and recursively expands partials. Partial
// references may pin an immutable version as {{partials.name@2}}.
//
// Errors (fail-closed — a half-rendered prompt must never reach a model):
//   - a {{var}} token whose name is absent from vars;
//   - a {{partials.name}} token when partials is nil, or when the lookup
//     reports found=false, or when the lookup fails (err);
//   - ctx cancellation / lookup errors surface unchanged.
//
// The function is deterministic and safe for concurrent use; it performs no
// I/O beyond the partials lookups it is given.
func RenderTemplate(ctx context.Context, template string, vars map[string]string, partials PartialsSource) (string, error) {
	return renderTemplate(ctx, template, vars, partials, nil, 0)
}

const maxPartialExpansionDepth = 8

func renderTemplate(ctx context.Context, template string, vars map[string]string, partials PartialsSource, stack []string, depth int) (string, error) {
	if depth > maxPartialExpansionDepth {
		return "", fmt.Errorf("render template: partial expansion depth exceeds %d at %s", maxPartialExpansionDepth, strings.Join(stack, " -> "))
	}
	locs := templateTokenRe.FindAllStringSubmatchIndex(template, -1)
	if len(locs) == 0 {
		return template, nil
	}
	var sb strings.Builder
	pos := 0
	for _, loc := range locs {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var (
			replacement string
			verbatim    bool
			err         error
		)
		if loc[2] >= 0 {
			name := template[loc[2]:loc[3]]
			base := name
			if at := strings.LastIndexByte(name, '@'); at >= 0 {
				base = name[:at]
			}
			if slices.Contains(stack, base) {
				return "", fmt.Errorf("render template: partial cycle: %s", strings.Join(append(append([]string(nil), stack...), base), " -> "))
			}
			var body string
			body, err = renderPartial(ctx, name, partials)
			if err == nil {
				replacement, err = renderTemplate(ctx, body, vars, partials, append(append([]string(nil), stack...), base), depth+1)
			}
		} else {
			name := template[loc[4]:loc[5]]
			if strings.HasPrefix(name, partialsTokenPrefix) {
				// The partials alternative failed, so this is a malformed
				// partial token ("{{partials.}}") the bare-name group caught
				// mid-braces — leave it verbatim, exactly like the builtins
				// substitution step (its regex never matches those either).
				// The "partials." namespace is reserved: a VARIABLE with
				// that prefix is unreachable from templates.
				verbatim = true
			} else {
				v, ok := vars[name]
				if !ok {
					return "", fmt.Errorf("render template: variable %q is not set", name)
				}
				replacement = v
			}
		}
		if err != nil {
			return "", err
		}
		if verbatim {
			continue
		}
		sb.WriteString(template[pos:loc[0]])
		sb.WriteString(replacement)
		pos = loc[1]
	}
	sb.WriteString(template[pos:])
	return sb.String(), nil
}

// renderPartial resolves one {{partials.name}} token body.
func renderPartial(ctx context.Context, name string, partials PartialsSource) (string, error) {
	if partials == nil {
		return "", fmt.Errorf("render template: partial %q: no partials source wired", name)
	}
	body, found, err := partials.Get(ctx, name)
	if err != nil {
		return "", fmt.Errorf("render template: partial %q: %w", name, err)
	}
	if !found {
		return "", fmt.Errorf("render template: partial %q: not found", name)
	}
	return body, nil
}

// PartialsLookup returns the store-backed PartialsSource for one org (the
// RenderTemplate). It reads the partials table under the org GUC on every
// Get: goroutine-safe (no mutable state), always-current, and bounded by the
// step's own size limit. Wire it as the step's "source" param at gateway
// wiring time:
//
//	builtins.NewPartialsSubstitute(map[string]any{"source": store.PartialsLookup(orgID)})
//
// A missing partial reports found=false (the step's on_missing param then
// decides skip vs error) — RenderTemplate treats found=false as a hard error.
func (s *Store) PartialsLookup(orgID string) PartialsSource {
	return partialsLookup{store: s, orgID: orgID}
}

type partialsLookup struct {
	store *Store
	orgID string
}

// Get resolves one partial name for the bound org (PartialsSource contract).
func (l partialsLookup) Get(ctx context.Context, name string) (string, bool, error) {
	return l.expand(ctx, name, nil, 0)
}

var partialReferenceRe = regexp.MustCompile(`\{\{\s*partials\.([A-Za-z0-9_.-]+(?:@[1-9][0-9]*)?)\s*\}\}`)

func (l partialsLookup) expand(ctx context.Context, name string, stack []string, depth int) (string, bool, error) {
	base := name
	if at := strings.LastIndexByte(base, '@'); at >= 0 {
		base = base[:at]
	}
	if slices.Contains(stack, base) {
		return "", false, fmt.Errorf("partial cycle: %s", strings.Join(append(append([]string(nil), stack...), base), " -> "))
	}
	if depth > maxPartialExpansionDepth {
		return "", false, fmt.Errorf("partial expansion depth exceeds %d at %s", maxPartialExpansionDepth, strings.Join(stack, " -> "))
	}
	body, found, err := l.get(ctx, name)
	if err != nil || !found {
		return body, found, err
	}
	locs := partialReferenceRe.FindAllStringSubmatchIndex(body, -1)
	if len(locs) == 0 {
		return body, true, nil
	}
	var out strings.Builder
	pos := 0
	for _, loc := range locs {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		child := body[loc[2]:loc[3]]
		expanded, childFound, err := l.expand(ctx, child, append(append([]string(nil), stack...), base), depth+1)
		if err != nil {
			return "", false, err
		}
		if !childFound {
			return "", false, fmt.Errorf("partial %q: not found", child)
		}
		out.WriteString(body[pos:loc[0]])
		out.WriteString(expanded)
		pos = loc[1]
	}
	out.WriteString(body[pos:])
	return out.String(), true, nil
}

func (l partialsLookup) get(ctx context.Context, name string) (string, bool, error) {
	base, version, pinned := strings.Cut(name, "@")
	if !pinned {
		base = name
	}
	p, err := l.store.GetPartial(ctx, l.orgID, base)
	if err != nil {
		if IsNotFound(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if pinned {
		v, parseErr := strconv.Atoi(version)
		if parseErr != nil || v < 1 {
			return "", false, fmt.Errorf("invalid partial version %q", version)
		}
		var body string
		err = l.store.withPolicyTx(ctx, l.orgID, func(tx auditTx) error {
			return tx.QueryRow(ctx, `SELECT body FROM partial_versions WHERE org_id = $1::uuid AND partial_id = $2::uuid AND version = $3`, l.orgID, p.ID, v).Scan(&body)
		})
		if err != nil {
			if IsNotFound(err) {
				return "", false, nil
			}
			return "", false, fmt.Errorf("get partial version: %w", err)
		}
		return body, true, nil
	}
	return p.Body, true, nil
}

// ─── OP-3 seam: org prompts as judge prompts ────────────────────────────

// JudgePromptSource returns the store-backed llmjudge.PromptSource for one
// org. Ref grammar (documented difference from the embedded source):
//
//	org:<name>@<label>  — resolves through THIS org's prompt labels
//	                      (GetActiveByLabel); <label> is a MOVABLE pointer,
//	                      so unlike judges refs ("judges/<name>@<version>",
//	                      immutable file versions) the bytes an org ref
//	                      renders can change when an admin re-promotes the
//	                      label. Policies that need byte-stable judging pin a
//	                      versioned embedded ref; org refs are for
//	                      org-managed prompts whose lifecycle the dashboard
//	                      owns.
//	judges/<name>@<ver> — delegates to llmjudge.EmbeddedPromptSource
//	                      (unchanged OP-3 behavior; judges/* stay embed).
//
// The returned Prompt.Body is the RAW stored template: the judge step
// compiles it as a text/template over {Input, Categories} exactly like the
// embedded judges (a {{var}}-style body is a policy LOAD error there — the
// two grammars are documented, not interchangeable). The source is
// goroutine-safe and honors ctx.
func (s *Store) JudgePromptSource(orgID string) llmjudge.PromptSource {
	return orgJudgePrompts{store: s, orgID: orgID}
}

type orgJudgePrompts struct {
	store *Store
	orgID string
}

// compile-time guard: the adapter satisfies the OP-3 seam.
var _ llmjudge.PromptSource = orgJudgePrompts{}

// Load resolves one prompt ref (PromptSource contract).
func (j orgJudgePrompts) Load(ctx context.Context, ref string) (llmjudge.Prompt, error) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, OrgPromptRefPrefix) {
		return llmjudge.EmbeddedPromptSource{}.Load(ctx, ref)
	}
	body := strings.TrimPrefix(ref, OrgPromptRefPrefix)
	at := strings.LastIndex(body, "@")
	if at <= 0 || at == len(body)-1 {
		return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: want <org:<name>@<label>>", ref)
	}
	name, label := body[:at], body[at+1:]
	if version, parseErr := strconv.Atoi(label); parseErr == nil {
		v, err := j.store.GetPromptVersionByName(ctx, j.orgID, name, version)
		if err != nil {
			if IsNotFound(err) {
				return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: immutable version %d for prompt %q is missing in this org", ref, version, name)
			}
			return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: %w", ref, err)
		}
		return llmjudge.Prompt{Ref: ref, Version: strconv.Itoa(v.Version), Body: v.Template}, nil
	}
	v, err := j.store.GetActiveByLabel(ctx, j.orgID, name, label)
	if err != nil {
		if IsNotFound(err) {
			return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: no prompt %q with label %q in this org", ref, name, label)
		}
		return llmjudge.Prompt{}, fmt.Errorf("prompt ref %q: %w", ref, err)
	}
	return llmjudge.Prompt{Ref: ref, Version: strconv.Itoa(v.Version), Body: v.Template}, nil
}
