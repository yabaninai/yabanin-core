package historyops

import (
	"fmt"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// Caller is the interactive principal attempting an engine action. Role and
// Perms are the org-resolved role plus explicit grants the HTTP boundary
// already resolved (RoleHas / RequireOrgRole semantics) — the engine never
// re-derives org membership, it only applies the history-operation rules on
// top (03-RIGHTS-MODEL §2).
type Caller struct {
	UserID string
	Role   adminstore.OrgRole
	// Perms is the caller's effective permission set for the org (role perms
	// plus explicit per-org grants). A nil map means "no explicit grants".
	Perms map[adminstore.Permission]bool
	// Subject distinguishes people from autonomous principals. Zero value or
	// RequestPayloadHuman = a human user; agent/ci/api_key are delegated
	// subjects and are refused for every mutating engine action.
	Subject adminstore.RequestPayloadSubjectType
}

func (c Caller) has(p adminstore.Permission) bool { return c.Perms[p] }

// human reports whether the caller is a human principal. Fail-closed: an
// unset subject is treated as human only because the HTTP boundary already
// authenticated the session; delegated subjects are explicit values.
func (c Caller) human() bool {
	return c.Subject == "" || c.Subject == adminstore.RequestPayloadHuman
}

// AuthorizePreview gates preview-class reads: any human with the org's
// requests.read permission (built into reader/operator/security_auditor/
// org-admin roles) may preview. Viewers can see what WOULD happen — they can
// never run it (03-RIGHTS-MODEL §2).
func AuthorizePreview(c Caller) error {
	if !c.human() {
		return Refuse(RefusalInsufficientRights,
			"delegated subjects cannot run history operations")
	}
	if !c.has(adminstore.PermRequestsRead) {
		return Refuse(RefusalInsufficientRights, "requests.read is required")
	}
	return nil
}

// AuthorizeJobRead gates job progress/status reads (metadata class).
func AuthorizeJobRead(c Caller) error { return AuthorizePreview(c) }

// AuthorizeManage gates destructive management actions (enqueue of real
// operations, cancel): human org-admins only (03-RIGHTS-MODEL §2). Role rank
// is compared directly so explicit permission grants can never substitute for
// the role itself here.
func AuthorizeManage(c Caller) error {
	if !c.human() {
		return Refuse(RefusalInsufficientRights,
			"delegated subjects cannot run history operations")
	}
	if c.Role != adminstore.RoleOrgAdmin {
		return Refuse(RefusalInsufficientRights,
			"org-admin role is required for history operations")
	}
	return nil
}

// AuthorizeEnqueue applies the per-operation rules on top of AuthorizeManage:
// content-destructive column rewrites (redact_content) additionally require
// the explicit payload and originals grants (03-RIGHTS-MODEL §3 — original-
// capture surfaces must be granted explicitly, built-in roles never carry
// requests.read_originals).
func AuthorizeEnqueue(op Operation, c Caller) error {
	if err := AuthorizeManage(c); err != nil {
		return err
	}
	if op == OpRedactContent {
		if !c.has(adminstore.PermRequestsPayloads) || !c.has(adminstore.PermRequestsReadOriginals) {
			return Refuse(RefusalInsufficientRights,
				"redact_content requires explicit requests.read_payloads and requests.read_originals grants")
		}
	}
	return nil
}

// AuthorizeCancel gates cancel requests: org-admin (management action).
func AuthorizeCancel(c Caller) error { return AuthorizeManage(c) }

// ActorType distinguishes interactive actors from automated ones.
type ActorType string

// Actor values recorded on jobs and journal entries.
const (
	ActorUser    ActorType = "user"
	ActorService ActorType = "service"
)

// JobActor is the attributed principal of a job (03-RIGHTS-MODEL §6): every
// job and every journal entry names its actor. Auto-retention jobs run as the
// retention service and MUST carry the policy version that authorized them,
// so audit can tie a destructive run back to the exact policy revision.
type JobActor struct {
	Type ActorType `json:"type"`
	// Author is the admin user id (user actors) or the service principal
	// identifier (service actors).
	Author string `json:"author"`
	// PolicyVersion is required for service actors: the policy/config version
	// stamp that authorized the automated run.
	PolicyVersion string `json:"policy_version,omitempty"`
}

// Validate enforces the actor contract. An empty type means a user actor
// (interactive enqueue is the overwhelmingly common path); a service actor
// without a policy version is malformed (ErrInvalidRequest — a wiring bug in
// the retention caller, not a refusal).
func (a JobActor) Validate() error {
	if a.Author == "" {
		return fmt.Errorf("%w: actor author is required", ErrInvalidRequest)
	}
	switch a.Type {
	case "", ActorUser:
		return nil
	case ActorService:
		if a.PolicyVersion == "" {
			return fmt.Errorf("%w: service actor requires policy_version", ErrInvalidRequest)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown actor type %q", ErrInvalidRequest, a.Type)
	}
}

// Normalized returns the actor with an explicit type (empty type = user).
func (a JobActor) Normalized() JobActor {
	if a.Type == "" {
		a.Type = ActorUser
	}
	return a
}
