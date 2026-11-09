package handlers

// SSO group → local-role mapping application (N04-P01). The org-declared
// rules live in sso_group_role_rules (migration 0012, pkg/adminstore); this
// file owns the login-time sync: after an OIDC identity verifies, the
// caller's org memberships are reconciled against the rules of each org they
// already belong to.
//
// Model (fail-closed and idempotent):
//
//   - Mapping is scoped to EXISTING memberships. SSO never provisions an
//     account and never creates a first membership; rules decide what ROLE an
//     existing membership holds. An org with no declared rules is untouched.
//   - A grant decision sets the membership role to the granted role and
//     records provenance (sso_role_grants). Repeated logins with the same
//     groups are byte-for-byte no-ops (no audit churn, no updated_at churn).
//     A membership that ALREADY holds the granted role without provenance is
//     never adopted — the mapping must not claim an admin's own grant.
//   - Deny-wins: a matching deny rule or conflicting grant rules produce no
//     grant; if the mapping had granted a role earlier, that grant is
//     revoked at this login (deny strips what the mapping gave).
//   - Revocation on subsequent sync: when the rules stop justifying the
//     previously granted role (rule removed, groups changed, deny added),
//     the mapping-granted role is revoked — but only if the membership still
//     holds exactly the granted role. A role an admin changed by hand after
//     the grant is left alone (the mapping relinquishes it).
//   - Cross-org isolation: rules and provenance are always resolved with the
//     org predicate; org A's rules never decide anything about org B.
//
// Failures of the mapping sync never block the login (the session's
// authority is the DB user, verified above); the sync is convergent under
// retry and the next login re-runs it. Convergence comes from write ORDER,
// not from rollback: a grant records provenance BEFORE touching the
// membership, so a split failure leaves at most a provenance ORPHAN
// (provenance for a membership the sync never changed) — the next login
// either completes that grant or relinquishes the orphan via the revoke
// path. The reverse order could strand a role granted WITHOUT provenance,
// which the do-not-adopt branch would then never revoke. Every
// grant/revocation is journalled through the shared durable audit writer
// with the mapped user in the details — the login request carries no
// session context yet.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// ssoMappingStore is the capability subset the mapping sync needs. It is
// resolved by capability assertion (the router.go watermark pattern), so
// stores that predate the feature — and every slim test stub — keep working
// with mapping simply inert.
type ssoMappingStore interface {
	GetUserOrgRoles(ctx context.Context, userID string) (map[string]adminstore.OrgRole, error)
	SetOrgMembership(ctx context.Context, userID, orgID string, role adminstore.OrgRole) (*adminstore.OrgMembership, error)
	DeleteOrgMembership(ctx context.Context, userID, orgID string) error
	ListSSOGroupRoleRules(ctx context.Context, orgID string) ([]adminstore.SSOGroupRoleRule, error)
	GetSSOGrantedRole(ctx context.Context, orgID, userID string) (adminstore.OrgRole, bool, error)
	SetSSOGrantedRole(ctx context.Context, orgID, userID string, role adminstore.OrgRole) error
	DeleteSSOGrantedRole(ctx context.Context, orgID, userID string) error
}

// applySSORoleMapping reconciles userID's org memberships with the declared
// group rules, given the raw ID-token groups of this login. sso identifies
// the binding in audit details ("oidc").
func (h *AdminHandlers) applySSORoleMapping(ctx context.Context, r *http.Request, userID string, groups []string, sso string) {
	ms, ok := h.store.(ssoMappingStore)
	if !ok {
		return // store without the mapping capability: feature off
	}
	orgRoles, err := ms.GetUserOrgRoles(ctx, userID)
	if err != nil {
		h.ssoMappingLog("list org memberships failed", err)
		return
	}
	// Deterministic order: audit entries and role writes must not depend on
	// Go's randomized map iteration.
	orgIDs := make([]string, 0, len(orgRoles))
	for orgID := range orgRoles {
		orgIDs = append(orgIDs, orgID)
	}
	sort.Strings(orgIDs)

	for _, orgID := range orgIDs {
		h.applySSORoleMappingForOrg(ctx, r, ms, userID, orgID, orgRoles[orgID], groups, sso)
	}
}

// applySSORoleMappingForOrg applies the mapping for ONE org membership.
// Errors are logged and skipped — the sync converges at the next login.
func (h *AdminHandlers) applySSORoleMappingForOrg(
	ctx context.Context,
	r *http.Request,
	ms ssoMappingStore,
	userID, orgID string,
	currentRole adminstore.OrgRole,
	groups []string,
	sso string,
) {
	rules, err := ms.ListSSOGroupRoleRules(ctx, orgID)
	if err != nil {
		h.ssoMappingLog("list sso group rules failed", err)
		return
	}
	decision := adminstore.ResolveSSORole(rules, groups)
	prevRole, hasPrev, err := ms.GetSSOGrantedRole(ctx, orgID, userID)
	if err != nil {
		h.ssoMappingLog("read sso role provenance failed", err)
		return
	}

	if decision.Granted {
		// Asymmetry by design: while a rule grants, the default branch
		// re-asserts the mapped role even over an admin's manual demotion
		// (the org's declared rule stays authoritative for the role it
		// names); once no rule grants, the revoke path below instead
		// relinquishes — an admin's manual edit is never clobbered there.
		switch {
		case currentRole == decision.Role && hasPrev && prevRole == decision.Role:
			// Idempotent re-login: already granted by this mapping. No
			// writes, no audit churn.
		case currentRole == decision.Role:
			// The membership already holds the granted role without mapping
			// provenance — an admin's own grant. Do not adopt it.
		default:
			// Provenance FIRST (convergence by write order — see the
			// file-header note): a failure between the two writes strands a
			// provenance orphan, never an unprovenanced grant, and the next
			// login heals or relinquishes it.
			if err := ms.SetSSOGrantedRole(ctx, orgID, userID, decision.Role); err != nil {
				h.ssoMappingLog("record sso role provenance failed", err)
				return
			}
			if _, err := ms.SetOrgMembership(ctx, userID, orgID, decision.Role); err != nil {
				h.ssoMappingLog("grant mapped role failed", err)
				return
			}
			h.auditLogActionWithCtx(ctx, r, "sso_role_grant", "org_membership",
				fmt.Sprintf("sso=%s,org=%s,user=%s,role=%s,group=%s", sso, orgID, userID, decision.Role, decision.Group))
		}
		return
	}

	// No rule granted (unmapped groups) or deny/conflict: nothing to grant —
	// and a mapping-granted role that is no longer justified is revoked at
	// this sync. Only the mapping's own grant is revocable, and only while
	// the membership still holds exactly that role.
	//
	// Revocation keys on the ROLE VALUE, not on the membership row the
	// mapping last wrote: if an admin deletes and re-creates the membership
	// at the provenance role, the sync cannot tell that recreation from the
	// mapping's grant and deletes it too. That ambiguity is deliberately
	// fail-closed — the sync errs toward revoking mapping-shaped state,
	// never toward silently keeping it.
	if !hasPrev {
		return
	}
	if currentRole == prevRole {
		if err := ms.DeleteOrgMembership(ctx, userID, orgID); err != nil && !errors.Is(err, adminstore.ErrNotFound) {
			h.ssoMappingLog("revoke mapped role failed", err)
			return
		}
		h.auditLogActionWithCtx(ctx, r, "sso_role_revoke", "org_membership",
			fmt.Sprintf("sso=%s,org=%s,user=%s,role=%s,denied=%t", sso, orgID, userID, prevRole, decision.Denied))
	}
	if err := ms.DeleteSSOGrantedRole(ctx, orgID, userID); err != nil {
		h.ssoMappingLog("clear sso role provenance failed", err)
	}
}

// ssoMappingLog reports a skipped sync step without blocking the login.
func (h *AdminHandlers) ssoMappingLog(msg string, err error) {
	h.auditLog().Warn("admin sso role mapping skipped — retried at next login", "msg", msg, "error", err)
}
