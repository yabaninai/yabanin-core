package adminstore

// Permission is one org-scoped capability. Anything absent from a role's row
// is denied.
type Permission string

// RequestPayloadDecision documents payload authorization precedence. A policy
// deny is absolute; an active resource-scoped grant is next; role permissions
// are the final fallback and never override an explicit deny.
type RequestPayloadDecision string

const (
	// RequestPayloadDenied is the fail-closed decision.
	RequestPayloadDenied RequestPayloadDecision = "deny"
	// RequestPayloadGranted means a valid resource-scoped grant applies.
	RequestPayloadGranted RequestPayloadDecision = "grant"
	// RequestPayloadRole means access is permitted by the final role fallback.
	RequestPayloadRole RequestPayloadDecision = "role"
)

// ResolveRequestPayloadDecision applies the shared deny > grant > role order.
func ResolveRequestPayloadDecision(denied, granted, roleAllows bool) RequestPayloadDecision {
	if denied {
		return RequestPayloadDenied
	}
	if granted {
		return RequestPayloadGranted
	}
	if roleAllows {
		return RequestPayloadRole
	}
	return RequestPayloadDenied
}

// Org-scoped permissions. A role that does not list one is denied.
const (
	PermAnalyticsRead    Permission = "analytics.read"
	PermRequestsRead     Permission = "requests.read"
	PermRequestsPayloads Permission = "requests.read_payloads"
	// PermRequestsReadOriginals is never included in a built-in role. Original
	// text requires a separately assigned grant in the authorization layer.
	PermRequestsReadOriginals Permission = "requests.read_originals"
	PermLineageRead           Permission = "lineage.read"
	PermLineageVerify         Permission = "lineage.verify"
	PermAuditRead             Permission = "audit.read"
	PermSecurityRead          Permission = "security.read"
	// PermSecurityManage is the operator write on the E06-P01 security
	// inbox (status transitions, assignment). Deliberately org_admin-only:
	// the write surface is narrower than the read surface (security_auditor
	// keeps read-only). W04-C02.
	PermSecurityManage  Permission = "security.manage"
	PermKeysManage      Permission = "keys.manage"
	PermAgentKeysManage Permission = "agent_keys.manage"
	PermBudgetsManage   Permission = "budgets.manage"
	PermMembersManage   Permission = "members.manage"
	PermRoutingManage   Permission = "routing.manage"
	PermPoliciesManage  Permission = "policies.manage"
	PermOrgUpdate       Permission = "org.update"
)

// GlobalRoleSecurityAuditor is the only non-root global role. It may read the
// platform audit log. Creating orgs, models, prices, admin users, and the
// MCP/A2A registries stays root-only.
const GlobalRoleSecurityAuditor = "security_auditor"

// AllPermissions is every permission in the matrix, in a stable order.
func AllPermissions() []Permission {
	return []Permission{
		PermAnalyticsRead,
		PermRequestsRead,
		PermRequestsPayloads,
		PermRequestsReadOriginals,
		PermLineageRead,
		PermLineageVerify,
		PermAuditRead,
		PermSecurityRead,
		PermSecurityManage,
		PermKeysManage,
		PermAgentKeysManage,
		PermBudgetsManage,
		PermMembersManage,
		PermRoutingManage,
		PermPoliciesManage,
		PermOrgUpdate,
	}
}

// RoleHas reports whether an org role grants p. Unknown roles grant nothing.
// partner has no HTTP route of its own today, so it grants nothing.
func RoleHas(role string, p Permission) bool {
	_, ok := rolePermissions[role][p]
	return ok
}

// CanReadGlobalAudit is true for root and for a global security auditor.
func CanReadGlobalAudit(isRoot bool, globalRole string) bool {
	return isRoot || globalRole == GlobalRoleSecurityAuditor
}

var rolePermissions = map[string]map[Permission]struct{}{
	// Payload reads are resource-scoped; org administration alone is not a
	// grant to inspect another subject's request history.
	string(RoleOrgAdmin):        permSet(PermAnalyticsRead, PermRequestsRead, PermLineageRead, PermLineageVerify, PermAuditRead, PermSecurityRead, PermSecurityManage, PermKeysManage, PermAgentKeysManage, PermBudgetsManage, PermMembersManage, PermRoutingManage, PermPoliciesManage, PermOrgUpdate),
	string(RoleOperator):        permSet(PermAnalyticsRead, PermRequestsRead, PermLineageRead, PermLineageVerify, PermKeysManage, PermAgentKeysManage, PermBudgetsManage, PermRoutingManage),
	string(RoleSecurityAuditor): permSet(PermAnalyticsRead, PermRequestsRead, PermLineageRead, PermLineageVerify, PermAuditRead, PermSecurityRead),
	string(RoleReader):          permSet(PermAnalyticsRead, PermRequestsRead, PermLineageRead),
	string(RolePartner):         {},
}

func permSet(perms ...Permission) map[Permission]struct{} {
	out := make(map[Permission]struct{}, len(perms))
	for _, p := range perms {
		out[p] = struct{}{}
	}
	return out
}
