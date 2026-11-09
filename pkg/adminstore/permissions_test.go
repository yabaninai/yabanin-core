package adminstore

import "testing"

func TestResolveRequestPayloadDecision_DenyGrantRolePrecedence(t *testing.T) {
	tests := []struct {
		name                  string
		denied, granted, role bool
		want                  RequestPayloadDecision
	}{
		{name: "deny overrides grant and role", denied: true, granted: true, role: true, want: RequestPayloadDenied},
		{name: "grant overrides role", granted: true, role: true, want: RequestPayloadGranted},
		{name: "role fallback", role: true, want: RequestPayloadRole},
		{name: "default deny", want: RequestPayloadDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveRequestPayloadDecision(tt.denied, tt.granted, tt.role); got != tt.want {
				t.Fatalf("ResolveRequestPayloadDecision() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRoleHas_Matrix(t *testing.T) {
	want := map[string]map[Permission]bool{}
	for _, role := range []string{string(RoleOrgAdmin), string(RoleOperator), string(RoleSecurityAuditor), string(RoleReader), string(RolePartner), "nope"} {
		want[role] = map[Permission]bool{}
	}
	for _, p := range AllPermissions() {
		if p != PermRequestsPayloads && p != PermRequestsReadOriginals {
			want[string(RoleOrgAdmin)][p] = true
		}
	}
	for _, p := range []Permission{PermAnalyticsRead, PermRequestsRead, PermLineageRead, PermLineageVerify, PermKeysManage, PermAgentKeysManage, PermBudgetsManage, PermRoutingManage} {
		want[string(RoleOperator)][p] = true
	}
	for _, p := range []Permission{PermAnalyticsRead, PermRequestsRead, PermLineageRead, PermLineageVerify, PermAuditRead, PermSecurityRead} {
		want[string(RoleSecurityAuditor)][p] = true
	}
	for _, p := range []Permission{PermAnalyticsRead, PermRequestsRead, PermLineageRead} {
		want[string(RoleReader)][p] = true
	}

	for _, role := range []string{string(RoleOrgAdmin), string(RoleOperator), string(RoleSecurityAuditor), string(RoleReader), string(RolePartner), "nope"} {
		for _, p := range AllPermissions() {
			if RoleHas(role, p) != want[role][p] {
				t.Errorf("RoleHas(%q, %q) = %v, want %v", role, p, RoleHas(role, p), want[role][p])
			}
		}
	}
}

func TestOriginalsReadPermissionIsNotGrantedByBuiltInRoles(t *testing.T) {
	for _, role := range []string{string(RoleOrgAdmin), string(RoleOperator), string(RoleSecurityAuditor), string(RoleReader), string(RolePartner)} {
		if RoleHas(role, PermRequestsReadOriginals) {
			t.Errorf("role %q unexpectedly has %q", role, PermRequestsReadOriginals)
		}
	}
}

func TestCanReadGlobalAudit(t *testing.T) {
	if !CanReadGlobalAudit(true, "") || !CanReadGlobalAudit(false, GlobalRoleSecurityAuditor) {
		t.Fatal("root and global auditor must read the platform audit log")
	}
	if CanReadGlobalAudit(false, "") || CanReadGlobalAudit(false, "operator") {
		t.Fatal("other global roles must not read the platform audit log")
	}
}
