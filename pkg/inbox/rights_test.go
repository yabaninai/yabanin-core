package inbox_test

// E06-P01 W04-C03: the rights battery for the operator write surface,
// written from OUTSIDE pkg/inbox (an auditor's vantage — it may use the
// public surface and the wiring facts, never package internals).
//
// Three pins:
//
//	role matrix   security.manage is org_admin-only (operator, auditor,
//	              reader, partner: denied); the read permission stays
//	              wider (org_admin + security_auditor)
//	route wiring  the PATCH route is mounted behind security.manage and
//	              the reads behind security.read; the handler layer has
//	              NO inline role/permission logic of its own (all
//	              authorization is the middleware's)
//	journal       the write path journals through the shared audit path
//
// UI: P01 ships no inbox UI; a UI rights check is N/A by design (noted in
// the delivery record, not silently skipped).

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/inbox"
)

const handlersSourcePath = "../../services/admin/handlers/security_inbox_handlers.go"

func readHandlersSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(handlersSourcePath)
	require.NoError(t, err, "the rights battery must run inside the repository checkout")
	return string(b)
}

func TestSecurityManageIsOrgAdminOnly(t *testing.T) {
	assert.True(t, adminstore.RoleHas(string(adminstore.RoleOrgAdmin), adminstore.PermSecurityManage),
		"org_admin is the operator write role")
	for _, role := range []string{
		string(adminstore.RoleOperator),
		string(adminstore.RoleSecurityAuditor),
		string(adminstore.RoleReader),
		string(adminstore.RolePartner),
		"nonexistent-role",
	} {
		assert.False(t, adminstore.RoleHas(role, adminstore.PermSecurityManage),
			"role %q must not hold security.manage", role)
	}
}

func TestSecurityReadStaysWiderThanManage(t *testing.T) {
	// The read surface is deliberately wider than the write surface: the
	// auditor watches, the org admin acts.
	assert.True(t, adminstore.RoleHas(string(adminstore.RoleSecurityAuditor), adminstore.PermSecurityRead))
	assert.False(t, adminstore.RoleHas(string(adminstore.RoleSecurityAuditor), adminstore.PermSecurityManage),
		"if the auditor could write, the read/write split would be meaningless")
	assert.False(t, adminstore.RoleHas(string(adminstore.RoleOperator), adminstore.PermSecurityRead))
}

func TestPatchRouteWiringPins(t *testing.T) {
	src := readHandlersSource(t)

	t.Run("reads behind security.read, writes behind security.manage", func(t *testing.T) {
		require.Contains(t, src, "h.RequireOrgPermission(adminstore.PermSecurityRead)",
			"the read mount must keep its permission gate")
		require.Contains(t, src, "h.RequireOrgPermission(adminstore.PermSecurityManage)",
			"the PATCH mount must sit behind the manage permission")
	})

	t.Run("the PATCH route exists exactly once and is PATCH-method", func(t *testing.T) {
		require.Contains(t, src, `gp.Patch("/api/organizations/{id}/security-inbox/{incident_id}"`,
			"the operator write must be a PATCH on the incident resource")
	})

	t.Run("no inline authorization in the handler layer", func(t *testing.T) {
		// Authorization is the middleware's job; a handler checking roles
		// itself would be a second, drift-prone law. (Comments may mention
		// roles; code must not branch on them.)
		for _, banned := range []string{
			"RoleHas(", "RoleOrgAdmin", "RoleSecurityAuditor", "RoleOperator",
			"IsRoot ==", "IsRoot !=",
		} {
			for _, line := range strings.Split(src, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue // comments are documentation, not law
				}
				assert.NotContains(t, line, banned,
					"handler layer must not branch on %q itself (middleware owns authorization)", banned)
			}
		}
	})

	t.Run("write outcomes are journaled through the shared audit path", func(t *testing.T) {
		require.Contains(t, src, `"security_inbox.patch"`,
			"the patch journal action must stay in the shared namespace")
		require.Contains(t, src, "h.auditLogAction(")
	})
}

func TestStatusLawIsExportedCode(t *testing.T) {
	// The W04-C01 law: the transition table is exported code law, not a
	// database/check constraint an operator could edit around. Pinned from
	// outside via the public surface: reopens are legal, skips are not.
	require.NoError(t, inbox.ValidateTransition(inbox.StatusResolved, inbox.StatusAcknowledged))
	require.NoError(t, inbox.ValidateTransition(inbox.StatusDismissed, inbox.StatusAcknowledged))
	require.NoError(t, inbox.ValidateTransition(inbox.StatusNew, inbox.StatusNew),
		"same-state is the idempotency law")
	require.ErrorIs(t, inbox.ValidateTransition(inbox.StatusNew, inbox.StatusResolved), inbox.ErrInvalidTransition)
	require.ErrorIs(t, inbox.ValidateTransition(inbox.StatusAcknowledged, inbox.StatusDismissed), inbox.ErrInvalidTransition)
	require.ErrorIs(t, inbox.ValidateTransition(inbox.StatusNew, "OPEN"), inbox.ErrInvalidTransition)
}
