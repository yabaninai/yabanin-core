package adminstore

// W-CAPS unit coverage: update validation bounds and the budget-exceeded
// webhook notifier's honest no-op / SSRF-rejection behavior. The DB round
// trip (defaults merge, per-org isolation) lives in orgcaps_int_test.go.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func int64ptr(v int64) *int64 { return &v }

func TestValidateOrgCapsUpdate(t *testing.T) {
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{}), "all-null update clears every override")

	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{RPM: int64ptr(1)}))
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{TPM: int64ptr(MaxOrgCapsValue)}))
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{MonthlyBudgetCents: int64ptr(5_000_000)}))
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{InputTPM: int64ptr(1)}))
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{OutputTPM: int64ptr(MaxOrgCapsValue)}))
	require.NoError(t, ValidateOrgCapsUpdate(OrgCapsUpdate{KeyTPM: int64ptr(50_000)}))

	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{RPM: int64ptr(0)}), "0 would mean unlimited-by-omission downstream")
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{RPM: int64ptr(-5)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{RPM: int64ptr(MaxOrgCapsValue + 1)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{TPM: int64ptr(0)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{MonthlyBudgetCents: int64ptr(0)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{MonthlyBudgetCents: int64ptr(MaxOrgCapsBudgetCents + 1)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{InputTPM: int64ptr(0)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{OutputTPM: int64ptr(-1)}))
	require.Error(t, ValidateOrgCapsUpdate(OrgCapsUpdate{KeyTPM: int64ptr(MaxOrgCapsValue + 1)}))
}

func TestValidAPIKeyPriority(t *testing.T) {
	assert.True(t, ValidAPIKeyPriority(0))
	assert.True(t, ValidAPIKeyPriority(DefaultAPIKeyPriority))
	assert.True(t, ValidAPIKeyPriority(MaxAPIKeyPriority))
	assert.False(t, ValidAPIKeyPriority(-1))
	assert.False(t, ValidAPIKeyPriority(10))
}

func TestBudgetWebhookNotifier_EmptyURLIsNoop(t *testing.T) {
	n := NewBudgetWebhookNotifier(nil)
	err := n.BudgetExceeded(context.Background(), "org-1",
		OrgAlertTarget{Name: "Org One", WebhookURL: ""}, 5_000_000, 5_100_000)
	require.NoError(t, err, "no webhook configured = honest no-op, not an error")
}

func TestBudgetWebhookNotifier_RejectsLoopbackTarget(t *testing.T) {
	// The delivery path reuses the spend-alert SSRF guard: a loopback (and
	// any reserved-range) webhook URL is rejected before a byte is sent.
	n := NewBudgetWebhookNotifier(nil)
	err := n.BudgetExceeded(context.Background(), "org-1",
		OrgAlertTarget{Name: "Org One", WebhookURL: "http://127.0.0.1:9090/hook"},
		5_000_000, 5_100_000)
	require.Error(t, err, "loopback webhook target must be rejected")
}
