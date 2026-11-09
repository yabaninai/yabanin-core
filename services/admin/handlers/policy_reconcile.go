package handlers

// "database vs git" visibility report for policy pipelines.
//
// Boundary (deliberate): the admin plane has no git checkout (it runs in a
// container), so this endpoint reports the DATABASE half of the drift
// signal — authorship per policy version. A policy whose newest version was
// authored outside git while older versions carry a git_sha is a DRIFT: it
// diverged from git after a reconcile (the Bifrost failure mode — a silent
// UI↔config divergence). A policy with no git-authored versions at all is
// UNMANAGED (never reconciled). The content-level DB-vs-git diff and the
// convergence itself live in the CLI (`yb policies reconcile`, git-wins +
// drift report): the endpoint tells you WHEN to run it, the CLI does it.
//
// The same org gate as the rest of the policy surface applies
// (RequireOrgPermissionPoliciesManage: root or org policies.manage; a
// non-member org is 404). Read-only: no store mutations, no cache bumps.

import (
	"net/http"

	"github.com/reireirei/yabanin/pkg/adminstore"
)

// Policy drift statuses (policyDriftStatus values in the response).
const (
	// PolicyDriftManaged: the newest version was authored by a git
	// reconcile (git_sha set).
	PolicyDriftManaged = "managed"
	// PolicyDriftDiverged: the newest version was authored outside git but
	// the policy HAS git history — edited past git after a reconcile.
	PolicyDriftDiverged = "drift"
	// PolicyDriftUnmanaged: no git-authored versions — never reconciled
	// (UI/API-native policy; reported for completeness, not an incident).
	PolicyDriftUnmanaged = "unmanaged"
)

// PolicyDriftEntry is one policy row of the drift report.
type PolicyDriftEntry struct {
	PolicyID       string `json:"policy_id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	Enabled        bool   `json:"enabled"`
	CurrentVersion int    `json:"current_version"`
	LatestVersion  int    `json:"latest_version"`
	LatestGitSHA   string `json:"latest_git_sha"`
	LatestAuthor   string `json:"latest_created_by"`
	// LatestEditedAt is when the newest version landed — the "since when"
	// of a drift.
	LatestEditedAt string `json:"latest_edited_at"`
}

// PolicyDriftReport is the GET drift payload.
type PolicyDriftReport struct {
	OrgID      string             `json:"org_id"`
	Count      int                `json:"count"`
	DriftCount int                `json:"drift_count"`
	Data       []PolicyDriftEntry `json:"data"`
}

// handleDrift serves GET /api/organizations/{id}/policies/drift: the
// DB-side drift classification of every policy in the org, oldest policy
// first (deterministic order for dashboards and alert diffs).
func (o *PolicyPipelineHandlers) handleDrift(w http.ResponseWriter, r *http.Request) {
	if o.unwired(w) {
		return
	}
	orgID := r.PathValue("id")
	policies, err := o.store.ListPolicies(r.Context(), orgID)
	if err != nil {
		o.writeStoreError(w, err)
		return
	}
	report := PolicyDriftReport{OrgID: orgID, Data: []PolicyDriftEntry{}}
	for _, p := range policies {
		versions, err := o.store.ListPolicyVersions(r.Context(), orgID, p.ID)
		if err != nil {
			o.writeStoreError(w, err)
			return
		}
		entry := PolicyDriftEntry{
			PolicyID:       p.ID,
			Name:           p.Name,
			Status:         PolicyDriftUnmanaged,
			Enabled:        p.Enabled,
			CurrentVersion: p.CurrentVersion,
		}
		if len(versions) > 0 {
			latest := versions[0] // newest first (store contract)
			entry.LatestVersion = latest.Version
			entry.LatestGitSHA = latest.GitSHA
			entry.LatestAuthor = latest.CreatedBy
			entry.LatestEditedAt = latest.CreatedAt.UTC().Format(http.TimeFormat)
			switch {
			case latest.GitSHA != "":
				entry.Status = PolicyDriftManaged
			case hasGitVersion(versions):
				entry.Status = PolicyDriftDiverged
			}
		}
		if entry.Status == PolicyDriftDiverged {
			report.DriftCount++
		}
		report.Data = append(report.Data, entry)
	}
	report.Count = len(report.Data)
	writeJSON(w, http.StatusOK, report)
}

// hasGitVersion reports whether any version was authored by a git reconcile.
func hasGitVersion(versions []adminstore.PolicyVersion) bool {
	for _, v := range versions {
		if v.GitSHA != "" {
			return true
		}
	}
	return false
}
