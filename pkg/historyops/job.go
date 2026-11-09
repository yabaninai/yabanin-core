package historyops

import (
	"sort"
	"time"
)

// JobStatus is the managed-job lifecycle state.
type JobStatus string

// Lifecycle states. pending → processing → completed|canceled|failed.
// failed and canceled are terminal; a failed job with attempts left returns
// to pending (ReleaseForRetry) instead of going terminal.
const (
	JobPending    JobStatus = "pending"
	JobProcessing JobStatus = "processing"
	JobCompleted  JobStatus = "completed"
	JobCanceled   JobStatus = "canceled"
	JobFailed     JobStatus = "failed"
)

// Terminal reports whether the status ends the job's lifecycle.
func (s JobStatus) Terminal() bool {
	return s == JobCompleted || s == JobCanceled || s == JobFailed
}

// Checkpoint is the worker-restart anchor (backlog AC-02): the captured plan
// and how far execution has advanced. The plan is captured BEFORE the first
// batch executes, so a restart resumes from the checkpoint and never
// re-plans against drifted data.
type Checkpoint struct {
	// Planned marks that Plan() has completed — true even for empty plans
	// (a valid selection may match zero rows; a no-op completion is then
	// correct and must not re-trigger planning on restart).
	Planned bool `json:"planned"`
	// Plan is the ordered list of id-precise batches. Id-precise means the
	// plan names concrete row ids, never a re-runnable predicate: replanning
	// on restart would silently pick up newly created rows.
	Plan [][]string `json:"plan"`
	// NextBatch is the index of the next batch to execute.
	NextBatch int `json:"next_batch"`
	// ProtectedIDs lists (capped) request ids the operation would leave
	// alone because a data-processing grant is still live. Reported by
	// archive ops via PlanReporter so an operator can see why selected
	// requests were skipped. Identifiers only — never payload content.
	ProtectedIDs []string `json:"protected_ids,omitempty"`
	// ProtectedTruncated reports whether ProtectedIDs hit the report cap.
	ProtectedTruncated bool `json:"protected_truncated,omitempty"`
}

// FamilyCounts accumulates confirmed row counts per family. Counts are
// identifiers-and-numbers only — never payload content.
type FamilyCounts map[Family]int64

// Add accumulates other into c.
func (c FamilyCounts) Add(other FamilyCounts) {
	for f, n := range other {
		c[f] += n
	}
}

// Clone returns an independent copy.
func (c FamilyCounts) Clone() FamilyCounts {
	out := make(FamilyCounts, len(c))
	for f, n := range c {
		out[f] = n
	}
	return out
}

// Total sums all families.
func (c FamilyCounts) Total() int64 {
	var total int64
	for _, n := range c {
		total += n
	}
	return total
}

// Names returns the family names in sorted order (stable journal details).
func (c FamilyCounts) Names() []string {
	out := make([]string, 0, len(c))
	for f := range c {
		out = append(out, string(f))
	}
	sort.Strings(out)
	return out
}

// Job is one managed history operation (backlog AC-02 semantics: lease,
// checkpoint, cancel, resume, idempotent replay).
type Job struct {
	ID              string      `json:"id"`
	OrgID           string      `json:"org_id"`
	Op              Operation   `json:"op"`
	Selection       Selection   `json:"selection"`
	SelectionDigest string      `json:"selection_digest"`
	Stamp           SchemaStamp `json:"stamp"`
	// Destination is the cold-storage root for archive operations (empty
	// otherwise). It is org-namespace-validated at enqueue.
	Destination    string `json:"destination,omitempty"`
	IdempotencyKey string `json:"idempotency_key"`

	Status          JobStatus `json:"status"`
	Attempts        int       `json:"attempts"`
	LeaseUntil      time.Time `json:"lease_until,omitempty"`
	WorkerID        string    `json:"worker_id,omitempty"`
	NextAttemptAt   time.Time `json:"next_attempt_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	CancelRequested time.Time `json:"cancel_requested,omitempty"`

	Checkpoint  Checkpoint   `json:"checkpoint"`
	Confirmed   FamilyCounts `json:"confirmed"`
	Actor       JobActor     `json:"actor"`
	Refusal     *Refusal     `json:"refusal,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	CompletedAt time.Time    `json:"completed_at,omitempty"`
}

// BatchesTotal returns the planned batch count (0 before planning).
func (j *Job) BatchesTotal() int { return len(j.Checkpoint.Plan) }

// BatchesDone returns the number of fully applied batches.
func (j *Job) BatchesDone() int { return j.Checkpoint.NextBatch }
