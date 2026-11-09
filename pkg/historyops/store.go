package historyops

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// JobStore persists managed jobs. The interface is the durable-persistence
// seam: a SQL-backed store (migration 0017, historyops_jobs) plugs in here
// without touching the engine. MemoryJobStore below is the reference
// implementation.
//
// Concurrency contract: implementations must make ClaimNext, SaveCheckpoint,
// Finalize and RequestCancel atomic with respect to each other; lease guards
// (workerID match) protect against two workers advancing one job after a
// lease expiry race. Errors returned for state violations are ErrLeaseLost /
// ErrJobTerminal / ErrNotFound / ErrDuplicateJob.
type JobStore interface {
	// CreateJob stores a new pending job. A repeated (org, idempotency key)
	// pair fails with ErrDuplicateJob.
	CreateJob(ctx context.Context, job *Job) error
	// JobByIdempotencyKey resolves the job created for (orgID, key). Absent
	// keys resolve to ErrNotFound (no job exists for this org+key).
	JobByIdempotencyKey(ctx context.Context, orgID, key string) (*Job, error)
	// JobByID resolves a job within orgID only: jobs of other orgs are
	// indistinguishable from unknown ids (ErrNotFound) — zero cross-org
	// leakage (03-RIGHTS-MODEL §4).
	JobByID(ctx context.Context, orgID, jobID string) (*Job, error)
	// ClaimNext atomically claims the oldest claimable pending job for
	// workerID (status pending, next attempt due), transitions it to
	// processing with leaseUntil = now+leaseTTL and increments Attempts.
	// An empty queue resolves to ErrQueueEmpty.
	ClaimNext(ctx context.Context, workerID string, leaseTTL time.Duration) (*Job, error)
	// RecoverExpiredLeases returns processing jobs whose lease expired to
	// pending so another worker can resume from their checkpoint.
	RecoverExpiredLeases(ctx context.Context) (int, error)
	// SaveCheckpoint advances the checkpoint and confirmed counts AND
	// renews the lease to now+leaseTTL — checkpoint = progress = renewal.
	// A worker that keeps checkpointing keeps its lease exclusively, so a
	// job whose total runtime exceeds one LeaseTTL is never re-queued under
	// a live worker: LeaseTTL bounds the duration of ONE batch (between
	// checkpoints), not the whole job. Guarded by the lease (ErrLeaseLost
	// when workerID no longer holds the job); a non-positive leaseTTL
	// leaves the lease unchanged (unused by the engine, whose config always
	// carries a positive TTL).
	SaveCheckpoint(ctx context.Context, jobID, workerID string, leaseTTL time.Duration, cp Checkpoint, confirmed FamilyCounts) error
	// ReleaseForRetry returns a processing job to pending for a later
	// attempt (transient failure); guarded by the lease.
	ReleaseForRetry(ctx context.Context, jobID, workerID string, nextAttempt time.Time, lastErr string) error
	// Finalize transitions a processing job to a terminal state; guarded by
	// the lease. Called exactly once per job by the engine.
	Finalize(ctx context.Context, jobID, workerID string, status JobStatus, confirmed FamilyCounts, refusal *Refusal, lastErr string) error
	// RequestCancel records a cancel request (org-scoped: foreign ids are
	// ErrNotFound). Cancel on a terminal job is ErrJobTerminal.
	RequestCancel(ctx context.Context, orgID, jobID string, at time.Time) error
}

// MemoryJobStore is an in-process JobStore — the reference implementation for
// tests and single-process deployments. Durability is the known, documented
// limitation; a crash loses queued jobs (deliver the SQL-backed store from
// the follow-up card to remove this).
type MemoryJobStore struct {
	mu  sync.Mutex
	now func() time.Time

	jobs map[string]*Job
	idem map[string]string // orgID|key → job id
	// order keeps creation order so ClaimNext is FIFO-deterministic.
	order []string
}

// NewMemoryJobStore builds a store using the given clock (nil = time.Now).
func NewMemoryJobStore(now func() time.Time) *MemoryJobStore {
	if now == nil {
		now = time.Now
	}
	return &MemoryJobStore{
		now:  now,
		jobs: make(map[string]*Job),
		idem: make(map[string]string),
	}
}

// NewJobID returns a fresh job identifier.
func NewJobID() string { return uuid.NewString() }

func (s *MemoryJobStore) clone(j *Job) *Job {
	cp := *j
	cp.Selection = j.Selection
	cp.Selection.Families = append([]Family(nil), j.Selection.Families...)
	cp.Confirmed = j.Confirmed.Clone()
	cp.Checkpoint.Plan = make([][]string, len(j.Checkpoint.Plan))
	for i, b := range j.Checkpoint.Plan {
		cp.Checkpoint.Plan[i] = append([]string(nil), b...)
	}
	cp.Checkpoint.ProtectedIDs = append([]string(nil), j.Checkpoint.ProtectedIDs...)
	if j.Refusal != nil {
		r := *j.Refusal
		r.GrantIDs = append([]string(nil), j.Refusal.GrantIDs...)
		cp.Refusal = &r
	}
	return &cp
}

// CreateJob implements JobStore.
func (s *MemoryJobStore) CreateJob(_ context.Context, job *Job) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := job.OrgID + "|" + job.IdempotencyKey
	if _, dup := s.idem[key]; dup {
		return ErrDuplicateJob
	}
	stored := s.clone(job)
	if stored.ID == "" {
		stored.ID = NewJobID()
	}
	now := s.now()
	stored.Status = JobPending
	stored.CreatedAt = now
	stored.UpdatedAt = now
	s.jobs[stored.ID] = stored
	s.idem[key] = stored.ID
	s.order = append(s.order, stored.ID)
	job.ID = stored.ID
	job.Status = JobPending
	return nil
}

// JobByIdempotencyKey implements JobStore.
func (s *MemoryJobStore) JobByIdempotencyKey(_ context.Context, orgID, key string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.idem[orgID+"|"+key]
	if !ok {
		return nil, ErrNotFound
	}
	return s.clone(s.jobs[id]), nil
}

// JobByID implements JobStore (org-scoped; ErrNotFound otherwise).
func (s *MemoryJobStore) JobByID(_ context.Context, orgID, jobID string) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok || j.OrgID != orgID {
		return nil, ErrNotFound
	}
	return s.clone(j), nil
}

// ClaimNext implements JobStore.
func (s *MemoryJobStore) ClaimNext(_ context.Context, workerID string, leaseTTL time.Duration) (*Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for _, id := range s.order {
		j := s.jobs[id]
		if j.Status != JobPending {
			continue
		}
		if !j.NextAttemptAt.IsZero() && j.NextAttemptAt.After(now) {
			continue
		}
		j.Status = JobProcessing
		j.Attempts++
		j.WorkerID = workerID
		j.LeaseUntil = now.Add(leaseTTL)
		j.UpdatedAt = now
		return s.clone(j), nil
	}
	return nil, ErrQueueEmpty
}

// RecoverExpiredLeases implements JobStore.
func (s *MemoryJobStore) RecoverExpiredLeases(_ context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	recovered := 0
	for _, id := range s.order {
		j := s.jobs[id]
		if j.Status == JobProcessing && !j.LeaseUntil.After(now) {
			j.Status = JobPending
			j.WorkerID = ""
			j.LeaseUntil = time.Time{}
			j.NextAttemptAt = now
			j.UpdatedAt = now
			recovered++
		}
	}
	return recovered, nil
}

// hold returns the live job pointer when workerID still holds its lease.
func (s *MemoryJobStore) hold(jobID, workerID string, now time.Time) (*Job, error) {
	j, ok := s.jobs[jobID]
	if !ok {
		return nil, ErrNotFound
	}
	if j.Status != JobProcessing || j.WorkerID != workerID {
		return nil, ErrLeaseLost
	}
	if j.LeaseUntil.Before(now) {
		return nil, ErrLeaseLost
	}
	return j, nil
}

// SaveCheckpoint implements JobStore: guarded mutation plus lease renewal
// (checkpoint = progress = renewal; a non-positive leaseTTL is a no-op
// renewal, see the interface contract).
func (s *MemoryJobStore) SaveCheckpoint(_ context.Context, jobID, workerID string, leaseTTL time.Duration, cp Checkpoint, confirmed FamilyCounts) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	j, err := s.hold(jobID, workerID, now)
	if err != nil {
		return err
	}
	j.Checkpoint = cp
	j.Confirmed = confirmed.Clone()
	if leaseTTL > 0 {
		j.LeaseUntil = now.Add(leaseTTL)
	}
	j.UpdatedAt = now
	return nil
}

// ReleaseForRetry implements JobStore.
func (s *MemoryJobStore) ReleaseForRetry(_ context.Context, jobID, workerID string, nextAttempt time.Time, lastErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.hold(jobID, workerID, s.now())
	if err != nil {
		return err
	}
	j.Status = JobPending
	j.WorkerID = ""
	j.LeaseUntil = time.Time{}
	j.NextAttemptAt = nextAttempt
	j.LastError = lastErr
	j.UpdatedAt = s.now()
	return nil
}

// Finalize implements JobStore.
func (s *MemoryJobStore) Finalize(_ context.Context, jobID, workerID string, status JobStatus, confirmed FamilyCounts, refusal *Refusal, lastErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.hold(jobID, workerID, s.now())
	if err != nil {
		return err
	}
	j.Status = status
	j.Confirmed = confirmed.Clone()
	j.Refusal = refusal
	j.LastError = lastErr
	j.LeaseUntil = time.Time{}
	now := s.now()
	j.CompletedAt = now
	j.UpdatedAt = now
	return nil
}

// RequestCancel implements JobStore (org-scoped, terminal-refusing).
func (s *MemoryJobStore) RequestCancel(_ context.Context, orgID, jobID string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok || j.OrgID != orgID {
		return ErrNotFound
	}
	if j.Status.Terminal() {
		return ErrJobTerminal
	}
	j.CancelRequested = at
	j.UpdatedAt = s.now()
	return nil
}
