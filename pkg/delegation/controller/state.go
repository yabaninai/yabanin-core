// Package controller implements the NEXT-08 episode controller: persistent
// state, a cross-process lease with generation fencing, and idempotent
// step-by-step execution over the existing delegation.Executor interface
// (FakeExecutor in tests — never a paid agent API).
//
// It COMPOSES with pkg/delegation: it does not replace or wrap the live
// Orchestrator, which keeps serving the MCP bridge unchanged.
package controller

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/reireirei/yabanin/pkg/delegation"
)

// Schema version of the on-disk episode file.
const stateSchemaVersion = 1

// EpisodeState is the lifecycle state of a delegated episode.
type EpisodeState string

// Episode lifecycle states. The pending/running/awaiting_review trio is
// live; done/failed/canceled are terminal (see EpisodeState.Terminal).
const (
	StatePending  EpisodeState = "pending"
	StateRunning  EpisodeState = "running"
	StateAwaiting EpisodeState = "awaiting_review"
	StateDone     EpisodeState = "done"
	StateFailed   EpisodeState = "failed"
	StateCanceled EpisodeState = "canceled"
)

// Terminal reports whether no further transitions are possible.
func (s EpisodeState) Terminal() bool {
	switch s {
	case StateDone, StateFailed, StateCanceled:
		return true
	}
	return false
}

// allowedTransitions is the full transition graph. Any edge not listed is
// rejected — the controller never invents lifecycle moves.
var allowedTransitions = map[EpisodeState][]EpisodeState{
	StatePending:  {StateRunning, StateCanceled},
	StateRunning:  {StateAwaiting, StateDone, StateFailed, StateCanceled},
	StateAwaiting: {StateDone, StateCanceled},
	StateDone:     {},
	StateFailed:   {},
	StateCanceled: {},
}

// CanTransition reports whether from → to is permitted.
func CanTransition(from, to EpisodeState) bool {
	for _, t := range allowedTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}

// Lease grants exclusive episode ownership to one controller process.
// Generation fences stale writers: any save whose lease generation is older
// than the on-disk one is rejected, so a crashed-and-resumed controller can
// never overwrite the successor's state.
type Lease struct {
	Holder     string    `json:"holder"`
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Expired reports whether the lease is no longer valid at t.
func (l *Lease) Expired(t time.Time) bool {
	return l == nil || !t.Before(l.ExpiresAt)
}

// StepRecord is one numbered, idempotent execution step.
type StepRecord struct {
	Index      int                `json:"index"`
	Name       string             `json:"name"`
	Status     string             `json:"status"` // pending | done | failed
	Result     *delegation.Result `json:"result,omitempty"`
	Error      string             `json:"error,omitempty"`
	StartedAt  time.Time          `json:"started_at,omitempty"`
	FinishedAt time.Time          `json:"finished_at,omitempty"`
}

// Episode is the persistent controller state for one delegated task.
type Episode struct {
	SchemaVersion int                     `json:"schema_version"`
	ID            string                  `json:"id"`
	Task          string                  `json:"task"`
	Mode          delegation.Mode         `json:"mode"`
	Provider      delegation.ProviderName `json:"provider"`
	State         EpisodeState            `json:"state"`
	Steps         []StepRecord            `json:"steps"`
	CurrentStep   int                     `json:"current_step"`
	Lease         *Lease                  `json:"lease,omitempty"`
	Generation    int64                   `json:"generation"` // monotonically bumped per save
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	FinalResult   *delegation.Result      `json:"final_result,omitempty"`
	CancelReason  string                  `json:"cancel_reason,omitempty"`
	// NEXT-12: the review decision that closed an awaiting_review episode.
	// Actor/time/state-hash make the approval auditable; the hash pins WHAT
	// the reviewer actually saw.
	Review *ReviewRecord `json:"review,omitempty"`
}

// NextPendingStep returns the first step not yet done, or -1.
func (e *Episode) NextPendingStep() int {
	for i := range e.Steps {
		if e.Steps[i].Status != "done" {
			return i
		}
	}
	return -1
}

// ErrFenced is returned when a writer's view is older than the on-disk state.
var ErrFenced = errors.New("episode state was modified by a newer controller (fenced)")

// ErrTransition is returned for lifecycle moves outside the graph.
var ErrTransition = errors.New("invalid episode state transition")

// ReviewRecord captures an approve/reject decision with full provenance.
type ReviewRecord struct {
	Decision  string    `json:"decision"` // approved | rejected
	Actor     string    `json:"actor"`
	At        time.Time `json:"at"`
	StateSHA  string    `json:"state_sha256"`
	RegistryS string    `json:"registry_sha256,omitempty"`
	Note      string    `json:"note,omitempty"`
}

// ErrLeaseHeld is returned when a live lease belongs to someone else.
var ErrLeaseHeld = errors.New("episode lease is held by another controller")

// Store persists one episode per JSON file under dir, atomically (tmp+rename).
// Cross-process safety = lease + generation fencing on every save.
type Store struct {
	dir string
	now func() time.Time
}

// NewStore returns a store rooted at dir (created if missing).
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("state dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}
	return &Store{dir: dir, now: time.Now}, nil
}

func (s *Store) path(id string) string {
	return filepath.Join(s.dir, "episode-"+sanitizeID(id)+".json")
}

// lockPath is the per-episode sidecar lock file. It never collides with the
// episode file itself (different suffix), so directory scans that filter on
// the ".json" suffix (Load, trcli delegate) are unaffected.
func (s *Store) lockPath(id string) string {
	return filepath.Join(s.dir, "episode-"+sanitizeID(id)+".lock")
}

// lockEpisode takes the per-episode cross-process flock and returns the
// unlock closure. LOCK_EX is blocking: a competing writer (e.g. a successor
// controller's takeover commit) waits microseconds for the current writer's
// SaveFenced to finish instead of interleaving with it.
func (s *Store) lockEpisode(id string) (func(), error) {
	fh, err := os.OpenFile(s.lockPath(id), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open episode lock: %w", err)
	}
	if err := flockEx(fh); err != nil {
		_ = fh.Close()
		return nil, fmt.Errorf("lock episode: %w", err)
	}
	return func() {
		_ = funlock(fh)
		_ = fh.Close()
	}, nil
}

func sanitizeID(id string) string {
	out := make([]rune, 0, len(id))
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// Load reads the episode; absent file returns os.ErrNotExist as-is.
func (s *Store) Load(id string) (*Episode, error) {
	raw, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var e Episode
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("corrupt episode %s: %w", id, err)
	}
	if e.SchemaVersion != stateSchemaVersion {
		return nil, fmt.Errorf("episode %s: unsupported schema version %d", id, e.SchemaVersion)
	}
	return &e, nil
}

// SaveFenced atomically persists e, rejecting the write when the on-disk
// generation has advanced beyond e.Generation (stale writer / fencing) or
// the live lease belongs to a different holder.
//
// The generation check alone is NOT sufficient: it compares a snapshot read
// before the rename, so two writers can both pass it from the same base
// generation and both commit G+1 — the second rename silently erases the
// first (TP16 mode-1: a takeover commit landing inside a predecessor's
// read-modify-write span was lost, leaving the orphaned executor running).
// A per-episode flock closes that read-check-write race: writers serialize
// on the sidecar lock, so the loser's check runs against the winner's
// committed state and fails with ErrFenced.
//
// Lock hierarchy: this episode flock is a LEAF lock. It is taken only here,
// never while another lock is held, and nothing else locks it, so there are
// no cycles. It serializes only SaveFenced callers (in-process callers are
// already serialized by Controller's episodeMu; the flock covers distinct
// processes and distinct Store instances on the same directory). Load needs
// no lock — the rename makes it an atomic snapshot read. Raw writers that
// bypass SaveFenced (test harnesses) keep no flock-backed invariants unless
// they hold this lock themselves while writing and verifying.
func (s *Store) SaveFenced(e *Episode, holder string) error {
	unlock, err := s.lockEpisode(e.ID)
	if err != nil {
		return err
	}
	defer unlock()

	onDisk, err := s.Load(e.ID)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		onDisk = nil
	default:
		return fmt.Errorf("fencing read: %w", err)
	}
	if onDisk != nil && onDisk.Generation > e.Generation {
		return ErrFenced
	}
	if onDisk != nil && onDisk.Lease != nil && !onDisk.Lease.Expired(s.now()) &&
		onDisk.Lease.Holder != holder && holder != "" {
		return ErrLeaseHeld
	}
	e.Generation++
	e.UpdatedAt = s.now()
	raw, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return fmt.Errorf("encode episode: %w", err)
	}
	tmp := s.path(e.ID) + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write tmp state: %w", err)
	}
	if err := os.Rename(tmp, s.path(e.ID)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("commit state: %w", err)
	}
	return nil
}

// Transition validates from → to and applies it (caller saves).
func (e *Episode) Transition(to EpisodeState) error {
	if !CanTransition(e.State, to) {
		return fmt.Errorf("%w: %s -> %s", ErrTransition, e.State, to)
	}
	e.State = to
	return nil
}

// AcquireLease takes the episode lease for holder if free or expired.
// A live foreign lease returns ErrLeaseHeld. Taking over an expired lease
// bumps the lease generation, fencing the crashed predecessor.
func (s *Store) AcquireLease(e *Episode, holder string, ttl time.Duration) error {
	now := s.now()
	if e.Lease != nil && !e.Lease.Expired(now) && e.Lease.Holder != holder {
		return ErrLeaseHeld
	}
	gen := int64(0)
	if e.Lease != nil {
		gen = e.Lease.Generation
		if e.Lease.Expired(now) {
			gen++ // takeover fences the stale holder
		}
	}
	e.Lease = &Lease{Holder: holder, Generation: gen, ExpiresAt: now.Add(ttl)}
	return s.SaveFenced(e, holder)
}

// RenewLease extends the episode's lease for its current holder.
func (s *Store) RenewLease(e *Episode, ttl time.Duration) error {
	if e.Lease == nil {
		return fmt.Errorf("no lease to renew")
	}
	e.Lease.ExpiresAt = s.now().Add(ttl)
	return s.SaveFenced(e, e.Lease.Holder)
}

// ReleaseLease clears the lease (terminal states keep it nil).
func (s *Store) ReleaseLease(e *Episode) error {
	e.Lease = nil
	return s.SaveFenced(e, "")
}
