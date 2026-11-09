package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// WorkspaceManager gives each episode an isolated git worktree under root,
// guarded by a cross-process file lock, and inventories the ACTUAL diff
// (git status/diff) rather than executor claims.
//
// NEXT-09 invariants:
//   - a worktree is logical isolation (own checkout + lock), NOT an OS
//     sandbox — executors still run with the operator's privileges;
//   - Remove only ever deletes directories this manager created (marker
//     file); foreign directories are refused, never removed.
type WorkspaceManager struct {
	root       string
	now        func() time.Time
	stateStore *Store // NEXT-11 overlap guard target (nil = no guard)
}

// Workspace is one acquired episode worktree.
type Workspace struct {
	EpisodeID string
	Path      string
	lock      *os.File
	mgr       *WorkspaceManager
}

// markerFile identifies directories created by this manager.
const markerFile = ".yabanin-workspace.json"

// ErrWorkspaceBusy is returned when another process holds the lock.
var ErrWorkspaceBusy = errors.New("workspace is locked by another process")

// ErrNotManagedWorkspace protects foreign directories from Remove.
var ErrNotManagedWorkspace = errors.New("directory is not a yabanin-managed workspace")

type wsMarker struct {
	EpisodeID string    `json:"episode_id"`
	CreatedAt time.Time `json:"created_at"`
	Creator   string    `json:"creator"`
}

// WithStateStore attaches the episode store for the NEXT-11 overlap guard
// (workspace and state trees must be disjoint) and returns the manager for
// chaining.
func (m *WorkspaceManager) WithStateStore(s *Store) *WorkspaceManager {
	m.stateStore = s
	return m
}

// NewWorkspaceManager roots episode worktrees at dir (created if missing).
func NewWorkspaceManager(dir string) (*WorkspaceManager, error) {
	if dir == "" {
		return nil, fmt.Errorf("workspace root is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create workspace root: %w", err)
	}
	return &WorkspaceManager{root: dir, now: time.Now}, nil
}

func (m *WorkspaceManager) pathFor(episodeID string) string {
	return filepath.Join(m.root, "wt-"+sanitizeID(episodeID))
}

// Acquire returns the episode's worktree, creating it (git worktree add from
// the source repo's HEAD) on first use. The flock is held until Release;
// a locked worktree returns ErrWorkspaceBusy instead of waiting.
func (m *WorkspaceManager) Acquire(episodeID, sourceRepo string) (*Workspace, error) {
	// NEXT-11: protected state (evidence/verifier files) must be unreachable
	// from inside the writable workspace — refuse overlapping trees.
	if m.stateStore != nil {
		if err := m.stateStore.EnforceStoreOutsideWorkspace(m.root); err != nil {
			return nil, err
		}
	}
	wsPath := m.pathFor(episodeID)
	lockPath := wsPath + ".lock"

	//nolint:gosec // G304 false positive: lockPath = root + "wt-" + sanitizeID(id);
	// sanitizeID keeps only [A-Za-z0-9_-], no traversal is possible.
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, ErrWorkspaceBusy
	}

	if _, statErr := os.Stat(wsPath); os.IsNotExist(statErr) {
		if err := m.createWorktree(wsPath, sourceRepo); err != nil {
			_ = lock.Close()
			return nil, err
		}
		marker, _ := json.Marshal(wsMarker{
			EpisodeID: episodeID,
			CreatedAt: m.now(),
			Creator:   fmt.Sprintf("pid:%d", os.Getpid()),
		})
		if err := os.WriteFile(filepath.Join(wsPath, markerFile), append(marker, '\n'), 0o600); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("write marker: %w", err)
		}
	}
	return &Workspace{EpisodeID: episodeID, Path: wsPath, lock: lock, mgr: m}, nil
}

func (m *WorkspaceManager) createWorktree(wsPath, sourceRepo string) error {
	if strings.TrimSpace(sourceRepo) == "" {
		return fmt.Errorf("source repo is required to create a worktree")
	}
	abs, err := filepath.Abs(sourceRepo)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	args := append([]string{"-C", abs}, gitConfigArgs...)
	args = append(args, "worktree", "add", "--detach", wsPath, "HEAD")
	//nolint:gosec // G204 false positive: fixed "git" binary, fixed argument
	// shape; wsPath is sanitized (see sanitizeID) and abs is operator-supplied.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = ScrubbedEnv(abs) // NEXT-11: allowlisted env only
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git worktree add: %w: %s", err, truncateOut(boundOutput(out)))
	}
	return nil
}

// Diff inventories the ACTUAL workspace changes: porcelain status entries
// plus a compact diffstat. Executor claims are never trusted here.
func (w *Workspace) Diff() (changed []string, diffstat string, err error) {
	if _, err := os.Stat(filepath.Join(w.Path, ".git")); err != nil {
		return nil, "", fmt.Errorf("workspace %s is not a git worktree: %w", w.Path, err)
	}
	statusOut, err := gitOutput(w.Path, "status", "--porcelain")
	if err != nil {
		return nil, "", fmt.Errorf("git status: %w", err)
	}
	for _, line := range strings.Split(string(statusOut), "\n") {
		// porcelain v1: "XY <path>" — the two status columns are positional,
		// so the line is NOT trimmed before slicing (a leading space is a
		// meaningful "unchanged in index" marker).
		if len(line) < 4 {
			continue
		}
		path := strings.TrimSpace(line[3:])
		if path == "" || strings.HasSuffix(path, "/"+markerFile) || path == markerFile {
			continue
		}
		// Renames arrive as "old -> new"; the inventory reports the new path.
		if idx := strings.Index(path, "-> "); idx >= 0 {
			path = strings.TrimSpace(path[idx+3:])
		}
		// Quoted paths are unquoted lossily here — sufficient for inventory.
		changed = append(changed, strings.Trim(path, "\""))
	}
	statOut, err := gitOutput(w.Path, "diff", "--stat", "HEAD")
	if err != nil {
		// Untracked-only workspaces have no diff vs HEAD — status is enough.
		// The error is deliberately swallowed WITH a comment (nilerr).
		return changed, "", nil //nolint:nilerr // untracked-only: no diff vs HEAD
	}
	return changed, strings.TrimSpace(string(statOut)), nil
}

func truncateOut(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

func gitOutput(dir string, args ...string) ([]byte, error) {
	// Fixed binary, constant subcommands; dir is the manager's own sanitized
	// workspace path (see sanitizeID) — G204 is a false positive here.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	full := append([]string{"-C", dir}, gitConfigArgs...)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "git", full...) //nolint:gosec // G204 false positive
	cmd.Env = ScrubbedEnv(dir)                      // NEXT-11: allowlisted env only
	out, err := cmd.Output()
	return boundOutput(out), err
}

// Release drops the lock but KEEPS the worktree: episodes resume across
// process restarts.
func (w *Workspace) Release() error {
	if w == nil || w.lock == nil {
		return nil
	}
	err := syscall.Flock(int(w.lock.Fd()), syscall.LOCK_UN)
	closeErr := w.lock.Close()
	w.lock = nil
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}
	return closeErr
}

// Remove deletes the episode worktree — only a marker-carrying directory
// this manager created. Foreign directories are refused (NEXT-09: never
// delete someone else's worktree), and the git worktree metadata is pruned.
func (m *WorkspaceManager) Remove(episodeID string) error {
	wsPath := m.pathFor(episodeID)
	//nolint:gosec // G304 false positive: wsPath is the sanitized manager path.
	markerBytes, err := os.ReadFile(filepath.Join(wsPath, markerFile))
	if err != nil {
		return ErrNotManagedWorkspace
	}
	var marker wsMarker
	if json.Unmarshal(markerBytes, &marker) != nil || marker.EpisodeID != episodeID {
		return ErrNotManagedWorkspace
	}
	if _, err := gitOutput(wsPath, "worktree", "remove", "--force", wsPath); err != nil {
		// Fall back to a plain directory removal when git metadata is gone.
		if err := os.RemoveAll(wsPath); err != nil {
			return fmt.Errorf("remove worktree: %w", err)
		}
	}
	_ = os.Remove(wsPath + ".lock")
	return nil
}
