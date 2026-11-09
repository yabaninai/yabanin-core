package harness

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ChangeKind is edit or create.
type ChangeKind string

// Change kinds recorded on a plan.
const (
	KindEdit   ChangeKind = "edit"
	KindCreate ChangeKind = "create"
)

// Managed records what a transaction owns inside a file.
type Managed struct {
	Blocks         []string       `json:"blocks"`
	CommentedLines []string       `json:"commented_lines"`
	JSONPaths      []string       `json:"json_paths"`
	PrevValues     map[string]any `json:"prev_values"`
}

// Change is one planned file edit. Validate runs on After before the write.
type Change struct {
	Path     string
	Kind     ChangeKind
	Before   []byte
	After    []byte
	Managed  Managed
	Validate func([]byte) error
}

// Plan is a set of changes for one tool.
type Plan struct {
	Tool     string
	Changes  []Change
	Warnings []string
}

// Engine applies and rolls back harness plans under Home/.yabanin/harness.
type Engine struct {
	Home    string
	Now     func() time.Time
	Version string
	FS      FS
}

// Report is the result of a rollback.
type Report struct {
	Tool   string
	Status string
	Files  []FileReport
}

// FileReport is one file in a rollback.
type FileReport struct {
	Path   string
	Action string
	Err    string
}

// ToolStatus is the latest transaction for a tool plus drift.
type ToolStatus struct {
	Tool   string
	Status string
	Drift  bool
}

// UnapplyFunc surgically removes managed edits when the file was changed by hand.
type UnapplyFunc func(path string, current []byte, m Managed) ([]byte, error)

var errLockBusy = errors.New("another yb harness is running")

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

func (e *Engine) version() string {
	if e.Version != "" {
		return e.Version
	}
	return "yb 0.1.0"
}

func (e *Engine) fs() FS {
	if e.FS != nil {
		return e.FS
	}
	return osFS{}
}

func (e *Engine) root() string {
	return filepath.Join(e.Home, ".yabanin", "harness")
}

// Apply writes the plan. A mismatch with Before or a write error restores earlier files and records nothing.
func (e *Engine) Apply(p Plan) (string, error) {
	if err := os.MkdirAll(e.root(), 0o700); err != nil {
		return "", err
	}
	release, err := acquireLock(filepath.Join(e.root(), ".lock"))
	if err != nil {
		return "", err
	}
	defer release()
	txID := e.now().UTC().Format("20060102T150405Z") + "-" + randomSuffix()
	var done []recorded
	for i, change := range p.Changes {
		if err := e.matchesBefore(change); err != nil {
			e.restoreAll(done)
			return "", err
		}
		if change.Validate != nil {
			if err := change.Validate(change.After); err != nil {
				e.restoreAll(done)
				return "", err
			}
		}
		rec, err := e.writeChange(txID, i, change)
		if err != nil {
			e.restoreAll(done)
			_ = os.RemoveAll(filepath.Join(e.root(), "backups", txID))
			return "", err
		}
		done = append(done, rec)
	}
	if err := e.commit(txID, p.Tool, done); err != nil {
		e.restoreAll(done)
		return "", err
	}
	return txID, nil
}

func (e *Engine) matchesBefore(change Change) error {
	current, err := e.fs().Read(change.Path)
	missing := errors.Is(err, os.ErrNotExist)
	if err != nil && !missing {
		return err
	}
	if change.Before == nil {
		if !missing {
			return fmt.Errorf("file changed since planning: %s", change.Path)
		}
		return nil
	}
	if missing || hash(current) != hash(change.Before) {
		return fmt.Errorf("file changed since planning: %s", change.Path)
	}
	return nil
}

func (e *Engine) writeChange(txID string, index int, change Change) (recorded, error) {
	link, target, err := resolveWritePath(e.fs(), change.Path)
	if err != nil {
		return recorded{}, err
	}
	current, err := e.fs().Read(target)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return recorded{}, err
	}
	mode := os.FileMode(0o600)
	if existed {
		if info, statErr := e.fs().Stat(target); statErr == nil {
			mode = info.Mode().Perm()
		}
	}
	backup := filepath.Join(e.root(), "backups", txID, fmt.Sprintf("%d.orig", index))
	if err := e.fs().AtomicWrite(backup, current, 0o600); err != nil {
		return recorded{}, err
	}
	meta := backupMeta{Path: change.Path, Target: target, Link: link, Existed: existed, Mode: uint32(mode)}
	metaBody, err := json.Marshal(meta)
	if err != nil {
		return recorded{}, err
	}
	if err := e.fs().AtomicWrite(backup+".meta.json", metaBody, 0o600); err != nil {
		return recorded{}, err
	}
	if err := e.fs().AtomicWrite(target, change.After, mode); err != nil {
		return recorded{}, err
	}
	return recorded{
		Path: change.Path, Target: target, Existed: existed, Mode: uint32(mode),
		Backup: backup, Pre: hash(current), Post: hash(change.After), Managed: change.Managed,
	}, nil
}

func (e *Engine) restoreAll(done []recorded) {
	for i := len(done) - 1; i >= 0; i-- {
		rec := done[i]
		if !rec.Existed {
			_ = e.fs().Remove(rec.Target)
			continue
		}
		body, err := e.fs().Read(rec.Backup)
		if err != nil {
			continue
		}
		_ = e.fs().AtomicWrite(rec.Target, body, os.FileMode(rec.Mode))
	}
}

func (e *Engine) commit(txID, tool string, done []recorded) error {
	state, err := e.load()
	if err != nil {
		return err
	}
	tx := transaction{
		ID: txID, Tool: tool, Status: "applied",
		CreatedAt: e.now().UTC().Format(time.RFC3339), YBVersion: e.version(),
	}
	for _, rec := range done {
		tx.Changes = append(tx.Changes, stateChange{
			Path: rec.Path, Target: rec.Target, Existed: rec.Existed, Mode: rec.Mode,
			Backup: rec.Backup, PreSHA256: rec.Pre, PostSHA256: rec.Post, Managed: rec.Managed,
		})
	}
	state.Version = 1
	state.Transactions = append(state.Transactions, tx)
	return e.save(state)
}

// Rollback undoes the latest applied transaction for tool.
func (e *Engine) Rollback(tool string, unapply UnapplyFunc) (Report, error) {
	if err := os.MkdirAll(e.root(), 0o700); err != nil {
		return Report{}, err
	}
	release, err := acquireLock(filepath.Join(e.root(), ".lock"))
	if err != nil {
		return Report{}, err
	}
	defer release()
	state, err := e.load()
	if err != nil {
		return Report{}, err
	}
	idx := -1
	for i := len(state.Transactions) - 1; i >= 0; i-- {
		if state.Transactions[i].Tool == tool && state.Transactions[i].Status == "applied" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Report{}, fmt.Errorf("no applied transaction for %s", tool)
	}
	tx := state.Transactions[idx]
	report := Report{Tool: tool}
	conflicts := 0
	for i := len(tx.Changes) - 1; i >= 0; i-- {
		ch := tx.Changes[i]
		target := ch.Target
		if target == "" {
			target = ch.Path
		}
		current, err := e.fs().Read(target)
		missing := errors.Is(err, os.ErrNotExist)
		if err != nil && !missing {
			report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "conflict", Err: err.Error()})
			conflicts++
			continue
		}
		if !missing && hash(current) == ch.PostSHA256 {
			if err := e.exactRestore(target, ch); err != nil {
				report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "conflict", Err: err.Error()})
				conflicts++
				continue
			}
			action := "restored"
			if !ch.Existed {
				action = "removed"
			}
			report.Files = append(report.Files, FileReport{Path: ch.Path, Action: action})
			continue
		}
		if unapply == nil {
			report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "conflict", Err: "file changed and no unapply"})
			conflicts++
			continue
		}
		next, err := unapply(ch.Path, current, ch.Managed)
		if err != nil {
			report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "conflict", Err: err.Error()})
			conflicts++
			continue
		}
		if err := e.fs().AtomicWrite(target, next, os.FileMode(ch.Mode)); err != nil {
			report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "conflict", Err: err.Error()})
			conflicts++
			continue
		}
		report.Files = append(report.Files, FileReport{Path: ch.Path, Action: "unapplied"})
	}
	if conflicts == 0 {
		tx.Status = "rolled_back"
	} else if conflicts == len(tx.Changes) {
		tx.Status = "applied"
	} else {
		tx.Status = "partially_rolled_back"
	}
	if conflicts < len(tx.Changes) {
		state.Transactions[idx] = tx
		if err := e.save(state); err != nil {
			return report, err
		}
	}
	report.Status = tx.Status
	return report, nil
}

func (e *Engine) exactRestore(target string, ch stateChange) error {
	if !ch.Existed {
		return e.fs().Remove(target)
	}
	body, err := e.fs().Read(ch.Backup)
	if err != nil {
		return err
	}
	mode := os.FileMode(ch.Mode)
	if mode == 0 {
		mode = 0o600
	}
	return e.fs().AtomicWrite(target, body, mode)
}

// Status reports the latest transaction of each tool and whether an applied file drifted.
func (e *Engine) Status() ([]ToolStatus, error) {
	state, err := e.load()
	if err != nil {
		return nil, err
	}
	latest := map[string]int{}
	for i, tx := range state.Transactions {
		latest[tx.Tool] = i
	}
	var out []ToolStatus
	for tool, idx := range latest {
		tx := state.Transactions[idx]
		drift := false
		if tx.Status == "applied" {
			for _, ch := range tx.Changes {
				target := ch.Target
				if target == "" {
					target = ch.Path
				}
				body, err := e.fs().Read(target)
				if err != nil || hash(body) != ch.PostSHA256 {
					drift = true
					break
				}
			}
		}
		out = append(out, ToolStatus{Tool: tool, Status: tx.Status, Drift: drift})
	}
	return out, nil
}

func hash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func randomSuffix() string {
	var buf [3]byte
	_, _ = randRead(buf[:])
	return hex.EncodeToString(buf[:])
}
