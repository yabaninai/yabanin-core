package harness

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type harnessState struct {
	Version      int           `json:"version"`
	Transactions []transaction `json:"transactions"`
}

type transaction struct {
	ID        string        `json:"id"`
	Tool      string        `json:"tool"`
	Status    string        `json:"status"`
	CreatedAt string        `json:"created_at"`
	YBVersion string        `json:"yb_version"`
	Changes   []stateChange `json:"changes"`
}

type stateChange struct {
	Path       string  `json:"path"`
	Target     string  `json:"target,omitempty"`
	Existed    bool    `json:"existed"`
	Mode       uint32  `json:"mode"`
	Backup     string  `json:"backup"`
	PreSHA256  string  `json:"pre_sha256"`
	PostSHA256 string  `json:"post_sha256"`
	Managed    Managed `json:"managed"`
}

type backupMeta struct {
	Path    string `json:"path"`
	Target  string `json:"target"`
	Link    string `json:"link,omitempty"`
	Existed bool   `json:"existed"`
	Mode    uint32 `json:"mode"`
}

type recorded struct {
	Path    string
	Target  string
	Existed bool
	Mode    uint32
	Backup  string
	Pre     string
	Post    string
	Managed Managed
}

func (e *Engine) load() (harnessState, error) {
	body, err := e.fs().Read(e.statePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return harnessState{Version: 1}, nil
		}
		return harnessState{}, err
	}
	var state harnessState
	if err := json.Unmarshal(body, &state); err != nil {
		return harnessState{}, err
	}
	return state, nil
}

func (e *Engine) save(state harnessState) error {
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return e.fs().AtomicWrite(e.statePath(), append(body, '\n'), 0o600)
}

func (e *Engine) statePath() string {
	return filepath.Join(e.root(), "state.json")
}

func randRead(b []byte) (int, error) { return rand.Read(b) }
