package controller

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// EpisodeEvidence is the NEXT-10 v2 evidence envelope for a delegated
// episode. It binds the episode state file (by content hash), the protected
// command registry (by content hash), and the outcome — so a reviewer can
// detect ANY post-hoc tampering with either file. Tamper-evidence only:
// no crypto signing by design (the card forbids release signing).
type EpisodeEvidence struct {
	SchemaVersion int          `json:"schema_version"`
	Kind          string       `json:"kind"`
	EpisodeID     string       `json:"episode_id"`
	StateSHA256   string       `json:"state_sha256"`
	Outcome       string       `json:"outcome"`
	StepStatuses  []string     `json:"step_statuses"`
	Registry      *registryRef `json:"command_registry,omitempty"`
	CreatedAt     string       `json:"created_at"`
}

type registryRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// RegistrySHA256 hashes the registry file at path (empty string when the
// file is absent — evidence records absence, never invents a hash).
func RegistrySHA256(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("registry path is empty")
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: operator-supplied repo path, read-only hash
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), nil
}

func statePath(s *Store, id string) string { return s.path(id) }

// WriteEvidence records the evidence envelope for an episode next to its
// state file. Called when the episode reaches a terminal or review state.
// TP-18: a v2 envelope REQUIRES the registry binding — an empty or
// unreadable registry path fails the write instead of silently producing
// unverifiable evidence — and the envelope is written atomically
// (tmp+rename), never half-written.
func (s *Store) WriteEvidence(e *Episode, registryPath string) (*EpisodeEvidence, error) {
	raw, err := os.ReadFile(statePath(s, e.ID))
	if err != nil {
		return nil, fmt.Errorf("read state for evidence: %w", err)
	}
	if registryPath == "" {
		return nil, fmt.Errorf("registry path is required for v2 evidence")
	}
	h, err := RegistrySHA256(registryPath)
	if err != nil {
		return nil, fmt.Errorf("read command registry: %w", err)
	}
	ev := &EpisodeEvidence{
		SchemaVersion: 2,
		Kind:          "delegation_episode",
		EpisodeID:     e.ID,
		StateSHA256:   fmt.Sprintf("%x", sha256.Sum256(raw)),
		Outcome:       string(e.State),
		Registry:      &registryRef{Path: registryPath, SHA256: h},
		CreatedAt:     s.now().UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	for _, st := range e.Steps {
		ev.StepStatuses = append(ev.StepStatuses, st.Status)
	}
	out, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return nil, err
	}
	dst := s.evidencePath(e.ID)
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("write evidence: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("commit evidence: %w", err)
	}
	return ev, nil
}

func (s *Store) evidencePath(id string) string {
	return filepath.Join(s.dir, "evidence-"+sanitizeID(id)+".json")
}

// VerifyEvidence recomputes the state and registry hashes and compares them
// with the recorded envelope. Any mismatch is tampering (or a legitimately
// evolved state file — both must block blind trust, per the card: never
// trust a candidate-modified validator).
// TP-18: verification is all-or-nothing — an empty verifier path, a missing
// registry binding, an unreadable registry, or envelope fields that do not
// match the state they hash all fail; none of them may count as verified.
func (s *Store) VerifyEvidence(id, registryPath string) (*EpisodeEvidence, error) {
	raw, err := os.ReadFile(s.evidencePath(id))
	if err != nil {
		return nil, err
	}
	var ev EpisodeEvidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, fmt.Errorf("corrupt evidence: %w", err)
	}
	if ev.SchemaVersion != 2 {
		return nil, fmt.Errorf("unsupported evidence schema %d", ev.SchemaVersion)
	}
	if registryPath == "" {
		return nil, fmt.Errorf("registry path is required to verify evidence")
	}
	stateRaw, err := os.ReadFile(statePath(s, id))
	if err != nil {
		return nil, fmt.Errorf("state missing: %w", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(stateRaw)); got != ev.StateSHA256 {
		return nil, fmt.Errorf("state file does not match evidence (tampered or evolved)")
	}
	if ev.Registry == nil {
		return nil, fmt.Errorf("evidence is missing the command registry binding")
	}
	got, err := RegistrySHA256(registryPath)
	if err != nil {
		return nil, fmt.Errorf("command registry unreadable: %w", err)
	}
	if got != ev.Registry.SHA256 {
		return nil, fmt.Errorf("command registry does not match evidence")
	}
	// The envelope must describe exactly the state file it hashes: a
	// swapped episode id, outcome or step list is tampering even when the
	// recorded state hash still matches the file on disk.
	var state Episode
	if err := json.Unmarshal(stateRaw, &state); err != nil {
		return nil, fmt.Errorf("state file is not a readable episode: %w", err)
	}
	if ev.Kind != "delegation_episode" {
		return nil, fmt.Errorf("evidence kind %q is not a delegation episode", ev.Kind)
	}
	if ev.EpisodeID != state.ID {
		return nil, fmt.Errorf("evidence episode id %q does not match state %q", ev.EpisodeID, state.ID)
	}
	if ev.Outcome != string(state.State) {
		return nil, fmt.Errorf("evidence outcome %q does not match state %q", ev.Outcome, state.State)
	}
	if len(ev.StepStatuses) != len(state.Steps) {
		return nil, fmt.Errorf("evidence records %d step statuses, state has %d", len(ev.StepStatuses), len(state.Steps))
	}
	for i, st := range ev.StepStatuses {
		if st != state.Steps[i].Status {
			return nil, fmt.Errorf("evidence step %d status %q does not match state %q", i, st, state.Steps[i].Status)
		}
	}
	return &ev, nil
}
