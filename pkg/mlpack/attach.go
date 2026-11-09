package mlpack

import (
	"fmt"
	"strings"

	"github.com/reireirei/yabanin/pkg/embeddings"
)

// Attach verifies a pack on disk (manifest provenance, weights presence, sha256 digests) and confirms
// confirmed provenance manifest is unknown origin and must not enter the
// distribution — the same refusal the embedder provenance gate applies to
// distribution defaults. There is deliberately no download path: a pack that
// does not verify simply refuses.
func Attach(dir string) (PackManifest, error) {
	m, err := Verify(dir)
	if err != nil {
		return PackManifest{}, err
	}
	if _, originErr := embeddings.ManifestFor(m.ID); originErr != nil {
		return PackManifest{}, fmt.Errorf("mlpack: pack %q from %q has no confirmed provenance manifest; unknown origin — pack must not enter the distribution (%v)", m.ID, dir, originErr)
	}
	return m, nil
}

// AttachResult is the wiring-facing summary of a successful Attach: the
// verified manifest plus the directory it was verified from.
type AttachResult struct {
	Manifest PackManifest
	Dir      string
}

// AttachDir attaches the pack in dir and returns the verified manifest with
// its resolved directory. Failure is a startup refusal for the caller.
func AttachDir(dir string) (AttachResult, error) {
	if strings.TrimSpace(dir) == "" {
		return AttachResult{}, fmt.Errorf("mlpack: pack dir is empty — set YABANIN_ML_PACK_DIR to a pack directory")
	}
	m, err := Attach(dir)
	if err != nil {
		return AttachResult{}, err
	}
	return AttachResult{Manifest: m, Dir: dir}, nil
}
