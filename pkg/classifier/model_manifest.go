// Package classifier documents distribution provenance for the models served
// by the ml_v1 classification service.
package classifier

import (
	"errors"
	"fmt"
	"strings"
)

// ModelManifest records the distribution provenance of one model: where its
// weights come from, the exact revision and digest that were verified, the
// license and acceptable-use dispositions, and the upstream-declared training
// data grounds. Entries without confirmed rights must not enter a
// distribution.
type ModelManifest struct {
	// ID is the stable identifier of the model, normally its upstream
	// repository id.
	ID string
	// Repo is the upstream repository URL.
	Repo string
	// Revision is the pinned 40-hex git commit of the upstream repository.
	// Floating refs (e.g. "main") are not acceptable.
	Revision string
	// SHA256 is the 64-hex sha256 digest of the verified weights file.
	SHA256 string
	// License is the recorded license of the model.
	License string
	// LicenseURL points at the license text or the upstream license
	// declaration.
	LicenseURL string
	// AUPURL points at an applicable acceptable-use policy, if one is
	// published.
	AUPURL string
	// Datasets lists the upstream-declared training-data grounds, or states
	// that no data is used.
	Datasets []string
	// Note records verification date and any explicit dispositions.
	Note string
}

// ModelProvenance returns the provenance manifest of the ml_v1 classifier
// service: BAAI/bge-small-en-v1.5 encoder weights served with a locally built
// 3-class head (deploy/classifier).
func ModelProvenance() ModelManifest {
	return ModelManifest{
		ID:         "BAAI/bge-small-en-v1.5",
		Repo:       "https://huggingface.co/BAAI/bge-small-en-v1.5",
		Revision:   "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
		SHA256:     "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad",
		License:    "MIT",
		LicenseURL: "https://github.com/FlagOpen/FlagEmbedding/blob/master/LICENSE",
		AUPURL:     "https://huggingface.co/acceptable-use-policy",
		Datasets: []string{
			"upstream model card: RetroMAE pre-training plus large-scale pairs data (contrastive learning); corpus inventory published in the FlagEmbedding baai_general_embedding README",
			"MTEB evaluation datasets referenced by the model card (benchmark only, not shipped)",
			"no training data is bundled in this repository",
		},
		Note: "Revision and model.safetensors sha256 pinned from the HuggingFace API on 2026-10-12; the repo publishes no LICENSE file, the card declares MIT and cites the FlagEmbedding license above; publisher publishes no model-specific AUP, the HuggingFace hub Acceptable Use Policy applies to hub downloads. The ml_v1 service (pkg/classifier/ml_v1.go) serves these encoder weights with a locally built 3-class head: deploy/classifier/Dockerfile copies artifacts/classifier-v1.pt or falls back to the deterministic head in deploy/classifier/generate_fallback.py; a trained checkpoint must ship with its own digest and training-data provenance before distribution.",
	}
}

// Validate reports whether the manifest records confirmed distribution
// rights: a pinned revision, a verified weights digest, a license, and an
// acceptable-use disposition. All problems are reported together.
func (m ModelManifest) Validate() error {
	var problems []string
	if strings.TrimSpace(m.ID) == "" {
		problems = append(problems, "model id is empty")
	}
	if strings.TrimSpace(m.Repo) == "" {
		problems = append(problems, "repo is empty")
	}
	if !isHexN(m.Revision, 40) {
		problems = append(problems, fmt.Sprintf("revision must be a pinned 40-hex git commit, got %q (floating refs like %q are rejected)", m.Revision, "main"))
	}
	if !isHexN(m.SHA256, 64) {
		problems = append(problems, "sha256 digest of the model weights is unknown or not a 64-hex value")
	}
	if strings.TrimSpace(m.License) == "" {
		problems = append(problems, "license is unconfirmed (not recorded)")
	}
	if !aupDispositionRecorded(m) {
		problems = append(problems, "acceptable-use policy disposition missing: record AUPURL or state in Note that the publisher publishes no model-specific AUP")
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

func isHexN(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func aupDispositionRecorded(m ModelManifest) bool {
	if strings.TrimSpace(m.AUPURL) != "" {
		return true
	}
	note := strings.ToLower(m.Note)
	return strings.Contains(note, "no aup") ||
		strings.Contains(note, "no acceptable use policy") ||
		strings.Contains(note, "no model-specific aup")
}
