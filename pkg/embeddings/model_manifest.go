// Package embeddings documents distribution provenance for the embedding
// models this package is allowed to address by name.
package embeddings

import (
	"errors"
	"fmt"
	"strings"
)

// ModelManifest records the distribution provenance of one embedding model:
// where its weights come from, the exact revision and digest that were
// verified, the license and acceptable-use dispositions, and the
// upstream-declared training-data grounds. Entries without confirmed rights
// must not enter a distribution.
type ModelManifest struct {
	// ID is the model id as used in Config.Model, matching the upstream
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

const hubAUPURL = "https://huggingface.co/acceptable-use-policy"

var modelManifests = map[string]ModelManifest{
	"BAAI/bge-small-en-v1.5": {
		ID:         "BAAI/bge-small-en-v1.5",
		Repo:       "https://huggingface.co/BAAI/bge-small-en-v1.5",
		Revision:   "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a",
		SHA256:     "3c9f31665447c8911517620762200d2245a2518d6e7208acc78cd9db317e21ad",
		License:    "MIT",
		LicenseURL: "https://github.com/FlagOpen/FlagEmbedding/blob/master/LICENSE",
		AUPURL:     hubAUPURL,
		Datasets: []string{
			"upstream model card: RetroMAE pre-training plus large-scale pairs data (contrastive learning); corpus inventory published in the FlagEmbedding baai_general_embedding README",
			"MTEB evaluation datasets referenced by the model card (benchmark only, not shipped)",
			"no training data is bundled in this repository",
		},
		Note: "Revision and model.safetensors sha256 pinned from the HuggingFace API on 2026-10-12; the repo publishes no LICENSE file, the card declares MIT and cites the FlagEmbedding license above; publisher publishes no model-specific AUP, the HuggingFace hub Acceptable Use Policy applies to hub downloads.",
	},
	"Xenova/bge-small-en-v1.5": {
		ID:         "Xenova/bge-small-en-v1.5",
		Repo:       "https://huggingface.co/Xenova/bge-small-en-v1.5",
		Revision:   "ea104dacec62c0de699686887e3f920caeb4f3e3",
		SHA256:     "828e1496d7fabb79cfa4dcd84fa38625c0d3d21da474a00f08db0f559940cf35",
		License:    "MIT (inherited from base model BAAI/bge-small-en-v1.5; conversion repo publishes no LICENSE file)",
		LicenseURL: "https://huggingface.co/BAAI/bge-small-en-v1.5",
		AUPURL:     hubAUPURL,
		Datasets: []string{
			"none — ONNX weight conversion of base_model BAAI/bge-small-en-v1.5; no additional training data",
		},
		Note: "Revision and onnx/model.onnx (float32, the file served by text-embeddings-inference) sha256 pinned from the HuggingFace API on 2026-10-12; the conversion repo publishes no LICENSE file and no model-specific AUP, rights derive from the MIT base model and the HuggingFace hub Acceptable Use Policy applies to hub downloads.",
	},
	"intfloat/multilingual-e5-small": {
		ID:         "intfloat/multilingual-e5-small",
		Repo:       "https://huggingface.co/intfloat/multilingual-e5-small",
		Revision:   "614241f622f53c4eeff9890bdc4f31cfecc418b3",
		SHA256:     "1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477",
		License:    "MIT",
		LicenseURL: "https://huggingface.co/intfloat/multilingual-e5-small/blob/main/README.md",
		AUPURL:     hubAUPURL,
		Datasets: []string{
			"weak-supervision stage (upstream card Training Details): filtered mC4, CC News, NLLB, Wikipedia, filtered Reddit, S2ORC, Stackexchange, xP3, miscellaneous unsupervised SBERT data",
			"supervised stage (upstream card Training Details): MS MARCO, NQ, Trivia QA, NLI from SimCSE, ELI5, DuReader Retrieval, KILT Fever, KILT HotpotQA, SQuAD, Quora, Mr. TyDi, MIRACL (training splits only)",
			"initialised from microsoft/Multilingual-MiniLM-L12-H384",
			"no training data is bundled in this repository",
		},
		Note: "Revision and model.safetensors sha256 pinned from the HuggingFace API on 2026-10-12; the card front matter declares license mit and links no separate LICENSE file; publisher publishes no model-specific AUP, the HuggingFace hub Acceptable Use Policy applies to hub downloads.",
	},
}

// ManifestFor returns the provenance manifest for a model id used in
// Config.Model. Ids are matched exactly. An id with no manifest, or a
// manifest whose rights are not confirmed, is treated the same as unknown
// origin: the package must not enter a distribution.
func ManifestFor(model string) (ModelManifest, error) {
	m, ok := modelManifests[model]
	if !ok {
		return ModelManifest{}, fmt.Errorf("embeddings: model %q has no provenance manifest; unknown origin — package must not enter the distribution", model)
	}
	if err := m.Validate(); err != nil {
		return ModelManifest{}, fmt.Errorf("embeddings: model %q manifest has unconfirmed rights (%v); package must not enter the distribution", model, err)
	}
	return m, nil
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
