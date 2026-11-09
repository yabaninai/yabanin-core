package provider

import (
	"errors"
	"fmt"
	"strings"
)

// Vertex capability matrix.
//
// Owner decisions this table operationalizes:
//   - I49: native Vertex AI ships with an EXPLICIT model-family, endpoint,
//     region and capability matrix — not "every model Google offers".
//   - I51: a request the matrix does not cover is REJECTED with the precise
//     reason (model / region named); no silent downgrade.
//   - I61: modality requirements are per-model; the matrix columns state what
//     each family actually supports. Families that are not in the matrix
//     (image generation, speech synthesis, audio-generation previews) are
//     precisely rejected until the mapping extends.
//
// The matrix is the release-scope subset of Vertex AI Gemini serving regions
// (documented GA endpoints, conservative): the {location}-aiplatform host
// form plus the "global" and "us"/"eu" multi-region forms. Later cards
// reconcile the list against the live region table; unknown locations fail
// closed here, which is safe: the operator extends the matrix when adding a
// region.
//
// Regions are deliberately coarse and verified per family: gemini-1.5
// predates the global and us/eu multi-region endpoints, so those locations
// must NOT be accepted for the 1.5 families (they would 404 upstream — a
// wrong region must be a gateway-side precise rejection, not an upstream
// error page).

// VertexCapabilities states what an upstream model family provides. The
// struct is a representation surface (packet acceptance: "Vertex
// capabilities представлены по model и region"); capability POLICIES beyond
// the gates in this file belong to later cards (I51 tool-call policies).
type VertexCapabilities struct {
	// Streaming: the family supports :streamGenerateContent upstream.
	Streaming bool
	// Tools: function/tool calling supported upstream.
	Tools bool
	// ImageInput: image parts accepted in generateContent requests.
	ImageInput bool
	// PDFInput: PDF documents accepted as input parts.
	PDFInput bool
	// AudioInput: audio parts (speech transcription/understanding) accepted.
	AudioInput bool
	// ImageGeneration: the family GENERATES images (I61 generation side).
	ImageGeneration bool
	// SpeechSynthesis: the family synthesizes speech output (I61).
	SpeechSynthesis bool
}

// vertexModelFamily is one matrix row: a model-name prefix, the family's
// capabilities and the locations that serve it.
type vertexModelFamily struct {
	// prefix matches the registry model name (the gateway writes the
	// models_registry.model_name into the body's model field before
	// PrepareRequest runs).
	prefix string
	// capabilities is returned by value; callers cannot mutate the matrix.
	capabilities VertexCapabilities
	// locations is the exact accepted location set for the family.
	locations []string
}

// geminiTextCaps is the multimodal-understanding capability set of the
// current Gemini text/chat families (image+PDF+audio input, streaming,
// tools). Image GENERATION and speech SYNTHESIS are different families and
// are intentionally false here (I61: per-model coverage; the generation
// families join the matrix when their request mapping ships).
func geminiTextCaps() VertexCapabilities {
	return VertexCapabilities{
		Streaming:  true,
		Tools:      true,
		ImageInput: true,
		PDFInput:   true,
		AudioInput: true,
	}
}

// vertexGemini2xLocations is the documented GA location set for the Gemini
// 2.x families: the global endpoint, the us/eu multi-regions and the core
// single regions. Conservative release-scope subset — reconciled against
// Google's live region table as regions are verified.
var vertexGemini2xLocations = []string{
	"global", "us", "eu",
	"us-central1", "us-east1", "us-east4", "us-west1",
	"europe-west1", "europe-west3", "europe-west4",
	"asia-east1", "asia-northeast1", "asia-south1", "asia-southeast1",
	"australia-southeast1", "me-central1", "northamerica-northeast1", "southamerica-east1",
}

// vertexGemini15Locations is the 1.5 legacy set: single regions only — the
// global and us/eu multi-region endpoints postdate the 1.5 families.
var vertexGemini15Locations = []string{
	"us-central1", "us-east1", "us-east4", "us-west1",
	"europe-west1", "europe-west3", "europe-west4",
	"asia-east1", "asia-northeast1", "asia-southeast1",
}

// vertexModelMatrix is the release capability matrix. Order matters: the
// FIRST matching prefix wins, so more specific prefixes precede looser ones.
var vertexModelMatrix = []vertexModelFamily{
	{
		prefix:       "gemini-2.5-",
		capabilities: geminiTextCaps(),
		locations:    vertexGemini2xLocations,
	},
	{
		prefix:       "gemini-2.0-",
		capabilities: geminiTextCaps(),
		locations:    vertexGemini2xLocations,
	},
	{
		prefix: "gemini-1.5-",
		capabilities: VertexCapabilities{
			Streaming:  true,
			Tools:      true,
			ImageInput: true,
			PDFInput:   true,
			AudioInput: true,
		},
		locations: vertexGemini15Locations,
	},
}

// vertexLocationRe validation lives in vertex.go (ParseVertexCredentials);
// the matrix check below is the SEMANTIC half (is this location served for
// this family) on top of the syntactic half (is this a well-formed
// location token).

// VertexLookup resolves a model name + location against the capability
// matrix. It returns the family's capabilities or a PRECISE error (I51):
// the error names the rejected model and/or location and the matrix
// boundary — never credentials, never a silent downgrade.
//
// This is the packet acceptance surface: Vertex capabilities are
// represented by model and region.
func VertexLookup(model, location string) (VertexCapabilities, error) {
	model = strings.TrimSpace(model)
	location = strings.TrimSpace(location)
	if model == "" {
		return VertexCapabilities{}, errors.New("vertex: model is required to look up capabilities")
	}
	if location == "" {
		return VertexCapabilities{}, errors.New("vertex: location is required to look up capabilities")
	}
	for _, fam := range vertexModelMatrix {
		if !strings.HasPrefix(model, fam.prefix) {
			continue
		}
		for _, loc := range fam.locations {
			if loc == location {
				return fam.capabilities, nil
			}
		}
		return VertexCapabilities{}, fmt.Errorf(
			"vertex: location %q is not served for model family %q (capability matrix; extend vertexModelMatrix when the region is verified)", location, fam.prefix)
	}
	return VertexCapabilities{}, fmt.Errorf(
		"vertex: model %q is not in the capability matrix (shipped families cover the Gemini text/multimodal generations; extend vertexModelMatrix for more)", model)
}

// vertexHostForLocation maps a validated location to the Vertex endpoint
// host: the global location uses the bare aiplatform host, multi-regions
// and regions use {location}-aiplatform. Callers must have validated the
// location syntactically (ParseVertexCredentials) and semantically
// (VertexLookup) — this function is the single URL-construction source.
func vertexHostForLocation(location string) string {
	if location == "global" {
		return "aiplatform.googleapis.com"
	}
	return location + "-aiplatform.googleapis.com"
}

// VertexEndpoint builds the Vertex AI generateContent endpoint path for the
// validated project/location/model (project and location are baked into the
// URL — /v1/projects/{project}/locations/{location}/…). stream selects
// :streamGenerateContent plus the ?alt=sse query that switches the response
// from a JSON array to one JSON object per SSE data frame — the form the
// translating stream handler consumes.
//
// project and location must already pass ParseVertexCredentials; model must
// be lookup-clean and free of path separators (enforced by
// parseVertexEnvelope). Exported for tests and ops tooling.
func VertexEndpoint(project, location, model string, stream bool) string {
	action := "generateContent"
	if stream {
		action = "streamGenerateContent?alt=sse"
	}
	return "/v1/projects/" + project +
		"/locations/" + location +
		"/publishers/google/models/" + model + ":" + action
}
