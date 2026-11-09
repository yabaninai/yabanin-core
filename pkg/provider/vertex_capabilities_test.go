package provider

// Tests for the Vertex capability matrix and the fail-closed boundaries
// (packet acceptance: "Vertex capabilities представлены по model и region";
// I51: precise rejection, no silent downgrade).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVertexLookupMatrix pins the model × region acceptance surface. The
// OK rows are the packet acceptance examples; the error rows pin the two
// precise rejection classes (unknown family, known family × wrong region).
func TestVertexLookupMatrix(t *testing.T) {
	t.Parallel()

	okCases := []struct {
		model, location string
	}{
		// Gemini 2.5 family: single region + global endpoint.
		{"gemini-2.5-flash", "us-central1"},
		{"gemini-2.5-pro", "global"},
		// Gemini 2.0 family: multi-region endpoints.
		{"gemini-2.0-flash", "eu"},
		{"gemini-2.0-flash-lite", "asia-east1"},
		// Gemini 1.5 family: single regions only (legacy set).
		{"gemini-1.5-pro", "europe-west4"},
		{"gemini-1.5-flash-002", "us-central1"},
	}
	for _, tc := range okCases {
		caps, err := VertexLookup(tc.model, tc.location)
		if err != nil {
			t.Errorf("VertexLookup(%q,%q): unexpected error %v", tc.model, tc.location, err)
			continue
		}
		// geminiTextCaps posture for every shipped family: multimodal
		// understanding yes; generation/synthesis are OTHER families (I61).
		if !caps.Streaming || !caps.Tools || !caps.ImageInput || !caps.PDFInput || !caps.AudioInput {
			t.Errorf("VertexLookup(%q,%q) caps = %+v, want multimodal-understanding set", tc.model, tc.location, caps)
		}
		if caps.ImageGeneration || caps.SpeechSynthesis {
			t.Errorf("VertexLookup(%q,%q) caps = %+v, generation/synthesis must not ride the text-family rows", tc.model, tc.location, caps)
		}
	}

	errCases := []struct {
		model, location, wantErrContains string
	}{
		// 1.5 predates global/us/eu multi-region endpoints — precise
		// gateway-side rejection, not an upstream 404.
		{"gemini-1.5-pro", "global", `location "global" is not served for model family "gemini-1.5-"`},
		{"gemini-1.5-pro", "us", `location "us" is not served for`},
		// Unknown location for a known family.
		{"gemini-2.5-flash", "moon-base1", `location "moon-base1" is not served for`},
		// Unknown family: precise model naming, boundary explanation.
		{"imagen-3.0-generate-001", "us-central1", `model "imagen-3.0-generate-001" is not in the capability matrix`},
		{"veo-2.0-generate-001", "us-central1", "not in the capability matrix"},
		{"", "us-central1", "model is required"},
		{"gemini-2.5-flash", "", "location is required"},
	}
	for _, tc := range errCases {
		_, err := VertexLookup(tc.model, tc.location)
		if err == nil {
			t.Errorf("VertexLookup(%q,%q): want error containing %q, got nil", tc.model, tc.location, tc.wantErrContains)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErrContains) {
			t.Errorf("VertexLookup(%q,%q) error = %q, want containing %q", tc.model, tc.location, err, tc.wantErrContains)
		}
	}
}

func TestVertexEndpointPaths(t *testing.T) {
	t.Parallel()

	cases := []struct {
		project, location, model string
		stream                   bool
		want                     string
	}{
		{
			"api-proj-0001", "us-central1", "gemini-2.0-flash", false,
			"/v1/projects/api-proj-0001/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent",
		},
		{
			// The stream endpoint must carry ?alt=sse: without it Vertex
			// answers a single JSON ARRAY (not SSE frames), which the
			// translating handler cannot parse as an event stream.
			"api-proj-0001", "global", "gemini-2.5-pro", true,
			"/v1/projects/api-proj-0001/locations/global/publishers/google/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
		},
	}
	for _, tc := range cases {
		got := VertexEndpoint(tc.project, tc.location, tc.model, tc.stream)
		if got != tc.want {
			t.Errorf("VertexEndpoint(%q,%q,%q,%v) = %q, want %q", tc.project, tc.location, tc.model, tc.stream, got, tc.want)
		}
	}

	hostCases := []struct{ location, want string }{
		{"global", "aiplatform.googleapis.com"},
		{"us", "us-aiplatform.googleapis.com"},
		{"eu", "eu-aiplatform.googleapis.com"},
		{"us-central1", "us-central1-aiplatform.googleapis.com"},
		{"europe-west4", "europe-west4-aiplatform.googleapis.com"},
	}
	for _, tc := range hostCases {
		if got := vertexHostForLocation(tc.location); got != tc.want {
			t.Errorf("vertexHostForLocation(%q) = %q, want %q", tc.location, got, tc.want)
		}
	}
}

// TestVertexCapsReturnedByValue guards the matrix against mutation through
// the exported lookup (callers get a copy; the matrix stays authoritative).
func TestVertexCapsReturnedByValue(t *testing.T) {
	t.Parallel()

	caps, err := VertexLookup("gemini-2.5-flash", "us-central1")
	if err != nil {
		t.Fatalf("VertexLookup: %v", err)
	}
	caps.Streaming = false
	caps.Tools = false

	again, err := VertexLookup("gemini-2.5-flash", "us-central1")
	if err != nil {
		t.Fatalf("second VertexLookup: %v", err)
	}
	if !again.Streaming || !again.Tools {
		t.Fatalf("matrix mutated through returned value: %+v", again)
	}
}

// TestVertexStreamHandlerNilResponse pins the defensive boundary: a nil
// upstream response never reaches the translating loop.
func TestVertexStreamHandlerNilResponse(t *testing.T) {
	t.Parallel()

	h := NewStreamHandler("vertex", "gemini-2.5-flash")
	rec := httptest.NewRecorder()
	usage, err := h.HandleStream(context.Background(), rec, rec, nil)
	if err == nil {
		t.Fatal("nil upstream response must fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "nil upstream response") {
		t.Fatalf("stream error = %q, want the nil-response boundary", err)
	}
	if usage != (Usage{}) {
		t.Fatalf("stream error must yield zero usage, got %+v", usage)
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("stream handler wrote %d bytes before failing: %q", rec.Body.Len(), rec.Body.String())
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status write: %d", rec.Code)
	}
}

// TestVertexStreamHandlerScopedToVertex guards the additive stream.go wiring:
// other providers keep their handlers (the vertex handler must not leak).
func TestVertexStreamHandlerScopedToVertex(t *testing.T) {
	t.Parallel()

	if _, isVertex := NewStreamHandler("vertex", "m").(vertexStreamTerminator); !isVertex {
		t.Fatal("vertex must resolve to the vertex stream handler")
	}
	if h := NewStreamHandler("openai", "gpt-4o"); isVertexTerminator(h) {
		t.Fatal("openai must NOT get the vertex handler")
	}
	if h := NewStreamHandler("", "gpt-4o"); isVertexTerminator(h) {
		t.Fatal("default provider must NOT get the vertex handler")
	}
}

func isVertexTerminator(h StreamHandler) bool {
	_, ok := h.(vertexStreamTerminator)
	return ok
}
