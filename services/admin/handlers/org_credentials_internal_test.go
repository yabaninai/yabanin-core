package handlers

// W-BYOK-API: the credentialProviders whitelist must stay a subset of the
// pkg/provider factory. The whitelist is declared locally (instead of calling
// provider.New at validation time) because the factory CONSTRUCTS adapters —
// NewSber reads env and loads an mTLS keypair from disk, a validation-time
// side effect and a false negative when the cert files are absent. This test
// is the drift alarm: a factory rename turns it red.

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/provider"
)

func TestOrgCredentialProvidersMatchFactory(t *testing.T) {
	if len(credentialProviders) == 0 {
		t.Fatal("credentialProviders whitelist is empty")
	}
	for name := range credentialProviders {
		if _, err := provider.New(name); err != nil {
			t.Errorf("whitelisted provider %q is not accepted by the factory: %v", name, err)
		}
	}
	// The empty name maps to the OpenAI adapter in the factory but must stay
	// rejected at the credential boundary: provider is required explicitly.
	if _, err := provider.New(""); err != nil {
		t.Fatalf("factory rejected the empty name unexpectedly: %v", err)
	}
}

// 03 boundary tests for parseModelCatalog (the discovery parse seam).
// The contract: a body that parses into {data[].id} is a display-only
// snapshot (discovered=true, verified=false); EVERYTHING else — truncation,
// wrong shapes, wrong entry types, an over-cap body, a mid-read failure — is
// the models_list_unavailable refusal and never a partial success.

// catalogBodyOfSize builds a valid {data:[{id:…}]} JSON document of exactly
// size bytes (pad absorbed by an ignored extra field), so the cap boundary
// can be probed byte-exactly.
func catalogBodyOfSize(t *testing.T, size int) string {
	t.Helper()
	const prefix = `{"object":"list","data":[{"id":"cap-model","pad":"`
	const suffix = `"}]}`
	if size < len(prefix)+len(suffix) {
		t.Fatalf("catalogBodyOfSize: size %d below the minimum %d", size, len(prefix)+len(suffix))
	}
	body := prefix + strings.Repeat("p", size-len(prefix)-len(suffix)) + suffix
	if len(body) != size {
		t.Fatalf("catalogBodyOfSize: built %d bytes, want %d", len(body), size)
	}
	return body
}

func TestParseModelCatalogBodyCapBoundary(t *testing.T) {
	// Exactly at the 1 MiB cap: read fully, parsed honestly.
	atCap := parseModelCatalog(strings.NewReader(catalogBodyOfSize(t, credCatalogMaxBodyRead)), "openai", "https://api.example-llm.dev/v1", http.StatusOK)
	if !atCap.Discovered || atCap.Reason != "" || atCap.Count != 1 || len(atCap.Data) != 1 || atCap.Data[0] != "cap-model" {
		t.Errorf("body exactly at cap = %+v, want a snapshot with [cap-model]", atCap)
	}
	if atCap.Verified == nil || *atCap.Verified {
		t.Errorf("verified = %v, want an explicit false on the snapshot", atCap.Verified)
	}

	// One byte over the cap: refusal, never a partial success.
	over := parseModelCatalog(strings.NewReader(catalogBodyOfSize(t, credCatalogMaxBodyRead+1)), "openai", "https://api.example-llm.dev/v1", http.StatusOK)
	if over.Discovered || over.Reason != catalogReasonListUnavailable || over.Count != 0 || over.Data != nil {
		t.Errorf("body one byte over cap = %+v, want a models_list_unavailable refusal", over)
	}
	if over.Status != http.StatusOK || over.Error != "" || over.Verified != nil {
		t.Errorf("refusal metadata = %+v, want status passthrough and no error text/verified flag", over)
	}
}

// failAfterReader yields its payload once, then fails the next read — the
// upstream connection died mid-body.
type failAfterReader struct {
	payload []byte
	done    bool
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("connection reset mid-body")
	}
	r.done = true
	return copy(p, r.payload), nil
}

func TestParseModelCatalogTruncatedBody(t *testing.T) {
	t.Run("json cut mid-record under the cap is a refusal, never partial", func(t *testing.T) {
		truncated := `{"object":"list","data":[{"id":"visible-a"},{"id":"cut-mid`
		res := parseModelCatalog(strings.NewReader(truncated), "openai", "https://api.example-llm.dev/v1", http.StatusOK)
		if res.Discovered || res.Reason != catalogReasonListUnavailable || res.Count != 0 || res.Data != nil {
			t.Errorf("truncated body = %+v, want a refusal with no data", res)
		}
		if strings.Contains(res.Error, "cut-mid") {
			t.Error("refusal echoes upstream body content")
		}
	})

	t.Run("mid-read transport failure is a refusal", func(t *testing.T) {
		res := parseModelCatalog(&failAfterReader{payload: []byte(`{"object":"list","data":[{"id":"a"}`)}, "openai", "https://api.example-llm.dev/v1", http.StatusOK)
		if res.Discovered || res.Reason != catalogReasonListUnavailable || res.Count != 0 || res.Data != nil {
			t.Errorf("mid-read failure = %+v, want a refusal with no data", res)
		}
	})
}

func TestParseModelCatalogMalformedEntries(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantFail  bool
		wantCount int
		wantData  []string
	}{
		{"entry without id is skipped, valid ones kept", `{"data":[{"object":"model"},{"id":"real"}]}`, false, 1, []string{"real"}},
		{"empty-string id is skipped", `{"data":[{"id":""},{"id":"real"}]}`, false, 1, []string{"real"}},
		{"numeric id fails the parse", `{"data":[{"id":123}]}`, true, 0, nil},
		{"good entry before a bad one is never a partial success", `{"data":[{"id":"good"},{"id":123}]}`, true, 0, nil},
		{"data as string refuses", `{"data":"nope"}`, true, 0, nil},
		{"data as object refuses", `{"data":{"id":"x"}}`, true, 0, nil},
		{"top-level array refuses", `["a","b"]`, true, 0, nil},
		{"top-level string refuses", `"catalog"`, true, 0, nil},
		{"data null is an honest empty snapshot", `{"data":null}`, false, 0, nil},
		{"absent data is an honest empty snapshot", `{}`, false, 0, nil},
		{"null entry is skipped without a crash", `{"data":[null]}`, false, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := parseModelCatalog(strings.NewReader(tc.body), "openai", "https://api.example-llm.dev/v1", http.StatusOK)
			if tc.wantFail {
				if res.Discovered || res.Reason != catalogReasonListUnavailable || res.Count != 0 || res.Data != nil {
					t.Fatalf("malformed body = %+v, want a models_list_unavailable refusal", res)
				}
				if res.Error != "" {
					t.Errorf("refusal carries error text %q, want none (body never echoed)", res.Error)
				}
				return
			}
			if !res.Discovered || res.Reason != "" || res.Count != tc.wantCount {
				t.Fatalf("body = %+v, want a snapshot with count %d", res, tc.wantCount)
			}
			if len(res.Data) != len(tc.wantData) {
				t.Fatalf("data = %v, want %v", res.Data, tc.wantData)
			}
			for i := range tc.wantData {
				if res.Data[i] != tc.wantData[i] {
					t.Fatalf("data = %v, want %v", res.Data, tc.wantData)
				}
			}
		})
	}
}
