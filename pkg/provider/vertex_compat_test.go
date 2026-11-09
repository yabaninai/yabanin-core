package provider

// Vertex AI consumer-compatibility corpus (card N08-P03-T09, packet N08-P03).
//
// The card walks "the old and the new configuration and the real supported
// consumers, with an explicit rejection for unsupported ones". The corpus
// builds on the seams established by T03–T08 (joint rig, ADC chain doubles,
// token recorder) and adds the compatibility surface they do not cover:
//
//  1. Model × region mapping — EVERY shipped (family, location) cell of
//     vertexModelMatrix resolves to the family's capabilities and composes
//     to the exact canonical endpoint URL, and a real consumer turn
//     completes end-to-end on every cell (acceptance: "Vertex capabilities
//     представлены по model и region"). The old (gemini-1.5, single-region)
//     and new (gemini-2.x, global/multi-region) configurations are walked
//     from the live matrix variables, and the gemini-1.5 × multi-region
//     rows the matrix must refuse are DERIVED from the live sets, not
//     copied.
//  2. Envelope shapes — old- and new-generation OpenAI consumers map to
//     IDENTICAL Gemini payloads (stop string vs array, system vs developer
//     role, max_tokens vs max_completion_tokens, string content vs text
//     part).
//  3. Usage shapes — native, translated and omitted usage forms agree
//     under the billing parse (ParseUsage), cached-token details included.
//  4. Auth variants — all three supported ADC configurations (env
//     service-account key, gcloud well-known user file, GCE metadata
//     server) complete the SAME consumer turn with their documented grant
//     shape and a binding-scoped token cache.
//  5. Unsupported consumers — model ids real clients still send
//     (PaLM/gemini-1.0/embedding/MedLM) fail closed at the matrix BEFORE
//     any credential or endpoint work.
//
// Real vs mock split as in the joint corpus: production code paths
// (translators, matrix, ADC chain over a real env var / key file /
// well-known file, real HTTP round-trips); the only doubles are loopback
// token/chat endpoints. Tests that touch process-global env/home seams run
// sequentially; assertions are exact-count and order-stable under -race
// and -shuffle.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// vertexCompatModelsByFamily names the real consumer model ids the corpus
// walks per shipped matrix family. New matrix families must register their
// consumer names here — the compatibility walk fails otherwise, which is
// the point: a family that ships without a walked consumer id is not
// release-verified.
var vertexCompatModelsByFamily = map[string][2]string{
	"gemini-2.5-": {"gemini-2.5-pro", "gemini-2.5-flash"},
	"gemini-2.0-": {"gemini-2.0-flash", "gemini-2.0-flash-lite"},
	"gemini-1.5-": {"gemini-1.5-pro-002", "gemini-1.5-flash-002"},
}

// vertexCompatReply is the upstream Gemini body the compat rigs answer
// with: one STOP candidate, the full usage metadata shape including the
// cached-token field, and an echo model version that must survive
// translation verbatim.
const vertexCompatReply = `{
	"candidates": [{
		"content": {"role": "model", "parts": [{"text": "compat-ok"}]},
		"finishReason": "STOP",
		"index": 0
	}],
	"usageMetadata": {
		"promptTokenCount": 9,
		"candidatesTokenCount": 2,
		"totalTokenCount": 11,
		"cachedContentTokenCount": 3
	},
	"modelVersion": "gemini-compat-echo"
}`

// vertexCompatTurnBody is the consumer request body used in every end-to-end
// turn: a client-side model name that differs from the served one (the
// registry override is part of the real consumer path).
const vertexCompatTurnBody = `{"model":"compat-client-said","messages":[{"role":"user","content":"hi"}]}`

// vertexCompatSentBody is the exact Gemini payload that body must produce
// upstream.
const vertexCompatSentBody = `{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}`

// vertexCompatLocationSet returns the set of locations a family serves
// (the live matrix variables are package-private slices shared by
// reference; copying through the set also proves there are no duplicate
// location entries).
func vertexCompatLocationSet(t *testing.T, locations []string) map[string]struct{} {
	t.Helper()
	set := make(map[string]struct{}, len(locations))
	for _, loc := range locations {
		set[loc] = struct{}{}
	}
	require.Len(t, set, len(locations), "duplicate location in matrix family: %v", locations)
	return set
}

// TestVertexCompat_MatrixModelRegionWalk walks EVERY shipped (model,
// location) cell of the capability matrix:
//
//   - representation: VertexLookup resolves both real consumer ids per
//     family on every family location to exactly the family capabilities
//     (the acceptance surface), and the canonical endpoint URL composes
//     for both the generateContent and the streamGenerateContent action;
//   - rejection: the gemini-1.5 × {global, us, eu} rows are derived from
//     the live location sets and must be refused with the precise reason
//     BEFORE any network or credential work;
//   - end-to-end: one real consumer turn per (walk model, location) cell
//     completes through the production pipeline with per-cell exact paths
//     and bearer tokens, and the binding cache is keyed by (project,
//     location) — model switches inside a location ride the cache.
func TestVertexCompat_MatrixModelRegionWalk(t *testing.T) {
	// Sequential: the joint rig pins GOOGLE_APPLICATION_CREDENTIALS.
	rig := newVertexJointRig(t, vertexCompatReply, "")
	tokens := func() (hits, minted int) { return rig.tokenSrv.snapshot() }

	// ---- Phase A: derived gemini-1.5 × multi-region rejection (no network).
	newGen := map[string]struct{}{}
	var legacy map[string]struct{}
	for i := range vertexModelMatrix {
		fam := &vertexModelMatrix[i]
		if fam.prefix == "gemini-1.5-" {
			legacy = vertexCompatLocationSet(t, fam.locations)
			continue
		}
		for loc := range vertexCompatLocationSet(t, fam.locations) {
			newGen[loc] = struct{}{}
		}
	}
	require.NotNil(t, legacy, "gemini-1.5- family missing from the matrix")
	multiRegion := make(map[string]struct{}, len(newGen))
	for loc := range newGen {
		if _, ok := legacy[loc]; !ok {
			multiRegion[loc] = struct{}{}
		}
	}
	// The 1.5-refused set is exactly today's documented boundary: the
	// global/us/eu multi-region endpoints (they postdate the 1.5 families)
	// PLUS the newer single regions (asia-south1, australia-southeast1,
	// me-central1, northamerica-northeast1, southamerica-east1) that the
	// conservative 1.5 subset predates. Pinning the full derived set keeps
	// the compatibility boundary explicit: extending either family's
	// location list updates this expectation deliberately.
	require.Equal(t, map[string]struct{}{
		"global":                  {},
		"us":                      {},
		"eu":                      {},
		"asia-south1":             {},
		"australia-southeast1":    {},
		"me-central1":             {},
		"northamerica-northeast1": {},
		"southamerica-east1":      {},
	}, multiRegion, "the endpoints the 1.5 families must refuse")
	for _, model := range vertexCompatModelsByFamily["gemini-1.5-"] {
		for loc := range multiRegion {
			_, err := VertexLookup(model, loc)
			require.Error(t, err, "%s@%s must be refused", model, loc)
			require.ErrorContains(t, err, fmt.Sprintf("location %q is not served for model family %q", loc, "gemini-1.5-"))
		}
	}
	hits, minted := tokens()
	require.Zero(t, hits, "rejections must precede any credential work")
	require.Zero(t, minted)

	// ---- Phase B: full representation walk (pure lookup + URL composition).
	//
	// Invariant the E2E walk depends on (and that caught a real drift once):
	// every location the matrix serves must also pass the credentials
	// syntax gate — otherwise VertexLookup accepts a cell that no real
	// consumer can ever reach, because ParseVertexCredentials fails first.
	for i := range vertexModelMatrix {
		for _, loc := range vertexModelMatrix[i].locations {
			_, err := ParseVertexCredentials(fmt.Sprintf(`{"project":"api-proj-0001","location":%q}`, loc))
			require.NoError(t, err, "matrix location %q must pass the credentials syntax gate", loc)
		}
	}
	cells := 0
	for i := range vertexModelMatrix {
		fam := &vertexModelMatrix[i]
		models, ok := vertexCompatModelsByFamily[fam.prefix]
		require.True(t, ok, "compat corpus must register consumer models for family %q", fam.prefix)
		for _, model := range models {
			for _, loc := range vertexCompatLocations(t, fam) {
				caps, err := VertexLookup(model, loc)
				require.NoError(t, err, "%s@%s", model, loc)
				require.Equal(t, fam.capabilities, caps, "%s@%s capabilities", model, loc)
				require.Equal(t, geminiTextCaps(), caps, "%s@%s ships the text/multimodal-understanding posture", model, loc)
				for _, stream := range []bool{false, true} {
					got, err := vertexUpstreamURL("", loc, VertexEndpoint("api-proj-0001", loc, model, stream))
					require.NoError(t, err, "%s@%s stream=%v", model, loc, stream)
					want := "https://" + vertexHostForLocation(loc) +
						"/v1/projects/api-proj-0001/locations/" + loc +
						"/publishers/google/models/" + model
					if stream {
						want += ":streamGenerateContent?alt=sse"
					} else {
						want += ":generateContent"
					}
					require.Equal(t, want, got, "%s@%s stream=%v", model, loc, stream)
				}
				cells++
			}
		}
	}
	require.NotZero(t, cells, "matrix walk found no cells")

	// ---- Phase C: end-to-end consumer turn on every (walk model, location).
	distinctLocations := map[string]struct{}{}
	var wantPaths []string
	for i := range vertexModelMatrix {
		fam := &vertexModelMatrix[i]
		walkModel := vertexCompatModelsByFamily[fam.prefix][0]
		for _, loc := range vertexCompatLocations(t, fam) {
			creds := fmt.Sprintf(`{"project":"api-proj-0001","location":%q}`, loc)
			out, err := rig.chatTurn(t, vertexCompatTurnBody, walkModel, creds)
			require.NoError(t, err, "%s@%s", walkModel, loc)
			assertJointChatCompletion(t, rig.adapter, out, "compat-ok", "gemini-compat-echo", 9, 2, 11, 3)
			wantPaths = append(wantPaths,
				"/v1/projects/api-proj-0001/locations/"+loc+"/publishers/google/models/"+walkModel+":generateContent")
			distinctLocations[loc] = struct{}{}
		}
	}
	reqs := rig.upstream.snapshot()
	require.Len(t, reqs, len(wantPaths))
	for i, req := range reqs {
		require.Equal(t, wantPaths[i], req.path, "request %d: per-cell path", i)
		require.Regexp(t, `^Bearer JT-[1-9][0-9]*$`, req.auth, "request %d: bearer token", i)
		require.JSONEq(t, vertexCompatSentBody, string(req.body), "request %d: payload", i)
	}
	// The binding cache is keyed by (project, location): the number of token
	// exchanges equals the DISTINCT locations walked — shared locations
	// across families reuse the binding.
	hits, minted = tokens()
	require.Len(t, distinctLocations, minted, "one token exchange per distinct (project, location) binding")
	require.Equal(t, minted, hits, "every token request mints exactly one token")

	// A second model of the first family on the first location rides the
	// same binding: no new exchange, new model in the path.
	first := &vertexModelMatrix[0]
	secondModel := vertexCompatModelsByFamily[first.prefix][1]
	firstLoc := first.locations[0]
	creds := fmt.Sprintf(`{"project":"api-proj-0001","location":%q}`, firstLoc)
	out, err := rig.chatTurn(t, vertexCompatTurnBody, secondModel, creds)
	require.NoError(t, err)
	assertJointChatCompletion(t, rig.adapter, out, "compat-ok", "gemini-compat-echo", 9, 2, 11, 3)
	reqs = rig.upstream.snapshot()
	require.Len(t, reqs, len(wantPaths)+1)
	require.Equal(t,
		"/v1/projects/api-proj-0001/locations/"+firstLoc+"/publishers/google/models/"+secondModel+":generateContent",
		reqs[len(wantPaths)].path)
	hits, minted = tokens()
	require.Len(t, distinctLocations, minted, "model switch inside a binding must not re-exchange")
	require.Equal(t, minted, hits)
}

// vertexCompatLocations returns a copy of a family's location list,
// guarding against duplicate entries in the live matrix slices.
func vertexCompatLocations(t *testing.T, fam *vertexModelFamily) []string {
	t.Helper()
	vertexCompatLocationSet(t, fam.locations) // duplicate guard on the live slice
	out := make([]string, len(fam.locations))
	copy(out, fam.locations)
	return out
}

// geminiMember extracts the inner Gemini payload from a translated
// envelope for shape comparison.
func geminiMember(t *testing.T, envelope []byte) string {
	t.Helper()
	var doc struct {
		Gemini json.RawMessage `json:"gemini"`
	}
	require.NoError(t, json.Unmarshal(envelope, &doc))
	require.NotEmpty(t, doc.Gemini, "envelope carries no gemini member")
	return string(doc.Gemini)
}

// TestVertexCompat_OldNewConsumerShapes pins that old- and new-generation
// OpenAI consumers translate to IDENTICAL Gemini payloads: the gateway is
// the compatibility layer, so a client's wire-generation choice must not
// change what the upstream sees (only PrepareRequest's model override and
// the capability matrix act after this point).
func TestVertexCompat_OldNewConsumerShapes(t *testing.T) {
	t.Parallel()

	v := &Vertex{}
	pairs := []struct{ name, oldBody, newBody string }{
		{"stop string vs stop array",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"stop":"END"}`,
			`{"model":"m","messages":[{"role":"user","content":"x"}],"stop":["END"]}`},
		{"system vs developer role",
			`{"model":"m","messages":[{"role":"system","content":"be terse"},{"role":"user","content":"x"}]}`,
			`{"model":"m","messages":[{"role":"developer","content":"be terse"},{"role":"user","content":"x"}]}`},
		{"max_tokens vs max_completion_tokens",
			`{"model":"m","messages":[{"role":"user","content":"x"}],"max_tokens":64}`,
			`{"model":"m","messages":[{"role":"user","content":"x"}],"max_completion_tokens":64}`},
		{"string content vs single text part",
			`{"model":"m","messages":[{"role":"user","content":"hello"}]}`,
			`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hello"}]}]}`},
		{"combined old vs new generation",
			`{"model":"m","messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"}],"max_tokens":32,"stop":"DONE"}`,
			`{"model":"m","messages":[{"role":"developer","content":"sys"},{"role":"user","content":"hi"}],"max_completion_tokens":32,"stop":["DONE"]}`},
	}
	for _, pair := range pairs {
		oldEnv := mustTranslate(t, v, pair.oldBody)
		newEnv := mustTranslate(t, v, pair.newBody)
		require.JSONEq(t, geminiMember(t, oldEnv), geminiMember(t, newEnv), "%s", pair.name)
	}

	// Sanity: the combined pair is non-degenerate — the shared payload
	// really carries the mapped fields, so the equality above is
	// meaningful rather than both sides collapsing to empty.
	combined := geminiMember(t, mustTranslate(t, v, pairs[len(pairs)-1].oldBody))
	var payload struct {
		SystemInstruction *struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"systemInstruction"`
		GenerationConfig *struct {
			MaxOutputTokens int      `json:"maxOutputTokens"`
			StopSequences   []string `json:"stopSequences"`
		} `json:"generationConfig"`
	}
	require.NoError(t, json.Unmarshal([]byte(combined), &payload))
	require.NotNil(t, payload.SystemInstruction, "system/developer must become systemInstruction")
	require.Equal(t, "sys", payload.SystemInstruction.Parts[0].Text)
	require.NotNil(t, payload.GenerationConfig, "max_tokens and stop must become generationConfig")
	require.Equal(t, 32, payload.GenerationConfig.MaxOutputTokens)
	require.Equal(t, []string{"DONE"}, payload.GenerationConfig.StopSequences)
}

// TestVertexCompat_UsageShapeParity pins that every supported usage shape
// — native Gemini usageMetadata, the translated chat.completion usage, and
// the absent-usage case — agrees under the billing parse (ParseUsage),
// including the cached-token details key that cache billing round-trips.
func TestVertexCompat_UsageShapeParity(t *testing.T) {
	t.Parallel()

	v := &Vertex{}
	candidates := `{"candidates":[{"content":{"parts":[{"text":"x"}]},"finishReason":"STOP"}]`
	rows := []struct {
		name           string
		native         string
		want           Usage
		wantDetailsKey bool
	}{
		{"full metadata with cached tokens",
			candidates + `,"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"totalTokenCount":11,"cachedContentTokenCount":3}}`,
			Usage{PromptTokens: 9, CompletionTokens: 2, TotalTokens: 11, CacheReadTokens: 3, Source: UsageSourceProvider},
			true},
		{"metadata without cached tokens omits the details key",
			candidates + `,"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2,"totalTokenCount":11}}`,
			Usage{PromptTokens: 9, CompletionTokens: 2, TotalTokens: 11, Source: UsageSourceProvider},
			false},
		{"metadata without total folds to prompt+completion",
			candidates + `,"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":2}}`,
			Usage{PromptTokens: 9, CompletionTokens: 2, TotalTokens: 11, Source: UsageSourceProvider},
			false},
		{"absent usage means none, not zeros",
			candidates + `}`,
			Usage{Source: UsageSourceNone},
			false},
	}
	for _, row := range rows {
		require.Equal(t, row.want, v.ParseUsage([]byte(row.native)), "%s: native parse", row.name)
		translated, err := v.TranslateResponse([]byte(row.native))
		require.NoError(t, err, row.name)
		require.Equal(t, row.want, v.ParseUsage(translated), "%s: translated parse must agree with native", row.name)
		require.Equal(t, row.wantDetailsKey,
			strings.Contains(string(translated), `"prompt_tokens_details"`),
			"%s: translated details key", row.name)
	}
}

// vertexCompatAuthChat is the chat-endpoint double for the auth-variant
// turns: it records each request's path and Authorization header, then
// answers with the standard compat reply.
type vertexCompatAuthChat struct {
	srv   *httptest.Server
	mu    sync.Mutex
	paths []string
	auths []string
}

func newVertexCompatAuthChat(t *testing.T) *vertexCompatAuthChat {
	t.Helper()
	chat := &vertexCompatAuthChat{}
	chat.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		chat.mu.Lock()
		chat.paths = append(chat.paths, r.URL.Path)
		chat.auths = append(chat.auths, r.Header.Get("Authorization"))
		chat.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, vertexCompatReply)
	}))
	t.Cleanup(chat.srv.Close)
	return chat
}

// vertexCompatMetadataRecorder is the GCE metadata server double: it
// records method, path and Metadata-Flavor and answers the documented
// instance service-account token shape.
type vertexCompatMetadataRecorder struct {
	srv    *httptest.Server
	hits   atomic.Int64
	method atomic.Value // string
	path   atomic.Value // string
	flavor atomic.Value // string
}

func newVertexCompatMetadataRecorder(t *testing.T) *vertexCompatMetadataRecorder {
	t.Helper()
	md := &vertexCompatMetadataRecorder{}
	md.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md.hits.Add(1)
		md.method.Store(r.Method)
		md.path.Store(r.URL.Path)
		md.flavor.Store(r.Header.Get("Metadata-Flavor"))
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "MT-1", "expires_in": 3600})
	}))
	t.Cleanup(md.srv.Close)
	return md
}

// vertexCompatAuthTurn runs the same end-to-end consumer turn the joint
// rig's chatTurn runs, against the auth-rig chat double.
func vertexCompatAuthTurn(t *testing.T, v *Vertex, chat *vertexCompatAuthChat, servedModel, creds string) []byte {
	t.Helper()
	envelope := mustTranslate(t, v, vertexCompatTurnBody)
	envelope = overrideEnvelopeModel(t, envelope, servedModel)
	req, err := v.PrepareRequest(context.Background(), chat.srv.URL, v.Path(false), envelope, creds, false)
	require.NoError(t, err)
	resp, err := chat.srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, "upstream answered %d: %s", resp.StatusCode, raw)
	out, err := v.TranslateResponse(raw)
	require.NoError(t, err)
	return out
}

// runVertexCompatAuthTurns performs the shared turn assertions for one
// auth variant: two identical consumer turns on the variant's location,
// both answered with the echo completion and the variant's bearer token,
// the second turn riding the binding cache (exactly one token fetch).
func runVertexCompatAuthTurns(t *testing.T, v *Vertex, chat *vertexCompatAuthChat, location, wantAuth string) {
	t.Helper()
	creds := fmt.Sprintf(`{"project":"api-proj-0001","location":%q}`, location)
	wantPath := "/v1/projects/api-proj-0001/locations/" + location +
		"/publishers/google/models/gemini-2.0-flash:generateContent"
	for i := 0; i < 2; i++ {
		out := vertexCompatAuthTurn(t, v, chat, "gemini-2.0-flash", creds)
		assertJointChatCompletion(t, v, out, "compat-ok", "gemini-compat-echo", 9, 2, 11, 3)
		require.Equal(t, wantPath, chat.paths[i], "turn %d path", i)
		require.Equal(t, wantAuth, chat.auths[i], "turn %d auth", i)
	}
}

// TestVertexCompat_AuthVariantsFullTurn walks all three supported ADC
// configurations (env service-account key, gcloud well-known authorized
// user, GCE metadata server) through the SAME end-to-end consumer turn,
// each on its own region: the auth configuration composes with the model ×
// region matrix. Every variant must present ITS OWN documented grant shape
// and get exactly one token exchange for the two-turn binding; the
// metadata variant additionally proves no OAuth token endpoint is involved
// (the exchange IS the documented metadata GET). Rejections for foreign
// credentials are pinned by the negative corpus — this walk is the
// supported-consumer half of the card action.
func TestVertexCompat_AuthVariantsFullTurn(t *testing.T) {
	// Sequential: GOOGLE_APPLICATION_CREDENTIALS and the user-home seam
	// are process-global.

	t.Run("env service account", func(t *testing.T) {
		tokenSrv := newVertexTokenRecorder(t)
		keyPath, clientEmail, _ := writeVertexSAKeyFile(t, tokenSrv.srv.URL)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)

		v := NewVertexWithSource(plainVertexADC(tokenSrv.srv))
		chat := newVertexCompatAuthChat(t)
		runVertexCompatAuthTurns(t, v, chat, "us-central1", "Bearer VT-1")

		require.Equal(t, int64(1), tokenSrv.hits.Load(), "second turn must ride the binding cache")
		form := tokenSrv.form(t)
		require.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", form.Get("grant_type"))
		assertion := form.Get("assertion")
		require.NotEmpty(t, assertion, "jwt-bearer grant carries the signed assertion")
		claims := decodeVertexJWTPart(t, assertion, 1)
		require.Equal(t, clientEmail, claims["iss"], "assertion must bind the key's identity")
		require.Equal(t, vertexCloudPlatformScope, claims["scope"])
		require.Equal(t, tokenSrv.srv.URL, claims["aud"])
	})

	t.Run("gcloud well-known user file", func(t *testing.T) {
		tokenSrv := newVertexTokenRecorder(t)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		home := t.TempDir()
		writeVertexUserKeyFile(t, home)
		vertexSwapHome(t, home, nil)

		adc := plainVertexADC(tokenSrv.srv)
		adc.oauthTokenURL = tokenSrv.srv.URL // prod: https://oauth2.googleapis.com/token
		v := NewVertexWithSource(adc)
		chat := newVertexCompatAuthChat(t)
		runVertexCompatAuthTurns(t, v, chat, "europe-west4", "Bearer VT-1")

		require.Equal(t, int64(1), tokenSrv.hits.Load())
		form := tokenSrv.form(t)
		require.Equal(t, "refresh_token", form.Get("grant_type"))
		require.Equal(t, "test-refresh-token-1", form.Get("refresh_token"))
		require.Equal(t, "test-user-client.apps.googleusercontent.com", form.Get("client_id"))
		require.Equal(t, "test-user-secret", form.Get("client_secret"))
	})

	t.Run("gce metadata server", func(t *testing.T) {
		md := newVertexCompatMetadataRecorder(t)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
		vertexSwapHome(t, "", errors.New("no home dir in test"))

		adc := newVertexADC(nil)
		adc.metadataURL = md.srv.URL
		adc.metadataClient = md.srv.Client()
		v := NewVertexWithSource(adc)
		chat := newVertexCompatAuthChat(t)
		runVertexCompatAuthTurns(t, v, chat, "asia-southeast1", "Bearer MT-1")

		require.Equal(t, int64(1), md.hits.Load())
		require.Equal(t, http.MethodGet, md.method.Load())
		require.Equal(t, "/computeMetadata/v1/instance/service-accounts/default/token", md.path.Load())
		require.Equal(t, "Google", md.flavor.Load())
	})
}

// TestVertexCompat_UnsupportedModelsRejectPrecisely pins the explicit
// rejection half of the card action: model ids real clients still send for
// Vertex — PaLM chat, embeddings, the retired gemini-1.0 generation and
// MedLM — fail closed at the capability matrix with the model named, and
// the rejection happens BEFORE any credential or endpoint work (zero token
// exchanges, zero upstream requests).
func TestVertexCompat_UnsupportedModelsRejectPrecisely(t *testing.T) {
	// Sequential: the joint rig pins GOOGLE_APPLICATION_CREDENTIALS.
	rig := newVertexJointRig(t, vertexCompatReply, "")

	unsupported := []string{
		"chat-bison@002",      // PaLM chat generation
		"text-embedding-004",  // embedding family
		"gemini-1.0-pro",      // retired generation
		"medlm-medium@latest", // MedLM family
	}
	for _, model := range unsupported {
		_, err := rig.chatTurn(t, vertexCompatTurnBody, model, rig.credsA)
		require.Error(t, err, "%s must be refused", model)
		require.ErrorContains(t, err, "is not in the capability matrix")
		require.ErrorContains(t, err, model, "the precise rejection names the model")
	}
	hits, minted := rig.tokenSrv.snapshot()
	require.Zero(t, hits, "unsupported consumers must not spend credential work")
	require.Zero(t, minted)
	require.Empty(t, rig.upstream.snapshot(), "unsupported consumers must not reach the endpoint")
}
