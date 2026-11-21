package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reireirei/yabanin/pkg/resolver"
)

// reviewMediaResult carries both parser dialects (audio reads
// prompt_tokens, images reads input_tokens) so one upstream 200 body
// projects 7/3 usage on every family.
const reviewMediaResult = `{"text":"ok","usage":{"prompt_tokens":7,"output_tokens":3,"input_tokens":7,"output_tokens_total":3,"total_tokens":10}}`

// TestReviewMediaKnownUsageAfterDisconnect is the owner's post-read
// cancel regression (review 0574aa1, media-post-read recheck): when the
// real transport reports the connection reusable (PutIdleConn with no
// error) after the provider's 200 was fully read, a deterministic cancel
// must NOT discard the observable paid usage. The KNOWN usage settles
// durably (facts row bound to the single admission), the cancellation is
// preserved as the terminal outcome, and no success bytes reach the dead
// client. Connected runs pin the healthy twin on the same code path.
func TestReviewMediaKnownUsageAfterDisconnect(t *testing.T) {
	for _, family := range []string{"speech", "transcriptions", "images"} {
		for _, timing := range []string{"connected", "after_read"} {
			t.Run(family+"/"+timing, func(t *testing.T) {
				var calls atomic.Int32
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					calls.Add(1)
					_, _ = w.Write([]byte(reviewMediaResult))
				}))
				defer srv.Close()

				var (
					gw          *gateway
					body        []byte
					contentType = "application/json"
					path        string
					handle      func(http.ResponseWriter, *http.Request)
					wantTokens  bool
				)
				switch family {
				case "speech":
					gw = newAudioGateway(t, audioTestModel(srv.URL))
					body = []byte(`{"model":"tts","input":"hé","voice":"alloy"}`)
					path = "/v1/audio/speech"
					handle = gw.audioSpeech
				case "transcriptions":
					gw = newAudioGateway(t, audioTranscriptionModel(srv.URL))
					body, contentType = buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "sample.wav", "audio/wav", audioFixtureBytes(t, "hello.wav"))
					path = "/v1/audio/transcriptions"
					handle = gw.audioTranscriptions
					wantTokens = true
				case "images":
					gw = imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: srv.URL, Enabled: true}, srv.URL)
					body = []byte(`{"model":"m","prompt":"a single red cube"}`)
					path = "/v1/images/generations"
					handle = gw.imagesGenerations
					wantTokens = true
				}
				gw.unitPricer = operatorUnitsForTest(t)
				store := &fakeInvocationStore{}
				gw.invocations = store

				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				var consumed atomic.Bool
				ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{PutIdleConn: func(err error) {
					if err == nil {
						consumed.Store(true)
						if timing == "after_read" {
							cancel()
						}
					}
				}})
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(body))
				req.Header.Set("Content-Type", contentType)
				goldenIdentity(req)
				rec := httptest.NewRecorder()
				handle(rec, req)

				require.True(t, consumed.Load(), "provider response must reach transport EOF: %s", rec.Body.String())
				require.EqualValues(t, 1, calls.Load())
				require.Len(t, store.admitted, 1)
				require.Len(t, store.facts, 1, "known provider usage did not reach durable accounting")
				require.Equal(t, store.admitted[0].InvocationID, store.facts[0].InvocationID)
				if wantTokens {
					require.Equal(t, "7", store.facts[0].Fields["tokens_in"])
					require.Equal(t, "3", store.facts[0].Fields["tokens_out"])
				} else {
					require.Equal(t, "0.000064", store.facts[0].Fields["estimated_cost_usd"])
				}
				if timing == "after_read" {
					require.Empty(t, rec.Body.String())
				} else {
					require.Equal(t, []byte(reviewMediaResult), rec.Body.Bytes())
				}
			})
		}
	}
}

// TestReviewMediaInterruptedReadNoFabricatedUsage is the other half of
// the owner review contract: a provider connection that dies BEFORE the
// 200 body reaches EOF is an interrupted read — no known usage exists, so
// nothing may be fabricated into durable accounting. The escrow settles
// empty (finalized without an event) and the client sees a 502; the
// reconciler's grace sweep owns the admitted-without-facts row.
func TestReviewMediaInterruptedReadNoFabricatedUsage(t *testing.T) {
	for _, family := range []string{"speech", "transcriptions", "images"} {
		t.Run(family, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				calls.Add(1)
				// Announce an 11-byte body, deliver 4 bytes, slam the
				// connection shut: the gateway's read fails mid-body.
				w.Header().Set("Content-Length", "11")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"te`))
				panic(http.ErrAbortHandler)
			}))
			defer srv.Close()

			var (
				gw          *gateway
				body        []byte
				contentType = "application/json"
				path        string
				handle      func(http.ResponseWriter, *http.Request)
			)
			switch family {
			case "speech":
				gw = newAudioGateway(t, audioTestModel(srv.URL))
				body = []byte(`{"model":"tts","input":"hé","voice":"alloy"}`)
				path = "/v1/audio/speech"
				handle = gw.audioSpeech
			case "transcriptions":
				gw = newAudioGateway(t, audioTranscriptionModel(srv.URL))
				body, contentType = buildAudioMultipart(t, map[string]string{"model": "m"}, "file", "sample.wav", "audio/wav", audioFixtureBytes(t, "hello.wav"))
				path = "/v1/audio/transcriptions"
				handle = gw.audioTranscriptions
			case "images":
				gw = imagesTestGateway(t, resolver.ModelInfo{ModelName: "gpt-image-1-canon", Provider: "openai", UpstreamURL: srv.URL, Enabled: true}, srv.URL)
				body = []byte(`{"model":"m","prompt":"a single red cube"}`)
				path = "/v1/images/generations"
				handle = gw.imagesGenerations
			}
			gw.unitPricer = operatorUnitsForTest(t)
			store := &fakeInvocationStore{}
			gw.invocations = store

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("Content-Type", contentType)
			goldenIdentity(req)
			rec := httptest.NewRecorder()
			handle(rec, req)

			require.EqualValues(t, 1, calls.Load())
			require.Equal(t, http.StatusBadGateway, rec.Code, "interrupted provider read must surface 502, got body %s", rec.Body.String())
			require.Len(t, store.admitted, 1, "the confirmed start existed — the reconciler sweep owns the admitted-without-facts row")
			require.Empty(t, store.facts, "an interrupted read must not fabricate usage into durable accounting")
		})
	}
}
