package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	eventpub "github.com/reireirei/yabanin/pkg/eventpublisher"
	"github.com/reireirei/yabanin/pkg/labels"
)

func TestLabelsMiddleware(t *testing.T) {
	gw := &gateway{}
	var seen http.Header
	next := gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		if labelsFrom(r.Context())["issue"] != "PAY-1" {
			t.Fatalf("%v", labelsFrom(r.Context()))
		}
		if r.Header.Get("X-Yabanin-Task") != "PAY-1" {
			t.Fatalf("task header %q", r.Header.Get("X-Yabanin-Task"))
		}
		if r.Header.Get("X-Yabanin-Repo") != "org/repo" {
			t.Fatalf("repo header %q", r.Header.Get("X-Yabanin-Repo"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Yabanin-Labels", "issue=PAY-1,task=PAY-1,git.repo=org/repo")
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code, rec.Body.String())
	}
	for key := range seen {
		if strings.HasPrefix(key, "X-Yabanin-Label") {
			t.Fatalf("upstream saw %s", key)
		}
	}
}

func TestLabelsDroppedAndReserved(t *testing.T) {
	gw := &gateway{}
	next := gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Yabanin-Labels", "1bad=x,yabanin.internal=1")
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code, rec.Body.String())
	}
	dropped := rec.Header().Get("X-Yabanin-Labels-Dropped")
	if !strings.Contains(dropped, "invalid_key") || !strings.Contains(dropped, "reserved") {
		t.Fatalf("%s", dropped)
	}
}

func TestLabelsSecretAndTaskHeaderWins(t *testing.T) {
	gw := &gateway{taskTag: "from-env"}
	next := gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if labelsFrom(r.Context())["task"] != "from-header" {
			t.Fatalf("%v", labelsFrom(r.Context()))
		}
		if _, ok := labelsFrom(r.Context())["leak"]; ok {
			t.Fatal("secret label kept")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	secret := "sk-" + strings.Repeat("A", 40)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Yabanin-Task", "from-header")
	req.Header.Set("X-Yabanin-Labels", "task=from-label,leak="+secret)
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Header().Get("X-Yabanin-Labels-Dropped"), secret) {
		t.Fatal("dropped header contains the secret")
	}
	if !strings.Contains(rec.Header().Get("X-Yabanin-Labels-Dropped"), "secret_like") {
		t.Fatal(rec.Header().Get("X-Yabanin-Labels-Dropped"))
	}
}

func TestLabelsTaskTagFallbackAndRepoHeader(t *testing.T) {
	gw := &gateway{taskTag: "ci-task"}
	next := gw.labelsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if labelsFrom(r.Context())["task"] != "ci-task" {
			t.Fatalf("task %v", labelsFrom(r.Context()))
		}
		if r.Header.Get("X-Yabanin-Task") != "" {
			t.Fatal("task tag must not be copied into the header")
		}
		if labelsFrom(r.Context())["git.repo"] != "org/repo" {
			t.Fatalf("repo %v", labelsFrom(r.Context()))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	req = req.WithContext(withPrincipalLabelSources(req.Context(), nil))
	req.Header.Set("X-Yabanin-Repo", "org/repo")
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
}

func TestLabelsRejectOpenAIAndAnthropic(t *testing.T) {
	compiled, err := labels.Policy{AllowedKeys: []string{"*"}, OnInvalid: "reject", OnMissing: "allow", MaxLabels: 32, ValueMaxLen: 3}.Compile()
	if err != nil {
		t.Fatal(err)
	}
	gw := &gateway{labelPolicy: func(context.Context, string) *labels.Compiled { return compiled }}
	secret := "sk-" + strings.Repeat("B", 40)
	body := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/chat/completions", nil)
	body.Header.Set("X-Yabanin-Labels", "issue=PAY-1")
	rec := httptest.NewRecorder()
	gw.labelsMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next")
	})).ServeHTTP(rec, body)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_labels") || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}

	anth := httptest.NewRecorder()
	anthReq := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/messages", nil)
	anthReq.Header.Set("X-Yabanin-Labels", "issue=PAY-1")
	anthropicErrorEnvelope(gw.labelsMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next")
	}))).ServeHTTP(anth, anthReq)
	if anth.Code != http.StatusBadRequest || !strings.Contains(anth.Body.String(), `"type":"error"`) || strings.Contains(anth.Body.String(), secret) {
		t.Fatalf("%d %s", anth.Code, anth.Body.String())
	}
}

func TestLabelsReachChatStreamResponsesAndMessages(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key := range r.Header {
			if strings.HasPrefix(key, "X-Yabanin-Label") {
				t.Errorf("upstream saw %s", key)
			}
		}
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n")
			_, _ = io.WriteString(w, "data: {\"choices\":[{\"index\":0,\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}\n\n")
			_, _ = io.WriteString(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer upstream.Close()
	gw := decisionTestGateway(upstream.URL)
	// The event observer also fires from detached pipelines (e.g. the shadow
	// dispatcher), so `got` is touched by more than the test goroutine — a
	// straggler from the previous subtest may land while the next one runs.
	// Guard it; a straggler carrying the same labels is assertion-harmless.
	var gotMu sync.Mutex
	var got []*eventpub.Event
	restore := observeEvent(func(ev *eventpub.Event) {
		gotMu.Lock()
		defer gotMu.Unlock()
		got = append(got, ev)
	})
	defer restore()
	cases := []struct {
		name    string
		path    string
		body    string
		handler http.HandlerFunc
	}{
		{"chat", "/v1/chat/completions", `{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}`, gw.chatCompletions},
		{"stream", "/v1/chat/completions", `{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}`, gw.chatCompletions},
		{"responses", "/v1/responses", `{"model":"gpt-4o-mini","input":"hi"}`, gw.responses},
		{"messages", "/v1/messages", `{"model":"gpt-4o-mini","max_tokens":8,"messages":[{"role":"user","content":"hi"}]}`, gw.messages},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotMu.Lock()
			got = nil
			gotMu.Unlock()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Yabanin-Labels", "issue=PAY-1,ci.pipeline=42")
			rec := httptest.NewRecorder()
			gw.labelsMiddleware(tc.handler).ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
			gotMu.Lock()
			n := len(got)
			var last *eventpub.Event
			if n > 0 {
				last = got[n-1]
			}
			gotMu.Unlock()
			if n == 0 || last.Labels["issue"] != "PAY-1" || last.Labels["ci.pipeline"] != "42" {
				t.Fatalf("%d events, last %+v", n, last)
			}
		})
	}
}
