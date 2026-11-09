package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompatAdapter_BearerAuthAndUsage(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		p    Provider
	}{
		{"sakana", Sakana{}},
		{"sarvam", Sarvam{}},
		{"krutrim", Krutrim{}},
		{"falcon", Falcon{}},
		{"mistral", Mistral{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var gotAuth string
			var gotBody string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				buf := make([]byte, 64)
				n, _ := r.Body.Read(buf)
				gotBody = string(buf[:n])
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
			}))
			defer srv.Close()

			req, err := tc.p.PrepareRequest(context.Background(), srv.URL, tc.p.Path(false), []byte(`{"model":"x"}`), "key-123", false)
			if err != nil {
				t.Fatalf("PrepareRequest: %v", err)
			}
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			body := make([]byte, 4096)
			n, _ := resp.Body.Read(body)
			_ = resp.Body.Close()

			if gotAuth != "Bearer key-123" {
				t.Fatalf("auth = %q, want Bearer key-123", gotAuth)
			}
			if !strings.Contains(gotBody, `"model":"x"`) {
				t.Fatalf("body not passed through: %q", gotBody)
			}
			u := tc.p.ParseUsage(body[:n])
			if u.PromptTokens != 10 || u.CompletionTokens != 5 || u.TotalTokens != 15 {
				t.Fatalf("usage = %+v", u)
			}
		})
	}
}

func TestNaver_CustomHeadersAndPath(t *testing.T) {
	t.Parallel()
	var clova, apigw string
	n := Naver{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clova = r.Header.Get("X-NCP-CLOVASTUDIO-API-KEY")
		apigw = r.Header.Get("X-NCP-APIGW-API-KEY")
		if r.URL.Path != n.Path(false) {
			t.Errorf("path = %q", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	req, err := n.PrepareRequest(context.Background(), srv.URL, n.Path(false), []byte(`{}`), "clova-k|apigw-k", false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()
	if clova != "clova-k" || apigw != "apigw-k" {
		t.Fatalf("headers clova=%q apigw=%q", clova, apigw)
	}
}

func TestNaver_BadApiKeyFormat_Errors(t *testing.T) {
	t.Parallel()
	n := Naver{}
	if _, err := n.PrepareRequest(context.Background(), "https://x", n.Path(false), []byte(`{}`), "no-pipe", false); err == nil {
		t.Fatal("expected error for missing pipe separator")
	}
}

func TestJais_TranslateRequest_RewritesModel(t *testing.T) {
	t.Parallel()
	out, err := Jais{}.TranslateRequest([]byte(`{"model":"jais-30b","messages":[]}`))
	if err != nil {
		t.Fatalf("TranslateRequest: %v", err)
	}
	if !strings.Contains(string(out), `"model":"jais-30b-chat"`) {
		t.Fatalf("model not rewritten: %s", out)
	}
}

func TestFactory_AllSovereignAdapters(t *testing.T) {
	t.Parallel()
	names := []string{"sakana", "sarvam", "krutrim", "naver", "falcon", "jais", "mistral", "yandex"}
	for _, n := range names {
		p, err := New(n)
		if err != nil {
			t.Fatalf("New(%q): %v", n, err)
		}
		if p.Name() != n {
			t.Fatalf("Name() = %q, want %q", p.Name(), n)
		}
	}
}

func TestFactory_SberReturnsPointer(t *testing.T) {
	t.Parallel()
	p, err := New("sber")
	if err != nil {
		t.Fatalf("New(sber): %v", err)
	}
	if p.Name() != "sber" {
		t.Fatalf("Name = %q", p.Name())
	}
}

func TestFactory_UnknownProvider_Errors(t *testing.T) {
	t.Parallel()
	if _, err := New("nope"); err == nil {
		t.Fatal("expected error for unknown provider")
	}
}
