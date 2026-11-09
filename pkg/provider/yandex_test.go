package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestYandex_PrepareRequest_FolderIDHeader(t *testing.T) {
	t.Parallel()
	var iam, folder string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iam = r.Header.Get("Authorization")
		folder = r.Header.Get("x-folder-id")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	y := Yandex{}
	req, err := y.PrepareRequest(context.Background(), srv.URL, y.Path(false), []byte(`{}`), "iam-tok|fld-42", false)
	if err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if iam != "Bearer iam-tok" {
		t.Fatalf("iam header = %q", iam)
	}
	if folder != "fld-42" {
		t.Fatalf("folder header = %q", folder)
	}
}

func TestYandex_BadApiKeyFormat_Errors(t *testing.T) {
	t.Parallel()
	y := Yandex{}
	if _, err := y.PrepareRequest(context.Background(), "https://x", y.Path(false), []byte(`{}`), "no-pipe", false); err == nil {
		t.Fatal("expected error for missing pipe")
	}
}

func TestYandex_PathHasLLMPrefix(t *testing.T) {
	var y Yandex
	if got := y.Path(false); got != "/llm/v1/chat/completions" {
		t.Fatalf("path = %q", got)
	}
}
