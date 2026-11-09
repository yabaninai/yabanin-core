package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	apierrs "github.com/reireirei/yabanin/pkg/apierrors"
	"github.com/reireirei/yabanin/pkg/apiformat"
	"github.com/reireirei/yabanin/pkg/budget"
)

func (gw *gateway) responses(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeResponsesError(w, http.StatusBadRequest, "invalid_request_error", "invalid_json", "request body too large or malformed")
		return
	}
	// state on either path, so continuation ids are refused uniformly —
	// the native passthrough no longer forwards previous_response_id to
	// the upstream. The error is byte-identical to the translation-layer
	// rejection (apiformat.ErrPreviousResponseID).
	if ferr := apiformat.RejectPreviousResponseID(body); ferr != nil {
		writeResponsesError(w, ferr.Status, ferr.Type, ferr.Code, ferr.Message)
		return
	}
	if gw.wantResponsesNative(r, body) {
		gw.responsesNative(w, r, body)
		return
	}
	chatBody, meta, ferr := apiformat.ResponsesToChat(body)
	if ferr != nil {
		writeResponsesError(w, ferr.Status, ferr.Type, ferr.Code, ferr.Message)
		return
	}
	if len(meta.Dropped) > 0 {
		w.Header().Set("X-Yabanin-Unsupported", unsupportedHeader(meta.Dropped))
	}
	r2 := r.Clone(withEndpoint(r.Context(), "responses"))
	r2.Body = io.NopCloser(bytes.NewReader(chatBody))
	r2.ContentLength = int64(len(chatBody))
	r2.Header.Set("Content-Type", "application/json")
	r2.Header.Del("X-Yabanin-Raw-Body")
	if r2.Header.Get("X-Session-Id") == "" && meta.PromptCacheKey != "" && budget.ValidTaskID(meta.PromptCacheKey) {
		r2.Header.Set("X-Session-Id", meta.PromptCacheKey)
	}
	sw := apiformat.NewResponsesWriter(w, meta, apiformat.ResponsesOptions{})
	gw.chatCompletions(sw, r2)
	sw.Finish()
}

// comma-separated names of the Responses fields the translation dropped.
func unsupportedHeader(names []string) string {
	joined := strings.Join(names, ",")
	const limit = 1024
	const suffix = ",…"
	if len(joined) <= limit {
		return joined
	}
	cut := limit - len(suffix)
	if cut < 0 {
		return suffix
	}
	return joined[:cut] + suffix
}

func writeResponsesError(w http.ResponseWriter, status int, errType, code, message string) {
	if status == 0 {
		status = http.StatusBadRequest
	}
	if errType == "" {
		errType = "invalid_request_error"
	}
	payload := apierrs.Responses(&apierrs.E{Status: status, Type: errType, Code: code, Message: message})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func (gw *gateway) wantResponsesNative(r *http.Request, body []byte) bool {
	if len(gw.cfg.ResponsesNativeProviders) == 0 {
		return false
	}
	var probe struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &probe) != nil || probe.Model == "" {
		return false
	}
	// RT-06: probe resolution runs under the request context; a registry
	// outage degrades to the adapted path, where admission surfaces 503.
	info, resErr := gw.resolveModelInfo(r.Context(), probe.Model)
	if resErr != nil {
		return false
	}
	if !providerListed(gw.cfg.ResponsesNativeProviders, info.Provider) {
		return false
	}
	org := r.Header.Get("X-Org-Id")
	if gw.toolPolicies != nil && gw.toolPolicies.HasDenyPolicies(r.Context(), org) {
		return false
	}
	return true
}

func providerListed(list []string, provider string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), provider) && provider != "" {
			return true
		}
	}
	return false
}
