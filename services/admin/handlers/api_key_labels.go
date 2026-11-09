package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/reireirei/yabanin/pkg/adminstore"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/labels"
)

const apiKeyLabelsBodyLimit = 16 * 1024

var apiKeyLabelSecrets = guardhooks.New(guardhooks.ModeLog)

type apiKeyLabelsRequest struct {
	Labels          map[string]string `json:"labels"`
	LabelsLocked    bool              `json:"labels_locked"`
	CanMintSessions bool              `json:"can_mint_sessions"`
	CanReadUsage    bool              `json:"can_read_usage"`
	// AF-09: optional expected current state (the recorded after of the
	// audited change) — makes the PUT an atomic compare-and-set for the
	// audit rollback path. Absent = plain unconditional update.
	Expected *adminstore.APIKeyLabelsState `json:"expected,omitempty"`
}

// UpdateAPIKeyLabels — PUT /api/api-keys/{id}/labels (keys.manage).
// Every label is checked. Any problem is 400 with [{key, reason}]; nothing is dropped quietly.
func (h *AdminHandlers) UpdateAPIKeyLabels() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.requireStore(w, r) {
			return
		}
		id := chi.URLParam(r, "id")
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, apiKeyLabelsBodyLimit))
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				h.respondError(w, r, fmt.Errorf("labels body exceeds 16 KiB"), http.StatusRequestEntityTooLarge)
				return
			}
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		var req apiKeyLabelsRequest
		if err := dec.Decode(&req); err != nil {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		var extra struct{}
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			h.respondError(w, r, fmt.Errorf("invalid request body"), http.StatusBadRequest)
			return
		}
		key, err := h.store.GetAPIKeyByID(r.Context(), id)
		if err != nil || key == nil {
			if err == nil {
				err = fmt.Errorf("api key not found")
			}
			h.respondError(w, r, err, http.StatusNotFound)
			return
		}
		if h.apiKeyHidden(w, r, key) {
			return
		}
		normalized, problems := normalizeAPIKeyLabels(req.Labels)
		if len(problems) > 0 {
			writeJSON(w, http.StatusBadRequest, problems)
			return
		}
		// AUX-14b: journal the label state on both sides of the update so the
		// audit page can show a diff and offer the reverse call. The before
		// map is captured from the fetched row BEFORE the store mutates it.
		before := map[string]any{
			"id":                id,
			"labels":            key.Labels,
			"labels_locked":     key.LabelsLocked,
			"can_mint_sessions": key.CanMintSessions,
			"can_read_usage":    key.CanReadUsage,
		}
		after := map[string]any{
			"id":                id,
			"labels":            normalized,
			"labels_locked":     req.LabelsLocked,
			"can_mint_sessions": req.CanMintSessions,
			"can_read_usage":    req.CanReadUsage,
		}
		if req.Expected != nil {
			cs := h.cas()
			if cs == nil {
				h.respondError(w, r, fmt.Errorf("preconditioned updates not supported"), http.StatusNotImplemented)
				return
			}
			current, err := cs.UpdateAPIKeyLabelsPreconditioned(r.Context(), id, normalized, req.LabelsLocked, req.CanMintSessions, req.CanReadUsage, req.Expected)
			if adminstore.IsNotFound(err) {
				h.respondError(w, r, fmt.Errorf("api key not found"), http.StatusNotFound)
				return
			}
			if err != nil {
				if errors.Is(err, adminstore.ErrPreconditionFailed) {
					// AF-09: stale label rollback — report the current state,
					// write nothing, journal nothing.
					if current == nil {
						current = &adminstore.APIKeyLabelsState{}
					}
					writeConflict(w, map[string]any{
						"id":                id,
						"labels":            current.Labels,
						"labels_locked":     current.LabelsLocked,
						"can_mint_sessions": current.CanMintSessions,
						"can_read_usage":    current.CanReadUsage,
					})
					return
				}
				h.respondError(w, r, err, http.StatusInternalServerError)
				return
			}
		} else if err := h.store.UpdateAPIKeyLabels(r.Context(), id, normalized, req.LabelsLocked, req.CanMintSessions, req.CanReadUsage); err != nil {
			h.respondError(w, r, err, http.StatusInternalServerError)
			return
		}
		h.purgeResolverKeys(r.Context(), key.KeyHash)
		names := make([]string, 0, len(normalized))
		for name := range normalized {
			names = append(names, name)
		}
		sort.Strings(names)
		h.auditLogActionDiff(r, "api_key.labels_update", "api_key:"+id, fmt.Sprintf(
			"keys=%s,labels_locked=%t,can_mint_sessions=%t,can_read_usage=%t",
			strings.Join(names, ","), req.LabelsLocked, req.CanMintSessions, req.CanReadUsage,
		), before, after)
		key.Labels = normalized
		key.LabelsLocked = req.LabelsLocked
		key.CanMintSessions = req.CanMintSessions
		key.CanReadUsage = req.CanReadUsage
		writeJSON(w, http.StatusOK, key)
	}
}

func normalizeAPIKeyLabels(in map[string]string) (map[string]string, []labels.Dropped) {
	out := map[string]string{}
	if len(in) == 0 {
		return out, nil
	}
	rawKeys := make([]string, 0, len(in))
	for key := range in {
		rawKeys = append(rawKeys, key)
	}
	sort.Strings(rawKeys)
	var problems []labels.Dropped
	accepted := 0
	for _, rawKey := range rawKeys {
		key, ok := labels.NormalizeKey(rawKey)
		if !ok {
			problems = append(problems, labels.Dropped{Key: rawKey, Reason: labels.DropInvalidKey})
			continue
		}
		if strings.HasPrefix(key, labels.ReservedPrefix) {
			problems = append(problems, labels.Dropped{Key: key, Reason: labels.DropReserved})
			continue
		}
		if _, exists := out[key]; exists {
			problems = append(problems, labels.Dropped{Key: key, Reason: labels.DropInvalidKey})
			continue
		}
		if accepted >= labels.MaxPerSource {
			problems = append(problems, labels.Dropped{Key: key, Reason: labels.DropTooMany})
			continue
		}
		value, reason := labels.NormalizeValue(in[rawKey])
		if reason != "" {
			problems = append(problems, labels.Dropped{Key: key, Reason: reason})
			continue
		}
		if labelValueIsSecret(value) {
			problems = append(problems, labels.Dropped{Key: key, Reason: labels.DropSecretLike})
			continue
		}
		out[key] = value
		accepted++
	}
	return out, problems
}

func labelValueIsSecret(value string) bool {
	for _, hit := range apiKeyLabelSecrets.Scan(value) {
		if hit.Category == guardhooks.CatSecret {
			return true
		}
	}
	return false
}
