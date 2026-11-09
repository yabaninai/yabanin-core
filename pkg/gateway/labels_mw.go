package cli

import (
	"context"
	"net/http"
	"strings"

	"github.com/reireirei/yabanin/pkg/budget"
	apierrors "github.com/reireirei/yabanin/pkg/errors"
	"github.com/reireirei/yabanin/pkg/guardhooks"
	"github.com/reireirei/yabanin/pkg/labels"
	"github.com/reireirei/yabanin/pkg/metrics"
)

var defaultLabelPolicy = compileDefaultPolicy()

var labelSecretHook = guardhooks.New(guardhooks.ModeLog)

func compileDefaultPolicy() *labels.Compiled {
	compiled, err := labels.DefaultPolicy().Compile()
	if err != nil {
		panic(err)
	}
	return compiled
}

func (gw *gateway) labelPolicyFor(ctx context.Context, orgID string) *labels.Compiled {
	if gw.labelPolicy != nil {
		return gw.labelPolicy(ctx, orgID)
	}
	return gw.orgLabelPolicies().get(ctx, orgID)
}

func (gw *gateway) labelsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		set, dropped := labels.FromRequest(r.Header)
		stripLabelHeaders(r.Header)
		sources := append(principalLabelSources(r.Context()), labels.Source{Name: "request", Labels: set})
		compiled := gw.labelPolicyFor(r.Context(), r.Header.Get("X-Org-Id"))
		res := labels.Resolve(compiled, sources, labelSecret)
		res.Dropped = append(dropped, res.Dropped...)
		bridgeLabels(gw, r, &res)
		if res.Rejected {
			apierrors.Write(w, http.StatusBadRequest, res.RejectCode, droppedKeys(res.Dropped))
			return
		}
		if header := formatDropped(res.Dropped); header != "" {
			w.Header().Set("X-Yabanin-Labels-Dropped", header)
		}
		if compiled.OnMissing() == "warn" && len(res.Missing) > 0 {
			w.Header().Set("X-Yabanin-Labels-Missing", strings.Join(res.Missing, ","))
		}
		for _, item := range res.Dropped {
			metrics.LabelsDroppedTotal.WithLabelValues(string(item.Reason)).Inc()
		}
		has := "false"
		if len(res.Labels) > 0 {
			has = "true"
		}
		metrics.LabelsRequestsTotal.WithLabelValues(has).Inc()
		next.ServeHTTP(w, r.WithContext(withLabels(r.Context(), res)))
	})
}

func labelSecret(value string) bool {
	for _, hit := range labelSecretHook.Scan(value) {
		if hit.Category == guardhooks.CatSecret {
			return true
		}
	}
	return false
}

func stripLabelHeaders(h http.Header) {
	prefix := http.CanonicalHeaderKey(labels.PerKeyPrefix)
	for key := range h {
		if key == labels.HeaderName || strings.HasPrefix(key, prefix) {
			h.Del(key)
		}
	}
}

func bridgeLabels(gw *gateway, r *http.Request, res *labels.Result) {
	if res.Labels == nil {
		res.Labels = labels.Set{}
	}
	taskHeader := r.Header.Get("X-Yabanin-Task")
	switch {
	case taskHeader != "" && budget.ValidTaskID(taskHeader):
		res.Labels["task"] = taskHeader
	case res.Labels["task"] != "" && budget.ValidTaskID(res.Labels["task"]):
		r.Header.Set("X-Yabanin-Task", res.Labels["task"])
	case gw.taskTag != "" && budget.ValidTaskID(gw.taskTag):
		res.Labels["task"] = gw.taskTag
	}
	repoHeader := r.Header.Get("X-Yabanin-Repo")
	if repoHeader == "" && repoLabelOK(res.Labels["git.repo"]) {
		r.Header.Set("X-Yabanin-Repo", res.Labels["git.repo"])
	}
	if res.Labels["git.repo"] == "" && len(repoHeader) > 0 && len(repoHeader) <= 128 && repoLabelOK(repoHeader) {
		res.Labels["git.repo"] = repoHeader
	}
}

func repoLabelOK(value string) bool {
	if value == "" || len(value) > 200 {
		return false
	}
	for _, c := range value {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '.' || c == '_' || c == '/' || c == '@' || c == ':' || c == '-':
		default:
			return false
		}
	}
	return true
}

func droppedKeys(dropped []labels.Dropped) string {
	keys := make([]string, 0, len(dropped))
	seen := map[string]bool{}
	for _, item := range dropped {
		if item.Key == "" || seen[item.Key] {
			continue
		}
		seen[item.Key] = true
		keys = append(keys, item.Key)
	}
	return strings.Join(keys, ",")
}

func formatDropped(dropped []labels.Dropped) string {
	if len(dropped) == 0 {
		return ""
	}
	var b strings.Builder
	for _, item := range dropped {
		part := item.Key + ":" + string(item.Reason)
		if b.Len() == 0 {
			if len(part) > 512 {
				return "…"
			}
			b.WriteString(part)
			continue
		}
		if b.Len()+1+len(part) > 512 {
			b.WriteString(",…")
			break
		}
		b.WriteByte(',')
		b.WriteString(part)
	}
	return b.String()
}
