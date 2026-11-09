package cictx

import (
	"regexp"
	"strings"

	"github.com/reireirei/yabanin/pkg/labels"
)

const maxCommitBytes = 64 << 10

var defaultIssue = regexp.MustCompile(`\b([A-Z][A-Z0-9]{1,9}-\d{1,7})\b`)

func clipMessage(msg string) string {
	if len(msg) > maxCommitBytes {
		return msg[:maxCommitBytes]
	}
	return msg
}

func put(dst map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if norm, reason := labels.NormalizeValue(value); reason == "" {
		dst[key] = norm
	}
}

func putURL(dst map[string]string, key, value string) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return
	}
	put(dst, key, value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func applyDefaultIssue(labels, texts map[string]string) {
	if labels["issue"] != "" {
		applyProject(labels)
		return
	}
	sources := []string{
		trailer(texts, "Issue"),
		trailer(texts, "Jira"),
		texts["branch"],
		texts["mr_title"],
		texts["commit_message"],
	}
	for _, source := range sources {
		if issue := firstIssue(source); issue != "" {
			labels["issue"] = issue
			break
		}
	}
	applyProject(labels)
}

func applyProject(labels map[string]string) {
	issue := labels["issue"]
	if issue == "" || labels["issue.project"] != "" {
		return
	}
	project, _, ok := strings.Cut(issue, "-")
	if ok && project != "" {
		labels["issue.project"] = project
	}
}

func firstIssue(text string) string {
	m := defaultIssue.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1]
}

func trailer(texts map[string]string, key string) string {
	for name, value := range texts {
		rest, ok := strings.CutPrefix(name, "trailers:")
		if ok && strings.EqualFold(rest, key) {
			return value
		}
	}
	return ""
}

func applyTask(env Env, labels, texts map[string]string) {
	if task := strings.TrimSpace(env.Getenv("YABANIN_TASK")); task != "" {
		put(labels, "task", task)
		return
	}
	if task := trailer(texts, "Yabanin-Task"); task != "" {
		put(labels, "task", task)
	}
}
