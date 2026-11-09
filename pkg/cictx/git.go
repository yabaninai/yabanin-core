package cictx

import (
	"context"
	"net/url"
	"strings"
	"time"
)

const gitCallTimeout = 2 * time.Second

func runGit(ctx context.Context, run Runner, dir string, stdin []byte, args ...string) (string, error) {
	if run == nil {
		return "", errNoRunner
	}
	cctx, cancel := context.WithTimeout(ctx, gitCallTimeout)
	defer cancel()
	return run.Run(cctx, dir, stdin, "git", args...)
}

// normalizeRepo turns an origin URL into group/project.
// https://host/group/proj.git and git@host:group/proj.git both become group/proj.
func normalizeRepo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.TrimSuffix(raw, ".git")
	if rest, ok := strings.CutPrefix(raw, "git@"); ok {
		_, path, found := strings.Cut(rest, ":")
		if found {
			return strings.Trim(path, "/")
		}
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		return strings.Trim(strings.TrimSuffix(parsed.Path, ".git"), "/")
	}
	return strings.Trim(raw, "/")
}

func localGit(ctx context.Context, run Runner, dir string, labels map[string]string, texts map[string]string) bool {
	remote, err := runGit(ctx, run, dir, nil, "remote", "get-url", "origin")
	if err != nil || strings.TrimSpace(remote) == "" {
		return false
	}
	if repo := normalizeRepo(remote); repo != "" {
		labels["git.repo"] = repo
	}
	ref, err := runGit(ctx, run, dir, nil, "rev-parse", "--abbrev-ref", "HEAD")
	if err == nil {
		ref = strings.TrimSpace(ref)
		if ref != "" && ref != "HEAD" {
			labels["git.ref"] = ref
			texts["branch"] = ref
		}
	}
	sha, err := runGit(ctx, run, dir, nil, "rev-parse", "--short", "HEAD")
	if err == nil {
		sha = strings.TrimSpace(sha)
		if sha != "" {
			labels["git.sha"] = sha
		}
	}
	if msg, err := runGit(ctx, run, dir, nil, "log", "-1", "--format=%B"); err == nil {
		texts["commit_message"] = clipMessage(msg)
		readTrailers(ctx, run, dir, texts["commit_message"], texts)
	}
	return true
}

func readTrailers(ctx context.Context, run Runner, dir, message string, texts map[string]string) {
	if strings.TrimSpace(message) == "" || run == nil {
		return
	}
	out, err := runGit(ctx, run, dir, []byte(message), "interpret-trailers", "--parse")
	if err != nil {
		return
	}
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		texts["trailers:"+key] = value
	}
}
