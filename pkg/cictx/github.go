package cictx

import (
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
)

const maxEventBytes = 1 << 20

var pullRef = regexp.MustCompile(`^refs/pull/(\d+)/(merge|head)$`)

func applyGitHub(env Env, labels, texts map[string]string) {
	labels["ci.system"] = "github"
	put(labels, "ci.pipeline", env.Getenv("GITHUB_RUN_ID"))
	putURL(labels, "ci.pipeline_url", githubRunURL(env))
	put(labels, "ci.run_attempt", env.Getenv("GITHUB_RUN_ATTEMPT"))
	job := env.Getenv("GITHUB_JOB")
	put(labels, "ci.job", job)
	put(labels, "ci.job_name", job)
	put(labels, "ci.workflow", env.Getenv("GITHUB_WORKFLOW"))
	put(labels, "ci.trigger", env.Getenv("GITHUB_EVENT_NAME"))
	put(labels, "git.repo", env.Getenv("GITHUB_REPOSITORY"))
	ref := firstNonEmpty(env.Getenv("GITHUB_HEAD_REF"), env.Getenv("GITHUB_REF_NAME"))
	put(labels, "git.ref", ref)
	if ref != "" {
		texts["branch"] = ref
	}
	put(labels, "git.base_ref", env.Getenv("GITHUB_BASE_REF"))
	put(labels, "git.sha", env.Getenv("GITHUB_SHA"))
	if mr := pullNumber(env.Getenv("GITHUB_REF")); mr != "" {
		labels["git.mr"] = mr
	}
	applyGitHubPayload(env.Getenv("GITHUB_EVENT_PATH"), labels, texts)
}

func githubActor(env Env) string { return env.Getenv("GITHUB_ACTOR") }

func githubRunURL(env Env) string {
	server := strings.TrimRight(env.Getenv("GITHUB_SERVER_URL"), "/")
	repo := env.Getenv("GITHUB_REPOSITORY")
	run := env.Getenv("GITHUB_RUN_ID")
	if server == "" || repo == "" || run == "" {
		return ""
	}
	return server + "/" + repo + "/actions/runs/" + run
}

func pullNumber(ref string) string {
	m := pullRef.FindStringSubmatch(strings.TrimSpace(ref))
	if m == nil {
		return ""
	}
	return m[1]
}

func applyGitHubPayload(path string, labels, texts map[string]string) {
	if path == "" {
		return
	}
	raw, err := readLimited(path, maxEventBytes)
	if err != nil || len(raw) == 0 || len(raw) > maxEventBytes {
		return
	}
	var event struct {
		PullRequest struct {
			Number int    `json:"number"`
			Title  string `json:"title"`
		} `json:"pull_request"`
		HeadCommit struct {
			Message string `json:"message"`
		} `json:"head_commit"`
	}
	if json.Unmarshal(raw, &event) != nil {
		return
	}
	if labels["git.mr"] == "" && event.PullRequest.Number > 0 {
		labels["git.mr"] = itoa(event.PullRequest.Number)
	}
	if event.PullRequest.Title != "" {
		texts["mr_title"] = event.PullRequest.Title
	}
	if event.HeadCommit.Message != "" {
		texts["commit_message"] = clipMessage(event.HeadCommit.Message)
	}
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is GITHUB_EVENT_PATH from the CI environment
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
