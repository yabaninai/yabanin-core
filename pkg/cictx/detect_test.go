package cictx

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/reireirei/yabanin/pkg/labels"
)

type fakeRun struct {
	out   map[string]string
	stdin string
}

func (f *fakeRun) Run(ctx context.Context, dir string, stdin []byte, name string, args ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	f.stdin = string(stdin)
	key := name + " " + strings.Join(args, " ")
	if f.out == nil {
		return "", errors.New("not a git repository")
	}
	got, ok := f.out[key]
	if !ok {
		return "", errors.New("not a git repository")
	}
	return got, nil
}

func loadEnv(t *testing.T, name string) MapEnv {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: name is a testdata fixture basename, not user input
	if err != nil {
		t.Fatal(err)
	}
	var env MapEnv
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestDetectGitLabPushTrailerBeatsBranch(t *testing.T) {
	env := loadEnv(t, "gitlab_push.json")
	run := &fakeRun{out: map[string]string{
		"git interpret-trailers --parse": "Issue: PAY-1\n",
	}}
	got, err := Detect(context.Background(), env, run, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.System != "gitlab" || got.Labels["ci.pipeline"] != "100" || got.Labels["git.repo"] != "group/proj" {
		t.Fatalf("%+v", got.Labels)
	}
	if got.Labels["issue"] != "PAY-1" || got.Labels["issue.project"] != "PAY" {
		t.Fatalf("issue %#v texts %#v", got.Labels, got.Texts)
	}
	if _, ok := got.Labels["ci.actor"]; ok {
		t.Fatal("actor must be absent by default")
	}
	if strings.Contains(joinValues(got.Labels), "fix: note") {
		t.Fatal("commit message leaked into labels")
	}
	built, _, _, err := Build(got, &Profile{Version: 1, Labels: ProfileLabels{IncludeActor: true}}, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if built["ci.actor"] != "ada" {
		t.Fatalf("actor %q", built["ci.actor"])
	}
}

func TestDetectGitLabMR(t *testing.T) {
	env := loadEnv(t, "gitlab_mr.json")
	got, err := Detect(context.Background(), env, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels["git.mr"] != "42" || got.Texts["mr_title"] != "Add PAY-77 support" {
		t.Fatalf("%#v %#v", got.Labels, got.Texts)
	}
	if got.Labels["git.ref"] != "feature/OTHER-1" || got.Labels["git.base_ref"] != "main" {
		t.Fatalf("ref %#v", got.Labels)
	}
	if got.Labels["issue"] != "OTHER-1" {
		t.Fatalf("branch should win over title, got %q", got.Labels["issue"])
	}
}

func TestDetectGitHubPush(t *testing.T) {
	env := loadEnv(t, "github_push.json")
	got, err := Detect(context.Background(), env, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.System != "github" || got.Labels["ci.job"] != "build" || got.Labels["git.repo"] != "org/app" {
		t.Fatalf("%#v", got.Labels)
	}
	if got.Labels["ci.pipeline_url"] != "https://github.com/org/app/actions/runs/55" {
		t.Fatalf("url %q", got.Labels["ci.pipeline_url"])
	}
	if _, ok := got.Labels["ci.actor"]; ok {
		t.Fatal("actor")
	}
}

func TestDetectGitHubPullRequest(t *testing.T) {
	env := loadEnv(t, "github_push.json")
	env["GITHUB_EVENT_NAME"] = "pull_request"
	env["GITHUB_REF"] = "refs/pull/17/merge"
	env["GITHUB_HEAD_REF"] = "feature/no-ticket"
	env["GITHUB_BASE_REF"] = "main"
	env["GITHUB_EVENT_PATH"] = filepath.Join("testdata", "github_pull_request.json")
	got, err := Detect(context.Background(), env, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.Labels["git.mr"] != "17" || got.Texts["mr_title"] != "Ship PAY-88" {
		t.Fatalf("%#v %#v", got.Labels, got.Texts)
	}
	if got.Labels["issue"] != "PAY-88" {
		t.Fatalf("issue %q", got.Labels["issue"])
	}
}

func TestDetectLocalAndTaskTrailer(t *testing.T) {
	run := &fakeRun{out: map[string]string{
		"git remote get-url origin":       "git@github.com:group/proj.git",
		"git rev-parse --abbrev-ref HEAD": "feature/PAY-5-x",
		"git rev-parse --short HEAD":      "abcdef",
		"git log -1 --format=%B":          "hello",
		"git interpret-trailers --parse":  "Yabanin-Task: billing",
	}}
	got, err := Detect(context.Background(), MapEnv{}, run, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.System != "local" || got.Labels["git.repo"] != "group/proj" || got.Labels["git.sha"] != "abcdef" {
		t.Fatalf("%#v", got.Labels)
	}
	if got.Labels["issue"] != "PAY-5" || got.Labels["task"] != "billing" {
		t.Fatalf("labels %#v", got.Labels)
	}
	env := MapEnv{"YABANIN_TASK": "from-env"}
	withTask, err := Detect(context.Background(), env, run, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if withTask.Labels["task"] != "from-env" {
		t.Fatalf("task %q", withTask.Labels["task"])
	}
}

func TestDetectNotARepository(t *testing.T) {
	got, err := Detect(context.Background(), MapEnv{}, &fakeRun{}, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if got.System != "" || len(got.Labels) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestNormalizeRepo(t *testing.T) {
	cases := map[string]string{
		"https://github.com/group/proj.git": "group/proj",
		"git@github.com:group/proj.git":     "group/proj",
		"ssh://git@github.com/group/proj":   "group/proj",
	}
	for raw, want := range cases {
		if got := normalizeRepo(raw); got != want {
			t.Fatalf("%s -> %q", raw, got)
		}
	}
}

func TestBuildExtractDoesNotCopyText(t *testing.T) {
	ctx := Context{
		Labels: labels.Set{},
		Texts:  map[string]string{"branch": "feature/PAY-1-api", "commit_message": "a long commit message"},
	}
	profile := &Profile{
		Version:   1,
		OnMissing: "warn",
		Require:   []string{"team"},
		Labels: ProfileLabels{Extract: []ExtractRule{{
			Label: "issue", From: []string{"branch", "commit_message"}, Regex: `\b(PAY-\d+)\b`, Template: "$1",
		}}},
	}
	got, _, missing, err := Build(ctx, profile, MapEnv{}, nil)
	if err != nil || got["issue"] != "PAY-1" || len(missing) != 1 || missing[0] != "team" {
		t.Fatalf("got %#v missing %#v err %v", got, missing, err)
	}
	for _, value := range got {
		if strings.Contains(value, "long commit") {
			t.Fatal(value)
		}
	}
}

func TestPipelineURLTooLongIsOmitted(t *testing.T) {
	env := MapEnv{
		"GITLAB_CI":       "true",
		"CI_PIPELINE_URL": strings.Repeat("a", 129),
		"CI_PROJECT_PATH": "group/proj",
		"CI_COMMIT_SHA":   "abc",
	}
	got, err := Detect(context.Background(), env, nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Labels["ci.pipeline_url"]; ok || got.Labels["git.repo"] != "group/proj" {
		t.Fatalf("%#v", got.Labels)
	}
}

func joinValues(set map[string]string) string {
	var b strings.Builder
	for _, value := range set {
		b.WriteString(value)
		b.WriteByte('\n')
	}
	return b.String()
}
