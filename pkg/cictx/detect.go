package cictx

import (
	"context"

	"github.com/reireirei/yabanin/pkg/labels"
)

// Context is the detected CI or local git attribution.
// Texts are extraction sources. They are never copied into Labels whole.
type Context struct {
	System string
	Labels labels.Set
	Texts  map[string]string
}

// Detect reads CI variables and, outside CI, a local git checkout.
// A directory that is not a repository returns an empty system and no git labels.
func Detect(ctx context.Context, env Env, run Runner, dir string) (Context, error) {
	if env == nil {
		env = MapEnv{}
	}
	if ctx == nil {
		return Context{}, errNilContext
	}
	labelsMap := map[string]string{}
	texts := map[string]string{}
	out := Context{Labels: labelsMap, Texts: texts}
	switch {
	case env.Getenv("GITLAB_CI") == "true":
		out.System = "gitlab"
		applyGitLab(env, labelsMap, texts)
		if texts["commit_message"] != "" {
			readTrailers(ctx, run, dir, texts["commit_message"], texts)
		}
	case env.Getenv("GITHUB_ACTIONS") == "true":
		out.System = "github"
		applyGitHub(env, labelsMap, texts)
		if texts["commit_message"] == "" {
			if msg, err := runGit(ctx, run, dir, nil, "log", "-1", "--format=%B"); err == nil {
				texts["commit_message"] = clipMessage(msg)
			}
		}
		readTrailers(ctx, run, dir, texts["commit_message"], texts)
	default:
		if localGit(ctx, run, dir, labelsMap, texts) {
			out.System = "local"
		}
	}
	applyTask(env, labelsMap, texts)
	applyDefaultIssue(labelsMap, texts)
	return out, nil
}
