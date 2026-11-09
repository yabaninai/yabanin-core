package cictx

func applyGitLab(env Env, labels, texts map[string]string) {
	labels["ci.system"] = "gitlab"
	put(labels, "ci.pipeline", env.Getenv("CI_PIPELINE_ID"))
	putURL(labels, "ci.pipeline_url", env.Getenv("CI_PIPELINE_URL"))
	put(labels, "ci.job", env.Getenv("CI_JOB_ID"))
	put(labels, "ci.job_name", env.Getenv("CI_JOB_NAME"))
	put(labels, "ci.stage", env.Getenv("CI_JOB_STAGE"))
	put(labels, "ci.workflow", env.Getenv("CI_PIPELINE_NAME"))
	put(labels, "ci.trigger", env.Getenv("CI_PIPELINE_SOURCE"))
	put(labels, "git.repo", env.Getenv("CI_PROJECT_PATH"))
	ref := firstNonEmpty(env.Getenv("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME"), env.Getenv("CI_COMMIT_REF_NAME"))
	put(labels, "git.ref", ref)
	if ref != "" {
		texts["branch"] = ref
	}
	put(labels, "git.base_ref", env.Getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"))
	put(labels, "git.sha", env.Getenv("CI_COMMIT_SHA"))
	put(labels, "git.mr", env.Getenv("CI_MERGE_REQUEST_IID"))
	if title := env.Getenv("CI_MERGE_REQUEST_TITLE"); title != "" {
		texts["mr_title"] = title
	}
	if msg := env.Getenv("CI_COMMIT_MESSAGE"); msg != "" {
		texts["commit_message"] = clipMessage(msg)
	}
}

func gitlabActor(env Env) string { return env.Getenv("GITLAB_USER_LOGIN") }
