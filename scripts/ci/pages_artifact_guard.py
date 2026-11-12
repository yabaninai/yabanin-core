#!/usr/bin/env python3
"""Pre-deploy guard for the Pages workflow (see .github/workflows/pages.yml).

Asserts, before actions/deploy-pages runs, that exactly one live artifact with
the agreed name (PAGES_ARTIFACT env, single-sourced in the workflow) is visible
for this workflow run. Short retries absorb artifact-service read-after-write
lag: run 43162707281 failed with "No artifacts named github-pages" about 0.4s
after the upload step finalized, while the artifact was attached to the run.

Failure modes caught before the deploy step:
  - upload step skipped or conditioned out while deploy still runs
  - upload `name` != deploy `artifact_name` (both read PAGES_ARTIFACT)
  - duplicate uploads (deploy-pages rejects multiple matching artifacts)
  - workflow token missing the `actions: read` permission (HTTP 401/403)

Exits 0 only when exactly one live matching artifact is visible.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request


def list_artifacts(api_url, repository, run_id, name, token):
    """Return the run-artifact listing page filtered to `name` (GitHub REST)."""
    url = (
        f"{api_url}/repos/{repository}/actions/runs/{run_id}"
        f"/artifacts?name={name}&per_page=100"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "pages-artifact-guard",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    name = os.environ.get("PAGES_ARTIFACT", "github-pages")
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    attempts = int(os.environ.get("PAGES_GUARD_ATTEMPTS", "6"))
    interval = float(os.environ.get("PAGES_GUARD_INTERVAL_SECONDS", "5"))

    missing = [
        label
        for label, value in (
            ("GITHUB_REPOSITORY", repository),
            ("GITHUB_RUN_ID", run_id),
            ("GITHUB_TOKEN/GH_TOKEN", token),
        )
        if not value
    ]
    if missing:
        print(f"::error::missing environment: {', '.join(missing)}")
        return 1

    for attempt in range(1, attempts + 1):
        try:
            page = list_artifacts(api_url, repository, run_id, name, token)
        except urllib.error.HTTPError as error:
            print(
                f"::error::artifact listing returned HTTP {error.code}; the "
                "workflow token needs 'actions: read' for this check"
            )
            return 1
        except (urllib.error.URLError, OSError) as error:
            print(f"::error::artifact listing request failed: {error}")
            return 1

        live = [a for a in page.get("artifacts", []) if not a.get("expired")]
        if len(live) == 1:
            artifact = live[0]
            print(
                f"artifact '{name}' visible: id={artifact['id']} "
                f"size={artifact['size_in_bytes']} digest={artifact.get('digest')}"
            )
            return 0
        if len(live) > 1:
            print(
                f"::error::{len(live)} live artifacts named '{name}'; "
                "deploy-pages rejects duplicates - check for duplicated upload steps"
            )
            return 1
        print(
            f"attempt {attempt}/{attempts}: artifact '{name}' not visible yet; "
            "absorbing artifact-service read-after-write lag"
        )
        if attempt < attempts:
            time.sleep(interval)

    print(
        f"::error::no live artifact named '{name}' for run {run_id} after "
        f"{attempts} attempts; deploy-pages would fail with \"No artifacts "
        f"named '{name}'\". Check that the upload-pages-artifact step ran "
        "unconditionally and that upload name and deploy artifact_name both "
        "reference PAGES_ARTIFACT."
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
