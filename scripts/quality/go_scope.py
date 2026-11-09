#!/usr/bin/env python3
"""Run a Go analysis command on root-module packages, excluding node_modules."""
import os
from pathlib import Path
import subprocess
import sys


def packages(root):
    # -e + not-.Error: tolerate unloadable directories. The site build copies
    # docs-linked .go samples (mixed package names) into the gitignored
    # web/site/build output; plain `go list ./...` hard-fails there
    # ("found packages X and Y") and would take static/security/tests with it.
    # Error rows emit nothing under this template, so they never enter scope.
    output = subprocess.check_output(
        ["go", "list", "-e", "-f", "{{if not .Error}}{{.Dir}}{{end}}", "./..."],
        cwd=root)
    result = []
    for line in output.decode().splitlines():
        path = Path(line).relative_to(root)
        if "node_modules" not in path.parts and "vendor" not in path.parts:
            result.append("./" + path.as_posix())
    if not result:
        raise ValueError("No root-module Go packages discovered")
    return result


def formatting(root):
    paths = subprocess.check_output(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root)
    files = sorted({os.fsdecode(path) for path in paths.split(b"\0")
                    if path.endswith(b".go") and (root / os.fsdecode(path)).is_file()
                    and "node_modules" not in Path(os.fsdecode(path)).parts})
    if not files:
        raise ValueError("No Go source files to check")
    # gofmt -l reports findings with exit 0; convert nonempty output to failure.
    # Chunked: at full-tree scale (~700 files) a single invocation overflows the
    # exec argument list on macOS (E2BIG) and the tool itself exits 2.
    findings = bytearray()
    chunk_size = 200
    for start in range(0, len(files), chunk_size):
        result = subprocess.run(["gofmt", "-l", *files[start:start + chunk_size]],
                                cwd=root, stdout=subprocess.PIPE, check=True)
        findings += result.stdout
    if findings:
        sys.stdout.buffer.write(findings)
        return 1
    return 0


if __name__ == "__main__":
    try:
        root = Path(__file__).resolve().parents[2]
        if len(sys.argv) < 2:
            raise ValueError("usage: go_scope.py <command> [args ...]")
        if sys.argv[1:] == ["format"]:
            sys.exit(formatting(root))
        scope = packages(root)
        print(f"Go scope: {len(scope)} root-module packages (node_modules excluded)", flush=True)
        os.chdir(root)
        os.execvp(sys.argv[1], sys.argv[1:] + scope)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Go scope error: {exc}", file=sys.stderr)
        sys.exit(2)
