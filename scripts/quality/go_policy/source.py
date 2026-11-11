# SPDX-License-Identifier: Apache-2.0
"""Source snapshots and bounded subprocesses for local Go policy gates."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root)


def names(raw):
    return [os.fsdecode(p) for p in raw.split(b'\0') if p]


def files(root):
    return sorted(set(names(git(root, 'ls-files', '-cz', '--others', '--exclude-standard'))))


def changes(root, base):
    return sorted(set(names(git(root, 'diff', '--no-renames', '--name-only', '-z', base, '--')) +
                      names(git(root, 'ls-files', '--others', '--exclude-standard', '-z'))))


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def environment(root, executable):
    import shutil
    tool = shutil.which(executable)
    if not tool:
        raise ValueError('Required executable is missing: ' + executable)
    env = dict(os.environ, GOWORK='off', GOFLAGS='')
    go = subprocess.check_output(['go', 'env', '-json', 'GOVERSION', 'GOOS', 'GOARCH',
                                 'CGO_ENABLED', 'GOTOOLCHAIN'], cwd=root, env=env, timeout=30)
    return {'go': json.loads(go), 'executable': str(Path(tool).resolve()),
            'executable_sha256': digest(tool), 'GOWORK': 'off', 'GOFLAGS': ''}


def snapshot(root):
    h = hashlib.sha256()
    for name in files(root):
        path = root / name
        h.update(os.fsencode(name) + b'\0')
        if path.is_symlink():
            h.update(b'link:' + os.fsencode(os.readlink(path)))
        elif path.exists():
            h.update(str(path.stat().st_mode).encode() + b'\0' + path.read_bytes())
        else:
            h.update(b'deleted')
    return {'commit': git(root, 'rev-parse', 'HEAD').decode().strip(), 'sha256': h.hexdigest()}


def archive(root, base, target):
    with tempfile.TemporaryFile() as stream:
        subprocess.run(['git', 'archive', base], cwd=root, stdout=stream, check=True)
        stream.seek(0)
        with tarfile.open(fileobj=stream) as bundle:
            bundle.extractall(target, filter='data')


def copy_source(root, target):
    import shutil
    for name in files(root):
        src, dst = root / name, target / name
        if not src.exists():
            continue
        if src.is_symlink():
            raise ValueError('Source symlink needs explicit handling: ' + name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)


def execute(argv, root, log, seconds=300, stdin=None, env_updates=None):
    env = dict(os.environ, GOWORK='off', GOFLAGS='')
    env.update(env_updates or {})
    with Path(log).open('w') as stream:
        proc = subprocess.Popen(argv, cwd=root, env=env, text=True, stdin=subprocess.PIPE,
                                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            proc.communicate(stdin, timeout=seconds)
        except BaseException:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise
    return proc.returncode


def write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2) + '\n')
