"""Read upstream repositories straight from git objects -- without a working-tree checkout.

Why: checking out untrusted third-party repositories (a) can fail on Windows (one of the ATR
paths contains ':'), (b) can plant files outside the intended directory, and (c) leaves a `.git`
tree of 100+ MB in the deliverable. Here we only
  * keep a throw-away *bare* object cache in third_party/.cache/<name>.git (safe to delete),
  * list the tree of a pinned commit, and
  * stream selected blobs through `git cat-file --batch`, validating every path ourselves.
Nothing from the upstream repositories is ever executed.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Tuple

from .util import git_blob_sha1


class GitError(RuntimeError):
    pass


class TreeEntry(NamedTuple):
    mode: str
    type: str
    sha: str
    size: int
    path: str


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"       # never block on credentials
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["LC_ALL"] = "C"
    return env


def run_git(git_dir: Path, args: Sequence[str], input_bytes: Optional[bytes] = None,
            check: bool = True, timeout: int = 900) -> bytes:
    cmd = ["git", "--git-dir=" + str(git_dir)] + list(args)
    try:
        proc = subprocess.run(cmd, input=input_bytes, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=_git_env(), timeout=timeout)
    except FileNotFoundError as exc:
        raise GitError("git executable not found in PATH (needed only for `sources sync`)") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git {' '.join(args[:3])} timed out after {timeout}s") from exc
    if check and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git {' '.join(args[:3])} failed (exit {proc.returncode}): {err}")
    return proc.stdout


def ensure_bare_repo(git_dir: Path) -> None:
    if (git_dir / "HEAD").is_file():
        return
    git_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--bare", "--quiet", str(git_dir)], check=True, env=_git_env(),
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def has_commit(git_dir: Path, sha: str) -> bool:
    if not (git_dir / "HEAD").is_file():
        return False
    proc = subprocess.run(["git", "--git-dir=" + str(git_dir), "cat-file", "-e", sha + "^{commit}"],
                          env=_git_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return proc.returncode == 0


def ls_remote(url: str, ref: str) -> str:
    """Resolve a branch / ref to a commit SHA on the remote (network access, no download)."""
    try:
        proc = subprocess.run(["git", "ls-remote", url, ref], env=_git_env(), timeout=120,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError as exc:
        raise GitError("git executable not found in PATH") from exc
    if proc.returncode != 0:
        raise GitError("git ls-remote failed: " + proc.stderr.decode("utf-8", "replace").strip())
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        sha, _, name = line.partition("\t")
        if name.strip() == ref or name.strip().endswith("/" + ref.split("/")[-1]):
            return sha.strip()
    first = proc.stdout.decode("utf-8", "replace").split("\t")[0].strip()
    if not first:
        raise GitError(f"ref {ref!r} not found on {url}")
    return first


def fetch_commit(git_dir: Path, url: str, sha_or_ref: str) -> None:
    ensure_bare_repo(git_dir)
    run_git(git_dir, ["fetch", "--no-tags", "--depth=1", "--quiet", url, sha_or_ref])


def commit_info(git_dir: Path, sha: str) -> Dict[str, str]:
    fmt = "%H%x00%an%x00%aI%x00%cI%x00%s"
    out = run_git(git_dir, ["show", "-s", "--format=" + fmt, sha]).decode("utf-8", "replace").strip()
    h, an, ad, cd, subj = out.split("\0")
    return {"sha": h, "author": an, "author_date": ad, "commit_date": cd, "subject": subj}


_TREE_RE = re.compile(r"^(\d{6}) (\w+) ([0-9a-f]{40,64}) +(-|\d+)$")


def ls_tree(git_dir: Path, sha: str, paths: Sequence[str]) -> List[TreeEntry]:
    args = ["ls-tree", "-r", "-z", "-l", sha]
    if paths:
        args += ["--"] + list(paths)
    raw = run_git(git_dir, args)
    entries: List[TreeEntry] = []
    for rec in raw.split(b"\0"):
        if not rec:
            continue
        head, _, path = rec.partition(b"\t")
        m = _TREE_RE.match(head.decode("ascii", "replace"))
        if not m:
            raise GitError(f"unparsable ls-tree record: {rec[:80]!r}")
        mode, typ, obj, size = m.groups()
        entries.append(TreeEntry(mode, typ, obj, -1 if size == "-" else int(size),
                                 path.decode("utf-8", "surrogateescape")))
    entries.sort(key=lambda e: e.path)
    return entries


def read_blobs(git_dir: Path, shas: Iterable[str]) -> Dict[str, bytes]:
    """Return {sha: content} for the requested blobs using one `cat-file --batch` process."""
    wanted = list(dict.fromkeys(shas))
    if not wanted:
        return {}
    stdin = ("\n".join(wanted) + "\n").encode("ascii")
    raw = run_git(git_dir, ["cat-file", "--batch"], input_bytes=stdin, timeout=1800)
    result: Dict[str, bytes] = {}
    pos = 0
    n = len(raw)
    for _ in wanted:
        eol = raw.find(b"\n", pos)
        if eol == -1:
            raise GitError("truncated cat-file output")
        header = raw[pos:eol].decode("ascii", "replace").split()
        if len(header) == 2 and header[1] == "missing":
            raise GitError(f"object {header[0]} is missing from the cache")
        if len(header) != 3:
            raise GitError(f"unexpected cat-file header {header!r}")
        obj, typ, size_s = header
        size = int(size_s)
        start = eol + 1
        data = raw[start:start + size]
        if len(data) != size:
            raise GitError("truncated cat-file object")
        if typ != "blob":
            raise GitError(f"object {obj} is a {typ}, expected blob")
        if git_blob_sha1(data) != obj:
            raise GitError(f"blob {obj} failed its integrity check")
        result[obj] = data
        pos = start + size + 1
        if pos > n + 1:
            raise GitError("cat-file output overrun")
    return result


# --------------------------------------------------------------------------------------
# path safety for materialisation
# --------------------------------------------------------------------------------------
_WIN_RESERVED = {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
_BAD_CHARS = set('<>:"|?*\\') | {chr(i) for i in range(32)}


def unsafe_path_reason(path: str) -> Optional[str]:
    """Return why `path` must not be written to disk (None = safe on Windows AND POSIX)."""
    if not path or path.startswith("/") or "\\" in path:
        return "absolute or backslash path"
    for part in path.split("/"):
        if part in ("", ".", ".."):
            return "empty / dot component"
        if part.lower().rstrip(". ").startswith(".git"):
            # .gitignore / .gitattributes / .github ... would change how a parent repository
            # treats the vendored tree (EOL conversion, ignore rules) -> never materialised.
            return "git metadata (.git*) is not materialised"
        if any(c in _BAD_CHARS for c in part):
            return "character not allowed in Windows file names"
        if part.endswith((" ", ".")):
            return "trailing space/dot"
        stem = part.split(".")[0].lower()
        if stem in _WIN_RESERVED:
            return "reserved Windows device name"
        if "~" in part and re.search(r"~\d", part):
            return "possible 8.3 short name alias"
    return None
