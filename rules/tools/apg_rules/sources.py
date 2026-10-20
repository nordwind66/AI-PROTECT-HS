"""Upstream source management: pin (lock), fetch, materialise safely, verify.

Files
  third_party/sources.def.json   what the sources are (URL, branch, paths, expected licence)
  third_party/sources.lock.json  what was actually fetched (commit, licence, per-file hashes)
  third_party/sources/<name>/    clean snapshot of the pinned commit (no .git)
  third_party/.cache/<name>.git  disposable bare object cache (can be deleted any time)
"""
from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .gitsrc import (GitError, commit_info, fetch_commit, has_commit, ls_remote, ls_tree,
                     read_blobs, unsafe_path_reason)
from .util import (atomic_write_text, canonical_json, ensure_dir, pretty_json, project_root,
                   read_text, sha256_bytes, sha256_file, utc_now, git_blob_sha1)


def third_party_dir() -> Path:
    return project_root() / "third_party"


def def_path() -> Path:
    return third_party_dir() / "sources.def.json"


def lock_path() -> Path:
    return third_party_dir() / "sources.lock.json"


def cache_dir() -> Path:
    return third_party_dir() / ".cache"


def sources_root() -> Path:
    return third_party_dir() / "sources"


@dataclass
class SourceDef:
    source_id: str
    name: str
    display_name: str
    repo_url: str
    branch: str
    license_expected: str
    license_files: List[str]
    importer: str
    include_paths: List[str] = field(default_factory=list)

    @property
    def dir(self) -> Path:
        return sources_root() / self.name

    @property
    def cache(self) -> Path:
        return cache_dir() / (self.name + ".git")


def load_defs() -> Dict[str, SourceDef]:
    doc = json.loads(read_text(def_path()))
    out: Dict[str, SourceDef] = {}
    for item in doc["sources"]:
        sd = SourceDef(
            source_id=item["source_id"], name=item["name"], display_name=item["display_name"],
            repo_url=item["repo_url"], branch=item.get("branch", "main"),
            license_expected=item["license_expected"], license_files=list(item["license_files"]),
            importer=item["importer"], include_paths=list(item.get("include_paths", [])),
        )
        if sd.source_id in out:
            raise ValueError(f"duplicate source_id {sd.source_id}")
        out[sd.source_id] = sd
    return out


def load_lock() -> Optional[Dict[str, Any]]:
    p = lock_path()
    if not p.is_file():
        return None
    return json.loads(read_text(p))


def detect_license(text: str) -> str:
    low = text.lower()
    if "permission is hereby granted, free of charge" in low and "mit license" in low:
        return "MIT"
    if "permission is hereby granted, free of charge" in low:
        return "MIT"  # MIT text without the heading
    if "apache license" in low and "version 2.0" in low:
        return "Apache-2.0"
    return "UNKNOWN"


# ---------------------------------------------------------------------------------------------
def _materialise(sd: SourceDef, sha: str, log: Callable[[str], None]) -> Dict[str, Any]:
    """Write the pinned tree into third_party/sources/<name>; return the per-source lock entry."""
    cache = sd.cache
    entries = ls_tree(cache, sha, sd.include_paths)
    if not entries:
        raise GitError(f"{sd.source_id}: no files at commit {sha} for paths {sd.include_paths}")
    keep = []
    skipped: List[Dict[str, str]] = []
    for e in entries:
        if e.type != "blob" or e.mode not in ("100644", "100755"):
            skipped.append({"path": e.path, "reason": f"object mode {e.mode}/{e.type} (symlink or submodule)"})
            continue
        why = unsafe_path_reason(e.path)
        if why:
            skipped.append({"path": e.path, "reason": why})
            continue
        keep.append(e)
    blobs = read_blobs(cache, [e.sha for e in keep])

    staging = sources_root() / (".staging-" + sd.name)
    if staging.exists():
        shutil.rmtree(staging)
    ensure_dir(staging)
    files: List[Dict[str, Any]] = []
    for e in keep:
        data = blobs[e.sha]
        target = staging / Path(*e.path.split("/"))
        ensure_dir(target.parent)
        with open(target, "wb") as fh:
            fh.write(data)
        files.append({"path": e.path, "size": len(data), "sha256": sha256_bytes(data),
                      "git_blob": e.sha})
    # atomic-ish swap
    final = sd.dir
    if final.exists():
        shutil.rmtree(final)
    staging.rename(final)

    lic_text = ""
    lic_path = None
    for cand in sd.license_files:
        if any(f["path"] == cand for f in files):
            lic_path = cand
            lic_text = (final / Path(*cand.split("/"))).read_text(encoding="utf-8", errors="replace")
            break
    spdx = detect_license(lic_text) if lic_text else "UNKNOWN"
    info = commit_info(cache, sha)
    tree_digest = sha256_bytes("\n".join(f"{f['path']}\0{f['sha256']}" for f in files).encode("utf-8"))
    return {
        "source_id": sd.source_id,
        "name": sd.name,
        "repo_url": sd.repo_url,
        "branch": sd.branch,
        "commit_sha": sha,
        "commit_date": info["commit_date"],
        "commit_author_date": info["author_date"],
        "commit_subject": info["subject"],
        "license_spdx_detected": spdx,
        "license_spdx_expected": sd.license_expected,
        "license_file": lic_path,
        "license_sha256": sha256_bytes(lic_text.encode("utf-8")) if lic_text else None,
        "include_paths": sd.include_paths,
        "importer": sd.importer,
        "file_count": len(files),
        "tree_sha256": tree_digest,
        "files": files,
        "skipped": skipped,
    }


def sync(source_ids: Optional[List[str]] = None, update: bool = False, offline: bool = False,
         log: Callable[[str], None] = print) -> Dict[str, Any]:
    """Make third_party/sources/* match the lock (or re-lock to the branch head with update=True)."""
    defs = load_defs()
    ids = source_ids or list(defs)
    for i in ids:
        if i not in defs:
            raise KeyError(f"unknown source {i!r}; known: {', '.join(defs)}")
    lock = load_lock() or {"lock_version": 1, "sources": {}}
    ensure_dir(cache_dir())
    ensure_dir(sources_root())
    for sid in ids:
        sd = defs[sid]
        pinned = lock["sources"].get(sid, {}).get("commit_sha")
        if update or not pinned:
            if offline:
                if not pinned:
                    raise GitError(f"{sid}: no lock entry and --offline given")
                sha = pinned
            else:
                sha = ls_remote(sd.repo_url, "refs/heads/" + sd.branch)
                log(f"[{sid}] branch {sd.branch} -> {sha}")
        else:
            sha = pinned
        if not has_commit(sd.cache, sha):
            if offline:
                raise GitError(f"{sid}: commit {sha} is not in the local cache and --offline was given")
            log(f"[{sid}] fetching {sd.repo_url} @ {sha} ...")
            fetch_commit(sd.cache, sd.repo_url, sha)
        old = lock["sources"].get(sid)
        entry = _materialise(sd, sha, log)
        if old and old.get("commit_sha") == sha and not update:
            # reproducibility check: re-materialising a locked commit must give identical bytes
            if old.get("tree_sha256") != entry["tree_sha256"]:
                raise GitError(f"{sid}: locked tree hash {old.get('tree_sha256')} != re-materialised "
                               f"{entry['tree_sha256']} (lock file and upstream disagree)")
            entry["locked_at"] = old.get("locked_at", utc_now())
        else:
            entry["locked_at"] = utc_now()
        if entry["license_spdx_detected"] != sd.license_expected:
            log(f"[{sid}] WARNING: licence detected as {entry['license_spdx_detected']}, "
                f"expected {sd.license_expected} -- review before redistributing")
        lock["sources"][sid] = entry
        log(f"[{sid}] {entry['file_count']} files, {len(entry['skipped'])} skipped, "
            f"licence {entry['license_spdx_detected']}, tree {entry['tree_sha256'][:12]}")
    lock["lock_version"] = 1
    lock["tool"] = {"name": TOOL_NAME, "version": TOOL_VERSION}
    lock["generated_at"] = utc_now()
    atomic_write_text(lock_path(), pretty_json(lock))
    _write_license_copies(lock, defs)
    return lock


def _write_license_copies(lock: Dict[str, Any], defs: Dict[str, SourceDef]) -> None:
    """Keep verbatim copies of the upstream licence texts in LICENSES/ (attribution duty)."""
    out_dir = ensure_dir(project_root() / "LICENSES")
    for sid, entry in lock["sources"].items():
        sd = defs.get(sid)
        if not sd or not entry.get("license_file"):
            continue
        src = sd.dir / Path(*entry["license_file"].split("/"))
        if src.is_file():
            spdx = entry["license_spdx_detected"]
            dst = out_dir / f"{sd.name}.{spdx}.LICENSE.txt"
            dst.write_bytes(src.read_bytes())


def verify(source_ids: Optional[List[str]] = None) -> List[str]:
    """Compare the materialised trees with the lock. Returns a list of problems (empty = OK)."""
    problems: List[str] = []
    lock = load_lock()
    if lock is None:
        return ["sources.lock.json does not exist -- run `rules.py sources sync --update`"]
    defs = load_defs()
    for sid in (source_ids or list(defs)):
        entry = lock["sources"].get(sid)
        if entry is None:
            problems.append(f"{sid}: not locked")
            continue
        root = defs[sid].dir
        if not root.is_dir():
            problems.append(f"{sid}: {root} missing (run `sources sync --locked`)")
            continue
        listed = set()
        for f in entry["files"]:
            listed.add(f["path"])
            p = root / Path(*f["path"].split("/"))
            if not p.is_file():
                problems.append(f"{sid}: missing file {f['path']}")
            elif sha256_file(p) != f["sha256"]:
                problems.append(f"{sid}: hash mismatch {f['path']}")
        for p in root.rglob("*"):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                if rel not in listed:
                    problems.append(f"{sid}: file not in lock: {rel}")
        if entry.get("license_spdx_detected") != entry.get("license_spdx_expected"):
            problems.append(f"{sid}: licence {entry.get('license_spdx_detected')} != expected "
                            f"{entry.get('license_spdx_expected')}")
    return problems
