"""Small shared helpers: hashing, canonical JSON, time, atomic file writes, project paths."""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Optional


# --------------------------------------------------------------------------------------
# project layout
# --------------------------------------------------------------------------------------
def project_root() -> Path:
    """Repository root = the directory that contains `tools/apg_rules` (this package)."""
    return Path(__file__).resolve().parent.parent.parent


def default_db_path() -> Path:
    return project_root() / "data" / "ai_prompt_rules.db"


def rel_to_root(path: os.PathLike) -> str:
    """Path relative to the project root with forward slashes (used inside DB / reports)."""
    p = Path(path).resolve()
    try:
        return p.relative_to(project_root()).as_posix()
    except ValueError:
        return p.as_posix()


# --------------------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------------------
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: os.PathLike) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_blob_sha1(data: bytes) -> str:
    """Git object id of a blob (lets us verify a file against `git ls-tree` without git)."""
    h = hashlib.sha1()
    h.update(b"blob %d\0" % len(data))
    h.update(data)
    return h.hexdigest()


# --------------------------------------------------------------------------------------
# canonical JSON -- the byte-exact form that is hashed / stored / consumed by the C++ side
# --------------------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace, UTF-8 (no \\u escapes)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False)


def canonical_json_bytes(obj: Any) -> bytes:
    return canonical_json(obj).encode("utf-8")


def pretty_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


# --------------------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------------------
def utc_now() -> str:
    """UTC timestamp, second precision, human readable and sortable: 2026-10-16T07:12:34Z"""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------
# files
# --------------------------------------------------------------------------------------
def ensure_dir(path: os.PathLike) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def atomic_write_bytes(path: os.PathLike, data: bytes) -> None:
    """Write via temp file in the same directory + os.replace (atomic on POSIX and Windows)."""
    path = Path(path)
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def atomic_write_text(path: os.PathLike, text: str) -> None:
    atomic_write_bytes(path, text.encode("utf-8"))


def read_text(path: os.PathLike) -> str:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8")


# --------------------------------------------------------------------------------------
# console output (Windows consoles are often GBK/cp936: never crash on printing)
# --------------------------------------------------------------------------------------
def setup_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - very old Python / redirected stream
            pass


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def chunks(seq: Iterable, size: int):
    buf = []
    for item in seq:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def first_line(text: Optional[str], limit: int = 160) -> str:
    if not text:
        return ""
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line if len(line) <= limit else line[: limit - 1] + "…"
