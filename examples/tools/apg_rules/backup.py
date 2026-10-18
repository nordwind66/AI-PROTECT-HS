"""Backup / restore / delivery snapshot of the authoritative SQLite database.

* backup    : SQLite online backup API -> a consistent copy even while another process writes.
* snapshot  : backup into a temporary file, make it self-contained (checkpoint, journal_mode=DELETE,
              integrity check, no -wal/-shm side files), then atomic rename. This is the form that
              is committed / shipped: copying only the .db file of a live WAL database could lose
              transactions that are still in the -wal file.
* restore   : validate the source file, keep a safety copy of the current database, replace atomically.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import tempfile
from pathlib import Path

from . import db as dbm
from .util import utc_now


def _backup_to(src_path: Path, dst_path: Path) -> None:
    src = dbm.connect(src_path, readonly=True)
    try:
        dst = sqlite3.connect(str(dst_path))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()


def backup_database(src: Path, out: Path) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp", dir=str(out.parent))
    os.close(fd)
    try:
        _backup_to(src, Path(tmp))
        os.replace(tmp, out)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return out


def _verify_file(path: Path) -> None:
    conn = sqlite3.connect(str(path))
    try:
        row = conn.execute("PRAGMA integrity_check").fetchone()
        if row[0] != "ok":
            raise dbm.DbError(f"integrity_check failed for {path}: {row[0]}")
        conn.execute("PRAGMA foreign_keys = ON")
        bad = conn.execute("PRAGMA foreign_key_check").fetchall()
        if bad:
            raise dbm.DbError(f"foreign_key_check failed for {path}: {len(bad)} violation(s)")
    finally:
        conn.close()


def snapshot_database(src: Path, out: Path, actor: str = "cli") -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=out.name + ".", suffix=".tmp", dir=str(out.parent))
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        _backup_to(src, tmp_path)
        c = sqlite3.connect(str(tmp_path))
        try:
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            c.execute("PRAGMA journal_mode = DELETE")
            c.execute("VACUUM")
        finally:
            c.close()
        _verify_file(tmp_path)
        for suffix in ("-wal", "-shm", "-journal"):
            side = Path(str(tmp_path) + suffix)
            if side.exists():
                side.unlink()
        os.replace(tmp_path, out)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()
    return out


def restore_database(src: Path, dst: Path, force: bool = False) -> None:
    src, dst = Path(src), Path(dst)
    if not src.is_file():
        raise dbm.DbError(f"{src} does not exist")
    _verify_file(src)
    if dst.exists() and not force:
        raise dbm.DbError(f"{dst} exists; use --force (a safety copy is kept as {dst}.before-restore)")
    if dst.exists():
        shutil.copy2(dst, str(dst) + ".before-restore")
    tmp = Path(str(dst) + ".restore.tmp")
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)
    for suffix in ("-wal", "-shm"):
        side = Path(str(dst) + suffix)
        if side.exists():
            side.unlink()
