#!/usr/bin/env bash
# rebuild_db.sh -- rebuild the rule database FROM SCRATCH from the locked upstream commits (rarely needed: the delivered
# data/ai_prompt_rules.db is the normal starting point, and day-to-day changes go through scripts/release.sh).
#
#   scripts/rebuild_db.sh [--db FILE] [--version V]
#
# Steps: materialise third_party/sources from sources.lock.json (needs git + network when they are missing), then
# tools/build_rules_db.py --fresh (import -> manual rules -> verify-tests -> validate --strict -> publish -> reports).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DB="$ROOT/data/ai_prompt_rules.db"; VERSION=""
while [ $# -gt 0 ]; do
  case "$1" in
    --db) DB="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
PY="${APG_PYTHON:-python3}"
RULES=("$PY" -X utf8 "$ROOT/tools/rules.py" --db "$DB")
if ! "${RULES[@]}" sources verify >/dev/null 2>&1; then
  echo "== sources are missing or differ from the lock: re-creating them from the locked commits"
  "${RULES[@]}" sources sync --locked
fi
"$PY" -X utf8 "$ROOT/tools/build_rules_db.py" --db "$DB" --fresh ${VERSION:+--version "$VERSION"}
