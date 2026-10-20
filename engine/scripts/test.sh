#!/usr/bin/env bash
# test.sh -- the engine's own tests: C++ unit tests (C ABI, hot reload, concurrency, compiler, normalisation vectors) and the
# schema / static checks (Python standard library only; skipped when python3 is missing).
#
#   scripts/test.sh [--build DIR]        DIR defaults to build/
#
# The engine tests need no rule database. How a real rule package behaves is tested by the rules project (rules/scripts/test.sh).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$ROOT/build"
while [ $# -gt 0 ]; do
  case "$1" in
    --build) BUILD="$2"; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -x "$BUILD/bin/apg_tests" ] || { echo "$BUILD/bin/apg_tests not found: run scripts/build.sh first" >&2; exit 1; }
status=0
echo "== C++ unit tests"
( cd "$ROOT" && "$BUILD/bin/apg_tests" ) || status=1
PY="${APG_PYTHON:-python3}"
if command -v "$PY" >/dev/null; then
  echo "== schema and static checks"
  ( cd "$ROOT" && "$PY" -X utf8 -m unittest discover -s tests/python ) || status=1
else
  echo "python3 not found: schema and static checks skipped"
fi
if [ "$status" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit "$status"
