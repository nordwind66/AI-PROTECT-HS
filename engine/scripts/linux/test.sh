#!/usr/bin/env bash
# test.sh -- the engine's own tests: C++ unit tests (CTest: cpp_unit; incl. C ABI, hot reload, concurrency, compiler) and the
# schema / static checks (Python standard library only, skipped when python3 is missing).
#
#   scripts/linux/test.sh [--build-dir build/linux]
#
# The engine tests need no rule database and no Python. How a real rule set behaves is tested by the rules project
# (rules/tests: differential test against the Python reference engine, run with the engine you built).
# This script does NOT run benchmarks (scripts/linux/bench.sh is separate and explicit).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$ROOT/build/linux"
while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) BUILD="$2"; shift ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -x "$BUILD/bin/apg_tests" ] || { echo "$BUILD/bin/apg_tests not found: run scripts/linux/build.sh first" >&2; exit 1; }
status=0
echo "== C++ unit tests (CTest: cpp_unit)"
( cd "$BUILD" && ctest -R cpp_unit --output-on-failure ) || status=1
PY="${APG_PYTHON:-python3}"
if command -v "$PY" >/dev/null; then
  echo "== schema and static checks (Python standard library only)"
  ( cd "$ROOT" && "$PY" -X utf8 -m unittest discover -s tests/python ) || status=1
else
  echo "python3 not found: schema and static checks SKIPPED"
fi
if [ "$status" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit "$status"
