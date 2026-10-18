#!/usr/bin/env bash
# test.sh -- run every functional test that exists for Linux:
#   1  CTest:  cpp_unit (C++ unit tests incl. C ABI, hot reload, concurrency), python_unit, e2e_compile_scan
#   2  differential test of the compiled engine against the Python reference engine (inside e2e)
#   3  C / C++ / dlopen / Python-ctypes example programs (inside e2e)
#
#   scripts/linux/test.sh [--build-dir build/linux] [--backend hyperscan|pcre2_fallback|both] [--db FILE] [--no-e2e]
#
# This script does NOT run benchmarks (scripts/linux/bench.sh is separate and explicit). It works on a COPY of the
# rule database (build/<dir>/e2e/rules.db) so that the delivered data/ai_prompt_rules.db stays byte-identical.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
BUILD="$ROOT/build/linux"; BACKEND=hyperscan; DB="$ROOT/data/ai_prompt_rules.db"; E2E=1
while [ $# -gt 0 ]; do
  case "$1" in
    --build-dir) BUILD="$2"; shift ;;
    --backend) BACKEND="$2"; shift ;;
    --db) DB="$2"; shift ;;
    --no-e2e) E2E=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
PY="${APG_PYTHON:-python3}"
[ -x "$BUILD/bin/apg_tests" ] || { echo "$BUILD/bin/apg_tests not found: run scripts/linux/build.sh first" >&2; exit 1; }
status=0

echo "== C++ unit tests (CTest: cpp_unit)"
( cd "$BUILD" && ctest -R cpp_unit --output-on-failure ) || status=1

echo "== Python unit tests of the rule tooling"
( cd "$ROOT" && "$PY" -X utf8 -m unittest discover -s tests/python ) || status=1

if [ "$E2E" -eq 1 ]; then
  echo "== end-to-end: compile -> load -> differential -> tamper -> release flow -> examples (backend: $BACKEND)"
  mkdir -p "$BUILD/e2e"
  cp -f "$DB" "$BUILD/e2e/rules.db"
  LIB="$(ls "$BUILD"/bin/libai_prompt_guard.so* 2>/dev/null | head -n1 || true)"
  ( cd "$ROOT" && "$PY" -X utf8 tests/e2e/run_e2e.py --cli "$BUILD/bin/ai-prompt-guard" --workdir "$BUILD/e2e/work" --db "$BUILD/e2e/rules.db" \
      --backend "$BACKEND" ${LIB:+--lib "$LIB"} --examples-dir "$BUILD/bin" --clean --report "$BUILD/e2e/report.json" ) || status=1
fi
echo
if [ "$status" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED (see above); report: $BUILD/e2e/report.json"; fi
exit "$status"
