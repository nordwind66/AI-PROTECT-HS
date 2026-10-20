#!/usr/bin/env bash
# test.sh -- the rules project's tests.
#
#   scripts/test.sh                              unit tests of the tooling (Python standard library only)
#   scripts/test.sh --engine BUILD_DIR           plus, with the engine built there (BUILD_DIR/bin/{ai-prompt-guard,libai_prompt_guard.so}):
#                                                end-to-end (compile -> differential against the reference engine -> tamper ->
#                                                release flow -> examples) and the shared-library differential check
#        [--backend hyperscan|pcre2_fallback|both]   backend of the end-to-end test (default hyperscan; compiling takes minutes)
#
# The end-to-end test works on a COPY of the rule database (a temporary directory) so data/ai_prompt_rules.db stays untouched.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENGINE=""; BACKEND=hyperscan
while [ $# -gt 0 ]; do
  case "$1" in
    --engine) ENGINE="$2"; shift ;;
    --backend) BACKEND="$2"; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
PY="${APG_PYTHON:-python3}"
status=0
echo "== unit tests"
( cd "$ROOT" && "$PY" -X utf8 -m unittest discover -s tests/python ) || status=1
if [ -n "$ENGINE" ]; then
  CLI="$ENGINE/bin/ai-prompt-guard"; LIB="$ENGINE/bin/libai_prompt_guard.so"
  [ -x "$CLI" ] && [ -f "$LIB" ] || { echo "$CLI / $LIB not found: build the engine first" >&2; exit 1; }
  WORK="$(mktemp -d)"
  cp "$ROOT/data/ai_prompt_rules.db" "$WORK/rules.db"
  echo "== end-to-end with the engine in $ENGINE (backend: $BACKEND)"
  ( cd "$ROOT" && "$PY" -X utf8 tests/e2e/run_e2e.py --cli "$CLI" --workdir "$WORK/work" --db "$WORK/rules.db" --backend "$BACKEND" \
      --lib "$LIB" --examples-dir "$ENGINE/bin" --clean --report "$WORK/report.json" ) || status=1
fi
echo
if [ "$status" -eq 0 ]; then echo "ALL TESTS PASSED"; else echo "SOME TESTS FAILED"; fi
exit "$status"
