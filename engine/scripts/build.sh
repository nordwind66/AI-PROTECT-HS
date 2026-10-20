#!/usr/bin/env bash
# build.sh -- build the engine: shared library, CLI, unit tests, examples.
#
#   scripts/build.sh                  the deliverable: libai_prompt_guard.so with Hyperscan, PCRE2, libstdc++ and libgcc linked IN
#                                     (the target machine needs only glibc). Uses the Hyperscan from scripts/setup.sh. -> build/
#   scripts/build.sh --system-libs    link the system's Hyperscan / PCRE2 dynamically instead (libhyperscan-dev, libpcre2-dev)
#   scripts/build.sh --no-hyperscan   only the explicit pcre2_fallback backend (no Hyperscan needed; slower)
#   scripts/build.sh --asan           Debug + AddressSanitizer / UBSan
#   options: --hs DIR (Hyperscan prefix, default .deps/hyperscan)  --out DIR  --jobs N  --clean
#
# Output: <out>/bin/{libai_prompt_guard.so, ai-prompt-guard, apg_tests, example_*}. The default <out> is build/, with a
# suffix for the variants (build-system, build-fallback, build-asan). Nothing is installed.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
MODE=static; TYPE=Release; OUT=""; HS="$ROOT/.deps/hyperscan"; JOBS="$(nproc 2>/dev/null || echo 2)"; CLEAN=0; EXTRA=(); SUFFIX=""
while [ $# -gt 0 ]; do
  case "$1" in
    --system-libs) MODE=system; SUFFIX=-system ;;
    --no-hyperscan) MODE=fallback; SUFFIX=-fallback ;;
    --asan) TYPE=Debug; SUFFIX=-asan; EXTRA+=("-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer" "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer") ;;
    --hs) HS="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    --clean) CLEAN=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$OUT" ] || OUT="$ROOT/build$SUFFIX"
command -v cmake >/dev/null || { echo "cmake not found: run scripts/setup.sh" >&2; exit 1; }
ARGS=(-S "$ROOT" -B "$OUT" "-DCMAKE_BUILD_TYPE=$TYPE")
case "$MODE" in
  static)
    [ -f "$HS/lib/libhs.a" ] || { echo "$HS/lib/libhs.a not found: run scripts/setup.sh first (or --hs DIR, or --system-libs)" >&2; exit 1; }
    ARGS+=("-DAPG_WITH_HYPERSCAN=ON" "-DAPG_STATIC_DEPS=ON" "-DHYPERSCAN_ROOT=$HS") ;;
  system)   ARGS+=("-DAPG_WITH_HYPERSCAN=ON") ;;
  fallback) ARGS+=("-DAPG_WITH_HYPERSCAN=OFF" "-DAPG_STATIC_DEPS=ON") ;;
esac
ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")
[ "$CLEAN" -eq 1 ] && rm -rf "$OUT"
echo "== configure ($MODE) -> $OUT"
cmake "${ARGS[@]}" >/dev/null
echo "== build ($JOBS jobs)"
cmake --build "$OUT" --parallel "$JOBS" 2>&1 | grep -E "error|warning|Error|Built target (ai_prompt_guard|ai-prompt-guard|apg_tests)" || true
[ -f "$OUT/bin/libai_prompt_guard.so" ] || { echo "build failed: run  cmake --build $OUT  to see the compiler output" >&2; exit 1; }
echo
echo "built: $OUT/bin/{libai_prompt_guard.so, ai-prompt-guard, apg_tests}"
if [ "$MODE" != system ] && command -v ldd >/dev/null; then
  echo "== run-time dependencies of libai_prompt_guard.so (glibc only is expected):"
  ldd "$OUT/bin/libai_prompt_guard.so" | sed 's/^/   /'
fi
echo "next: scripts/test.sh${OUT:+ --build $OUT}"
