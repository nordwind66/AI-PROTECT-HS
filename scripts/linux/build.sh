#!/usr/bin/env bash
# build.sh -- configure and build the shared library, the static library, the CLI, the tests and the examples (Release).
#
#   scripts/linux/build.sh                      Hyperscan + PCRE2 + SQLite from the system
#   scripts/linux/build.sh --no-hyperscan       explicit pcre2_fallback backend only (no Hyperscan installed)
#   scripts/linux/build.sh --asan               Debug + AddressSanitizer / UBSan (separate build directory)
#   scripts/linux/build.sh --prefix-path DIR    extra CMAKE_PREFIX_PATH (a self-built Hyperscan / PCRE2)
#   scripts/linux/build.sh --jobs N | --build-dir DIR | --clean
#
# Output (all in <build-dir>/bin): libai_prompt_guard.so, ai-prompt-guard, apg_tests, example_* ; <build-dir>/lib: libai_prompt_guard.a
# Nothing is installed; missing dependencies produce the CMake error with the hint from scripts/linux/setup_deps.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HS=ON; BUILD_TYPE=Release; BUILD_DIR=""; JOBS="$(nproc 2>/dev/null || echo 2)"; PREFIX=""; CLEAN=0; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-hyperscan) HS=OFF ;;
    --asan) BUILD_TYPE=Debug; EXTRA+=("-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer" "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer"); [ -z "$BUILD_DIR" ] && BUILD_DIR="$ROOT/build/linux-asan" ;;
    --prefix-path) PREFIX="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    --build-dir) BUILD_DIR="$2"; shift ;;
    --clean) CLEAN=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$BUILD_DIR" ]; then
  if [ "$HS" = OFF ]; then BUILD_DIR="$ROOT/build/linux-fallback"; else BUILD_DIR="$ROOT/build/linux"; fi
fi
command -v cmake >/dev/null || { echo "cmake not found: run scripts/linux/setup_deps.sh" >&2; exit 1; }
[ "$CLEAN" -eq 1 ] && rm -rf "$BUILD_DIR"
ARGS=(-S "$ROOT" -B "$BUILD_DIR" "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" "-DAPG_WITH_HYPERSCAN=$HS")
[ -n "$PREFIX" ] && ARGS+=("-DCMAKE_PREFIX_PATH=$PREFIX")
ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")
echo "== configure: cmake ${ARGS[*]}"
cmake "${ARGS[@]}"
echo "== build ($JOBS jobs)"
cmake --build "$BUILD_DIR" --parallel "$JOBS"
echo
echo "Built into $BUILD_DIR"
ls -1 "$BUILD_DIR"/bin/libai_prompt_guard.* "$BUILD_DIR"/bin/ai-prompt-guard "$BUILD_DIR"/bin/apg_tests 2>/dev/null || true
echo "Next: scripts/linux/init_rules.sh   then   scripts/linux/test.sh"
