#!/usr/bin/env bash
# build.sh -- configure and build the shared library, the static library, the CLI, the tests and the examples (Release).
#
#   scripts/linux/build.sh                      Hyperscan + PCRE2 + SQLite from the system
#   scripts/linux/build.sh --no-hyperscan       explicit pcre2_fallback backend only (no Hyperscan installed)
#   scripts/linux/build.sh --static --hyperscan-root DIR
#                                               self-contained libai_prompt_guard.so: Hyperscan, PCRE2, libstdc++ and libgcc linked IN
#                                               (the target machine needs only glibc). DIR = prefix of a -fPIC static Hyperscan,
#                                               see scripts/linux/build_hyperscan_static.sh. Separate build directory build/linux-static
#   scripts/linux/build.sh --asan               Debug + AddressSanitizer / UBSan (separate build directory)
#   scripts/linux/build.sh --prefix-path DIR    extra CMAKE_PREFIX_PATH (a self-built Hyperscan / PCRE2)
#   scripts/linux/build.sh --jobs N | --build-dir DIR | --clean
#
# Output (all in <build-dir>/bin): libai_prompt_guard.so, ai-prompt-guard, apg_tests, example_* ; <build-dir>/lib: libai_prompt_guard.a
# Nothing is installed; missing dependencies produce the CMake error with the hint from scripts/linux/setup_deps.sh.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
HS=ON; BUILD_TYPE=Release; BUILD_DIR=""; JOBS="$(nproc 2>/dev/null || echo 2)"; PREFIX=""; STATIC=0; HS_ROOT=""; CLEAN=0; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --no-hyperscan) HS=OFF ;;
    --asan) BUILD_TYPE=Debug; EXTRA+=("-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer" "-DCMAKE_C_FLAGS=-fsanitize=address,undefined -fno-omit-frame-pointer"); [ -z "$BUILD_DIR" ] && BUILD_DIR="$ROOT/build/linux-asan" ;;
    --static) STATIC=1 ;;
    --hyperscan-root) HS_ROOT="$2"; shift ;;
    --prefix-path) PREFIX="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    --build-dir) BUILD_DIR="$2"; shift ;;
    --clean) CLEAN=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ -z "$BUILD_DIR" ]; then
  if [ "$STATIC" -eq 1 ]; then BUILD_DIR="$ROOT/build/linux-static"
  elif [ "$HS" = OFF ]; then BUILD_DIR="$ROOT/build/linux-fallback"; else BUILD_DIR="$ROOT/build/linux"; fi
fi
command -v cmake >/dev/null || { echo "cmake not found: run scripts/linux/setup_deps.sh" >&2; exit 1; }
[ "$CLEAN" -eq 1 ] && rm -rf "$BUILD_DIR"
ARGS=(-S "$ROOT" -B "$BUILD_DIR" "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" "-DAPG_WITH_HYPERSCAN=$HS")
[ "$STATIC" -eq 1 ] && ARGS+=("-DAPG_STATIC_DEPS=ON")
[ -n "$HS_ROOT" ] && ARGS+=("-DHYPERSCAN_ROOT=$HS_ROOT")
[ -n "$PREFIX" ] && ARGS+=("-DCMAKE_PREFIX_PATH=$PREFIX")
ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")
echo "== configure: cmake ${ARGS[*]}"
cmake "${ARGS[@]}"
echo "== build ($JOBS jobs)"
cmake --build "$BUILD_DIR" --parallel "$JOBS"
echo
echo "Built into $BUILD_DIR"
ls -1 "$BUILD_DIR"/bin/libai_prompt_guard.* "$BUILD_DIR"/bin/ai-prompt-guard "$BUILD_DIR"/bin/apg_tests 2>/dev/null || true
if [ "$STATIC" -eq 1 ] && command -v ldd >/dev/null; then
  echo "== run-time dependencies of libai_prompt_guard.so (should be glibc only):"
  ldd "$BUILD_DIR/bin/libai_prompt_guard.so" | sed 's/^/   /'
fi
echo "Next: scripts/linux/test.sh"
