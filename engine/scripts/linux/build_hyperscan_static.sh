#!/usr/bin/env bash
# build_hyperscan_static.sh -- build a position-independent STATIC Hyperscan (libhs.a) that can be linked into
# libai_prompt_guard.so, so the target machine needs no Hyperscan at all.
#
# Why: the distro's libhs.a is not built with -fPIC (the link of a shared library fails with "recompile with -fPIC"),
# and the distro's libhs.so would have to be installed on every target machine.
#
#   scripts/linux/build_hyperscan_static.sh                         -> build/hyperscan-static  (nehalem baseline)
#   scripts/linux/build_hyperscan_static.sh --prefix /opt/hs-static
#   scripts/linux/build_hyperscan_static.sh --arch haswell          faster (AVX2) but the library then refuses CPUs without AVX2
#   scripts/linux/build_hyperscan_static.sh --src DIR --pcre-src DIR  use sources you already have (no network)
#
# Needs: git (unless --src), curl (unless --pcre-src), cmake, g++, make, ragel, python3, Boost headers
#        (Ubuntu/Debian: apt install build-essential cmake ragel libboost-dev python3 git curl).
# Network (only when no --src / --pcre-src is given): github.com (Hyperscan v5.4.2) and sourceforge.net (PCRE 8.45,
# which the Hyperscan build compiles in).
#
# --arch is the CPU baseline compiled INTO the library (-march=<arch>); a plain static Hyperscan has no run-time CPU
# dispatch ("fat runtime" is shared-library only). nehalem = SSE4.2/POPCNT, every x86-64 CPU since ~2009. Rule
# databases compiled with `--cpu-target generic` (the default of init_rules.sh) then run on any CPU the library accepts.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="$ROOT/build/hyperscan-static"; ARCH=nehalem; SRC=""; PCRE_SRC=""; JOBS="$(nproc 2>/dev/null || echo 2)"
HS_TAG=v5.4.2; PCRE_VER=8.45
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift ;;
    --arch) ARCH="$2"; shift ;;
    --src) SRC="$2"; shift ;;
    --pcre-src) PCRE_SRC="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
for t in cmake g++ make ragel python3; do
  command -v "$t" >/dev/null || { echo "missing tool: $t (see the header of this script)" >&2; exit 1; }
done
[ -f /usr/include/boost/config.hpp ] || [ -f /usr/local/include/boost/config.hpp ] || { echo "Boost headers not found (apt install libboost-dev)" >&2; exit 1; }

WORK="$ROOT/build/hyperscan-src"
mkdir -p "$WORK"
if [ -z "$SRC" ]; then
  SRC="$WORK/hyperscan"
  if [ ! -f "$SRC/CMakeLists.txt" ]; then
    echo "== fetching Hyperscan $HS_TAG"
    git clone --depth 1 --branch "$HS_TAG" https://github.com/intel/hyperscan.git "$SRC"
  fi
fi
if [ -z "$PCRE_SRC" ]; then
  PCRE_SRC="$WORK/pcre-$PCRE_VER"
  if [ ! -f "$PCRE_SRC/pcre.h.in" ]; then
    echo "== fetching PCRE $PCRE_VER (compiled into Hyperscan)"
    curl -fsSL -o "$WORK/pcre.tar.bz2" "https://sourceforge.net/projects/pcre/files/pcre/$PCRE_VER/pcre-$PCRE_VER.tar.bz2/download"
    tar -xjf "$WORK/pcre.tar.bz2" -C "$WORK"
  fi
fi

BUILD="$WORK/build-$ARCH"
echo "== configuring (arch=$ARCH, static, PIC) -> $PREFIX"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DPCRE_SOURCE="$PCRE_SRC" -DFAT_RUNTIME=OFF -DBUILD_EXAMPLES=OFF \
  -DCMAKE_C_FLAGS="-march=$ARCH -mtune=generic -fPIC" -DCMAKE_CXX_FLAGS="-march=$ARCH -mtune=generic -fPIC" >"$WORK/configure.log" 2>&1 \
  || { tail -30 "$WORK/configure.log"; echo "configure failed (full log: $WORK/configure.log)" >&2; exit 1; }
echo "== building libhs.a with $JOBS job(s) (several minutes)"
cmake --build "$BUILD" --target hs hs_runtime -j"$JOBS" >"$WORK/build.log" 2>&1 \
  || { tail -30 "$WORK/build.log"; echo "build failed (full log: $WORK/build.log)" >&2; exit 1; }
mkdir -p "$PREFIX/lib" "$PREFIX/include/hs"
cp "$BUILD/lib/libhs.a" "$PREFIX/lib/"
[ -f "$BUILD/lib/libhs_runtime.a" ] && cp "$BUILD/lib/libhs_runtime.a" "$PREFIX/lib/"
cp "$SRC"/src/hs.h "$SRC"/src/hs_common.h "$SRC"/src/hs_compile.h "$SRC"/src/hs_runtime.h "$PREFIX/include/hs/"
# a relocation that is not position independent would break the shared-library link: check it here
if readelf -r "$PREFIX/lib/libhs.a" 2>/dev/null | grep -qE 'R_X86_64_(32|32S|PC32) .*__libc_single_threaded'; then
  echo "warning: libhs.a still has non-PIC relocations" >&2
fi
echo
echo "done: $PREFIX/lib/libhs.a ($(du -h "$PREFIX/lib/libhs.a" | cut -f1)), headers in $PREFIX/include/hs"
echo "use it:  bash scripts/linux/build.sh --static --hyperscan-root $PREFIX"
