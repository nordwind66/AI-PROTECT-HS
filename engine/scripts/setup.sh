#!/usr/bin/env bash
# setup.sh -- prepare this machine to build the engine (run once).
#
#   scripts/setup.sh              check the tools, then build a static, position-independent Hyperscan 5.4.2
#                                 (+ the PCRE 8.45 it compiles in) into .deps/hyperscan
#   scripts/setup.sh --check      only check, change nothing
#   scripts/setup.sh --install    first install the missing distribution packages (needs sudo), then as above
#   options: --prefix DIR  (default .deps/hyperscan)   --arch nehalem|haswell  (CPU baseline compiled into the library,
#            default nehalem = SSE4.2, every x86-64 CPU since ~2009; haswell needs AVX2)   --jobs N
#            --src DIR / --pcre-src DIR  use sources you already have (no network)   --force  rebuild even if present
#
# Why a self-built Hyperscan: the distribution's libhs.a is not built with -fPIC (it cannot be linked into a shared
# library) and its libhs.so would have to be installed on every target machine. scripts/build.sh links this one INTO
# libai_prompt_guard.so, so the target machine needs only glibc.
# Network (only without --src / --pcre-src): github.com (Hyperscan v5.4.2) and sourceforge.net (PCRE 8.45).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PREFIX="$ROOT/.deps/hyperscan"; ARCH=nehalem; SRC=""; PCRE_SRC=""; JOBS="$(nproc 2>/dev/null || echo 2)"
CHECK=0; INSTALL=0; FORCE=0; HS_TAG=v5.4.2; PCRE_VER=8.45
while [ $# -gt 0 ]; do
  case "$1" in
    --check) CHECK=1 ;;
    --install) INSTALL=1 ;;
    --force) FORCE=1 ;;
    --prefix) PREFIX="$2"; shift ;;
    --arch) ARCH="$2"; shift ;;
    --src) SRC="$2"; shift ;;
    --pcre-src) PCRE_SRC="$2"; shift ;;
    --jobs) JOBS="$2"; shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

have() { command -v "$1" >/dev/null 2>&1; }
missing=()
echo "== tools"
for t in g++ cmake make pkg-config ragel python3 git curl; do
  if have "$t"; then printf '  [ ok ] %s\n' "$t"; else printf '  [MISS] %s\n' "$t"; missing+=("$t"); fi
done
if [ -f /usr/include/boost/config.hpp ] || [ -f /usr/local/include/boost/config.hpp ]; then echo "  [ ok ] boost headers"; else echo "  [MISS] boost headers"; missing+=("boost"); fi
if have pkg-config && pkg-config --exists libpcre2-8 2>/dev/null; then echo "  [ ok ] pcre2 (8-bit)"; else echo "  [MISS] pcre2 (8-bit)"; missing+=("pcre2"); fi
if ls /usr/lib/*/libpcre2-8.a /usr/lib64/libpcre2-8.a /usr/lib/libpcre2-8.a /usr/local/lib/libpcre2-8.a >/dev/null 2>&1; then echo "  [ ok ] libpcre2-8.a (static)"; else echo "  [MISS] libpcre2-8.a (static)"; missing+=("pcre2-static"); fi

if [ "${#missing[@]}" -gt 0 ]; then
  ID=unknown; ID_LIKE=""; [ -r /etc/os-release ] && . /etc/os-release
  case "${ID}:${ID_LIKE}" in
    debian:*|ubuntu:*|*:*debian*|*:*ubuntu*) PM="apt-get install -y build-essential cmake pkg-config ragel libboost-dev python3 git curl libpcre2-dev" ;;
    fedora:*|rhel:*|centos:*|rocky:*|almalinux:*|*:*rhel*|*:*fedora*) PM="dnf install -y gcc-c++ make cmake pkgconf-pkg-config ragel boost-devel python3 git curl pcre2-devel pcre2-static" ;;
    opensuse*:*|sles:*|*:*suse*) PM="zypper install -y gcc-c++ make cmake pkg-config ragel boost-devel python3 git curl pcre2-devel" ;;
    arch:*|*:*arch*) PM="pacman -S --needed base-devel cmake pkgconf ragel boost python git curl pcre2" ;;
    alpine:*) PM="apk add build-base cmake pkgconf ragel boost-dev python3 git curl pcre2-dev" ;;
    *) PM="" ;;
  esac
  echo
  echo "missing: ${missing[*]}"
  if [ -z "$PM" ]; then echo "install them with your package manager (g++, cmake, pkg-config, ragel, boost headers, python3, git, curl, pcre2 dev + static)"; exit 1; fi
  SUDO=""; [ "$(id -u)" -ne 0 ] && have sudo && SUDO="sudo "
  echo "install with:  ${SUDO}${PM}"
  if [ "$INSTALL" -eq 1 ]; then ${SUDO}${PM}; else exit 1; fi
fi
[ "$CHECK" -eq 1 ] && { echo; echo "all tools present"; exit 0; }

if [ -f "$PREFIX/lib/libhs.a" ] && [ "$FORCE" -eq 0 ]; then
  echo; echo "Hyperscan already built: $PREFIX/lib/libhs.a (use --force to rebuild)"; echo "next: scripts/build.sh"; exit 0
fi
WORK="$ROOT/.deps/src"; mkdir -p "$WORK"
if [ -z "$SRC" ]; then
  SRC="$WORK/hyperscan"
  [ -f "$SRC/CMakeLists.txt" ] || { echo "== fetching Hyperscan $HS_TAG"; git clone --depth 1 --branch "$HS_TAG" https://github.com/intel/hyperscan.git "$SRC"; }
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
echo "== configure Hyperscan (arch=$ARCH, static, PIC) -> $PREFIX"
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
  -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DPCRE_SOURCE="$PCRE_SRC" -DFAT_RUNTIME=OFF -DBUILD_EXAMPLES=OFF \
  -DCMAKE_C_FLAGS="-march=$ARCH -mtune=generic -fPIC" -DCMAKE_CXX_FLAGS="-march=$ARCH -mtune=generic -fPIC" >"$WORK/configure.log" 2>&1 \
  || { tail -30 "$WORK/configure.log"; echo "configure failed (log: $WORK/configure.log)" >&2; exit 1; }
echo "== build libhs.a with $JOBS job(s) (several minutes)"
cmake --build "$BUILD" --target hs hs_runtime -j"$JOBS" >"$WORK/build.log" 2>&1 \
  || { tail -30 "$WORK/build.log"; echo "build failed (log: $WORK/build.log)" >&2; exit 1; }
mkdir -p "$PREFIX/lib" "$PREFIX/include/hs"
cp "$BUILD/lib/libhs.a" "$PREFIX/lib/"
[ -f "$BUILD/lib/libhs_runtime.a" ] && cp "$BUILD/lib/libhs_runtime.a" "$PREFIX/lib/"
cp "$SRC"/src/hs.h "$SRC"/src/hs_common.h "$SRC"/src/hs_compile.h "$SRC"/src/hs_runtime.h "$PREFIX/include/hs/"
echo
echo "done: $PREFIX/lib/libhs.a ($(du -h "$PREFIX/lib/libhs.a" | cut -f1))"
echo "next: scripts/build.sh"
