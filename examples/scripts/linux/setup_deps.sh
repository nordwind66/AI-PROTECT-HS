#!/usr/bin/env bash
# setup_deps.sh -- check the build / run dependencies on Linux and tell the user exactly what is missing.
#
#   scripts/linux/setup_deps.sh              CHECK mode (default): needs no privileges, changes nothing
#   scripts/linux/setup_deps.sh --install    prints and then RUNS the package-manager command (sudo if needed)
#
# Nothing is installed unless --install is given explicitly; the build and test scripts never call this script.
set -u

MODE=check
for a in "$@"; do
  case "$a" in
    --install) MODE=install ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

ok=0; missing=()
have() { command -v "$1" >/dev/null 2>&1; }
check_cmd() { # name command [min-note]
  if have "$2"; then printf '  [ ok ] %-22s %s\n' "$1" "$($2 --version 2>&1 | head -n1)"; else printf '  [MISS] %-22s not found\n' "$1"; missing+=("$1"); ok=1; fi
}
check_pc() { # name pkg-config-module
  if have pkg-config && pkg-config --exists "$2" 2>/dev/null; then
    printf '  [ ok ] %-22s %s\n' "$1" "$(pkg-config --modversion "$2")"
  else
    printf '  [MISS] %-22s (pkg-config module %s)\n' "$1" "$2"; missing+=("$1"); ok=1
  fi
}

echo "== tools"
if have g++; then check_cmd "C++17 compiler (g++)" g++
elif have clang++; then check_cmd "C++17 compiler (clang++)" clang++
else printf '  [MISS] %-22s neither g++ nor clang++ found\n' "C++17 compiler"; missing+=("C++17 compiler"); ok=1; fi
check_cmd "cmake (>= 3.16)" cmake
check_cmd "make or ninja" make
check_cmd "python3 (>= 3.8)" python3
check_cmd "pkg-config" pkg-config
echo "== libraries (development files)"
check_pc "Hyperscan (libhs)" libhs
check_pc "PCRE2 (8-bit)" libpcre2-8
check_pc "SQLite3" sqlite3

# ---- distribution detection ---------------------------------------------------------------------------------------
ID=unknown; ID_LIKE=""
if [ -r /etc/os-release ]; then . /etc/os-release; fi
case "${ID}:${ID_LIKE}" in
  debian:*|ubuntu:*|*:*debian*|*:*ubuntu*) PM="apt-get install -y build-essential cmake pkg-config python3 libhyperscan-dev libpcre2-dev libsqlite3-dev" ;;
  fedora:*|rhel:*|centos:*|rocky:*|almalinux:*|*:*rhel*|*:*fedora*) PM="dnf install -y gcc-c++ make cmake pkgconf-pkg-config python3 hyperscan-devel pcre2-devel sqlite-devel" ;;
  opensuse*:*|sles:*|*:*suse*) PM="zypper install -y gcc-c++ make cmake pkg-config python3 hyperscan-devel pcre2-devel sqlite3-devel" ;;
  arch:*|*:*arch*) PM="pacman -S --needed base-devel cmake pkgconf python hyperscan pcre2 sqlite" ;;
  alpine:*) PM="apk add build-base cmake pkgconf python3 hyperscan-dev pcre2-dev sqlite-dev" ;;
  *) PM="" ;;
esac

echo
if [ "$ok" -eq 0 ]; then
  echo "All dependencies are present. Next: scripts/linux/build.sh"
  exit 0
fi
echo "Missing: ${missing[*]}"
if [ -z "$PM" ]; then
  echo "Distribution '$ID' is not recognised. Install: a C++17 compiler, CMake >= 3.16, Python 3, pkg-config and the"
  echo "development packages of Hyperscan (libhs), PCRE2 (8-bit) and SQLite3. Hyperscan is available in most"
  echo "distributions; on x86-64 only (the engine does not support ARM). If your distribution has no Hyperscan package,"
  echo "build it from https://github.com/intel/hyperscan and pass -DHYPERSCAN_ROOT=<prefix> to CMake, or use the explicit"
  echo "fallback backend:  scripts/linux/build.sh --no-hyperscan   (slower, reported as 'pcre2_fallback')."
  exit 1
fi
SUDO=""
if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo "; fi
echo "Suggested command (needs administrator rights):"
echo "  ${SUDO}${PM}"
if [ "$MODE" = install ]; then
  echo
  echo "--install given: running it now."
  # shellcheck disable=SC2086
  exec ${SUDO}${PM%% *} ${PM#* }
fi
echo "(nothing was installed: re-run with --install to execute the command above)"
exit 1
