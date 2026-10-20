#!/usr/bin/env bash
# bench.sh -- benchmark a rule package with the engine: P50 / P95 / P99 latency, scans per second, MB/s, multi-thread
# scaling, load time and RSS, per text size and per mix (no-hit / low-hit / high-hit). Run it yourself on an idle machine
# (not on a laptop on battery, not on a noisy shared runner); nothing else starts it.
#
#   scripts/bench.sh --manifest RULES/active.json [--build DIR] [--iterations N] [--threads 1,2,4] [--sizes 256,1024,4096,16384] [--out FILE]
#
# The result JSON is written next to a host description (lscpu, memory, governor) so that a number is never separated from
# the machine that produced it. examples/c/bench_live.c is the live (one line per second) variant.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$ROOT/build"; MANIFEST=""; ITER=2000; THREADS="1,2,4"; SIZES="256,1024,4096,16384,65536"; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift ;;
    --build) BUILD="$2"; shift ;;
    --iterations) ITER="$2"; shift ;;
    --threads) THREADS="$2"; shift ;;
    --sizes) SIZES="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
CLI="$BUILD/bin/ai-prompt-guard"
[ -x "$CLI" ] || { echo "$CLI not found: run scripts/build.sh first" >&2; exit 1; }
[ -n "$MANIFEST" ] || { echo "--manifest FILE (manifest.json or active.json of a rule package) is required" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "$MANIFEST not found" >&2; exit 1; }
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[ -n "$OUT" ] || OUT="$ROOT/reports/bench_$(hostname 2>/dev/null || echo host)_$STAMP.json"
mkdir -p "$(dirname "$OUT")"
{
  echo "host: $(hostname 2>/dev/null || echo host)"; echo "date_utc: $STAMP"; echo "kernel: $(uname -srvm)"
  command -v lscpu >/dev/null && lscpu | sed 's/^/cpu: /'
  grep -E 'MemTotal|SwapTotal' /proc/meminfo 2>/dev/null | sed 's/^/mem: /'
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  grep -E 'CMAKE_(BUILD_TYPE|CXX_COMPILER:|CXX_FLAGS)' "$BUILD/CMakeCache.txt" 2>/dev/null | sed 's/^/build: /'
} > "${OUT%.json}.host.txt"
echo "host description: ${OUT%.json}.host.txt"
"$CLI" bench --manifest "$MANIFEST" --dataset "$ROOT/tests/corpus" --sizes "$SIZES" --iterations "$ITER" --threads "$THREADS" --out "$OUT"
echo "result: $OUT"
