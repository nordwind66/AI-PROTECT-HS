#!/usr/bin/env bash
# bench.sh -- the formal benchmark. It NEVER runs by itself (not from build.sh, test.sh, init_rules.sh or CI):
# you must say so explicitly with --run (or APG_RUN_BENCH=1).
#
#   scripts/linux/bench.sh --run [--build-dir build/linux] [--manifest FILE] [--iterations N] [--threads 1,2,4,8]
#                          [--sizes 256,1024,4096,16384,65536] [--out reports/bench_<host>_<date>.json]
#
# Measures (per text size and per mix no-hit / low-hit / high-hit): P50 / P95 / P99 latency, scans per second, MB/s,
# multi-thread scaling, load time and RSS. Compile time, database size and import / publish time are measured by
# `--compile-timing` (a separate, explicit step). Results are written next to the host description (lscpu, memory,
# compiler flags) so that a number is never separated from the machine that produced it.
# Run it on an otherwise idle machine; do not benchmark on a laptop on battery or inside a noisy shared runner.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
RUN=${APG_RUN_BENCH:-0}; BUILD="$ROOT/build/linux"; MANIFEST=""; ITER=2000; THREADS="1,2,4"; SIZES="256,1024,4096,16384,65536"; OUT=""; COMPILE_TIMING=0
while [ $# -gt 0 ]; do
  case "$1" in
    --run) RUN=1 ;;
    --build-dir) BUILD="$2"; shift ;;
    --manifest) MANIFEST="$2"; shift ;;
    --iterations) ITER="$2"; shift ;;
    --threads) THREADS="$2"; shift ;;
    --sizes) SIZES="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --compile-timing) COMPILE_TIMING=1 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
if [ "$RUN" != 1 ]; then
  echo "bench.sh is an explicit action: re-run with --run to start the benchmark (nothing was measured)." >&2
  exit 2
fi
CLI="$BUILD/bin/ai-prompt-guard"
[ -x "$CLI" ] || { echo "$CLI not found: run scripts/linux/build.sh first" >&2; exit 1; }
[ -n "$MANIFEST" ] || MANIFEST="$ROOT/dist/linux/x86_64/active.json"
[ -f "$MANIFEST" ] || { echo "$MANIFEST not found: run scripts/linux/init_rules.sh first" >&2; exit 1; }
HOST="$(hostname 2>/dev/null || echo host)"; STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
[ -n "$OUT" ] || OUT="$ROOT/reports/bench_${HOST}_${STAMP}.json"
mkdir -p "$(dirname "$OUT")"
{
  echo "host: $HOST"; echo "date_utc: $STAMP"; echo "kernel: $(uname -srvm)"
  command -v lscpu >/dev/null && lscpu | sed 's/^/cpu: /'
  grep -E 'MemTotal|SwapTotal' /proc/meminfo 2>/dev/null | sed 's/^/mem: /'
  echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
  grep -E 'CMAKE_(BUILD_TYPE|CXX_COMPILER:|CXX_FLAGS)' "$BUILD/CMakeCache.txt" 2>/dev/null | sed 's/^/build: /'
} > "${OUT%.json}.host.txt"
echo "host description written to ${OUT%.json}.host.txt"
"$CLI" bench --manifest "$MANIFEST" --dataset "$ROOT/tests/corpus" --sizes "$SIZES" --iterations "$ITER" --threads "$THREADS" --out "$OUT"
echo "benchmark written to $OUT"
if [ "$COMPILE_TIMING" -eq 1 ]; then
  PY="${APG_PYTHON:-python3}"
  TMP="$(mktemp -d)"; cp "$ROOT/data/ai_prompt_rules.db" "$TMP/rules.db"
  VERSION="$("$PY" -X utf8 - "$TMP/rules.db" <<'EOF'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1], uri=True)
print(c.execute("SELECT version FROM ruleset_versions WHERE status='published' ORDER BY version_id DESC LIMIT 1").fetchone()[0])
EOF
)"
  s=$(date +%s.%N); "$CLI" compile --db "$TMP/rules.db" --version "$VERSION" --out "$TMP/dist" --force >/dev/null; e=$(date +%s.%N)
  echo "compile_seconds: $(echo "$e - $s" | bc -l 2>/dev/null || echo "$e $s")" | tee -a "${OUT%.json}.host.txt"
  du -sb "$TMP/dist" "$TMP/rules.db" | sed 's/^/size_bytes: /' | tee -a "${OUT%.json}.host.txt"
  rm -rf "$TMP"
fi
