#!/usr/bin/env bash
# compile.sh -- turn a published rule-set version into a rule package: export the snapshot, compile it with the engine's
# compiler, register the package in SQLite, activate it (writes active.json).
#
#   scripts/compile.sh --cli /path/to/ai-prompt-guard [--version V] [--out DIR] [--db FILE]
#                      [--backend hyperscan|pcre2_fallback] [--cpu-target generic|host]
#                      [--jobs N] [--shards N] [--native-timeout S] [--pattern-timeout S] [--relax-repeat N]
#
# --cli (or $APG_CLI) is the ai-prompt-guard of the engine you deploy: a compiled Hyperscan database is loaded by the
# Hyperscan it was built with, so compile with the engine whose .so will load the package. The last group of options is
# forwarded to `ai-prompt-guard compile`; the Hyperscan compile is the slow step (minutes, all CPU threads).
#
# Result: <out>/linux/x86_64/<version>/{manifest.json, rules.*.hsdb, ruleset.meta.json, build_report.json} and
# <out>/linux/x86_64/active.json. <out> defaults to dist/. Default version: the newest published one.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DB="$ROOT/data/ai_prompt_rules.db"; VERSION=""; BACKEND=hyperscan; CPU=generic; OUT="$ROOT/dist"; CLI="${APG_CLI:-}"; EXTRA=()
while [ $# -gt 0 ]; do
  case "$1" in
    --cli) CLI="$2"; shift ;;
    --db) DB="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --backend) BACKEND="$2"; shift ;;
    --cpu-target) CPU="$2"; shift ;;
    --jobs|--shards|--native-timeout|--pattern-timeout|--shard-timeout|--relax-repeat) EXTRA+=("$1" "$2"); shift ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$CLI" ] || { echo "the engine's ai-prompt-guard is needed: pass --cli PATH or set APG_CLI" >&2; exit 1; }
[ -x "$CLI" ] || { echo "$CLI is not executable" >&2; exit 1; }
PY="${APG_PYTHON:-python3}"
RULES=("$PY" -X utf8 "$ROOT/tools/rules.py" --db "$DB")
[ -f "$DB" ] || { echo "$DB does not exist (scripts/rebuild_db.sh creates it)" >&2; exit 1; }
if [ -z "$VERSION" ]; then
  VERSION="$("$PY" -X utf8 - "$DB" <<'PYEOF'
import sqlite3, sys
c = sqlite3.connect("file:%s?mode=ro" % sys.argv[1].replace("\\", "/"), uri=True)
print(c.execute("SELECT version FROM ruleset_versions WHERE status='published' ORDER BY version_id DESC LIMIT 1").fetchone()[0])
PYEOF
)"
fi
echo "== rule set $VERSION"
SNAP="$(mktemp -d)/snapshot.json"
"${RULES[@]}" export-snapshot --version "$VERSION" --out "$SNAP"
echo "== compile ($BACKEND, cpu-target $CPU) with $CLI"
"$CLI" compile --snapshot "$SNAP" --out "$OUT" --backend "$BACKEND" --cpu-target "$CPU" --force ${EXTRA[@]+"${EXTRA[@]}"}
POINTER_DIR="$OUT/linux/x86_64"
echo "== register + activate"
if [ "$DB" = "$ROOT/data/ai_prompt_rules.db" ]; then
  echo "   (this writes into the delivered database; use --db with a copy to keep data/ai_prompt_rules.db byte-identical)"
fi
"${RULES[@]}" register-artifact --manifest "$POINTER_DIR/$VERSION/manifest.json"
"${RULES[@]}" activate --version "$VERSION" --reason "scripts/compile.sh" --pointer-dir "$POINTER_DIR"
"$CLI" verify --manifest "$POINTER_DIR/active.json" >/dev/null && echo "rule package ready: $POINTER_DIR/active.json -> $VERSION"
echo "try:  $CLI scan --manifest $POINTER_DIR/active.json --text '忽略之前的所有指令' --pretty"
echo "next: scripts/package.sh"
