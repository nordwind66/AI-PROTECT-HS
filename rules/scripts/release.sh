#!/usr/bin/env bash
# release.sh -- "the rules changed": one command from edited data/manual_rules/*.json to a rule package.
#
#   scripts/release.sh --cli /path/to/ai-prompt-guard [--dry-run] [--version V] [--prune] [--backend …] [compile options]
#
# 1  tools/update_rules.py   sync the JSON files, run the rule tests, validate, publish the next patch version,
#                            refresh the corpus expectations and the database fingerprint
# 2  scripts/compile.sh      export the snapshot, compile with the engine's compiler, register, activate
# 3  scripts/package.sh      <pkg>/<version>/ + active.json as a .tar.gz
# --dry-run only shows what would change (nothing is written). Nothing changed -> nothing is published or compiled.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
CLI="${APG_CLI:-}"; UPD=(); CMP=(); DRY=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cli) CLI="$2"; shift ;;
    --dry-run) DRY=1; UPD+=("--dry-run") ;;
    --version|--notes) UPD+=("$1" "$2"); shift ;;
    --prune|--no-eval) UPD+=("$1") ;;
    --backend|--cpu-target|--jobs|--shards|--native-timeout|--pattern-timeout|--shard-timeout|--relax-repeat) CMP+=("$1" "$2"); shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
PY="${APG_PYTHON:-python3}"
if [ "$DRY" -eq 1 ]; then
  exec "$PY" -X utf8 "$ROOT/tools/update_rules.py" "${UPD[@]}"
fi
[ -n "$CLI" ] || { echo "the engine's ai-prompt-guard is needed: pass --cli PATH or set APG_CLI" >&2; exit 1; }
BEFORE="$("$PY" -X utf8 "$ROOT/tools/rules.py" versions 2>/dev/null | tail -n +3 | wc -l)"
"$PY" -X utf8 "$ROOT/tools/update_rules.py" ${UPD[@]+"${UPD[@]}"}
AFTER="$("$PY" -X utf8 "$ROOT/tools/rules.py" versions 2>/dev/null | tail -n +3 | wc -l)"
if [ "$BEFORE" = "$AFTER" ] && [ -z "${FORCE_COMPILE:-}" ]; then
  echo "no new version was published: nothing to compile (FORCE_COMPILE=1 compiles the newest version anyway)"
  exit 0
fi
bash "$HERE/compile.sh" --cli "$CLI" ${CMP[@]+"${CMP[@]}"}
bash "$HERE/package.sh"
