#!/usr/bin/env bash
# package.sh -- put the compiled rule package of the active version into one relocatable directory (+ .tar.gz).
# The engine is a separate package (engine/scripts/package.sh); copy the two to the target machine independently.
#
#   <pkg>/<version>/…     manifest.json, rules.*.hsdb, ruleset.meta.json, build_report.json
#   <pkg>/active.json     pointer to the version: give the engine  {"manifest_path": "<pkg>/active.json"}
#   <pkg>/SHA256SUMS
#
#   scripts/package.sh [--dist DIR] [--out DIR] [--name NAME]     DIR defaults to dist/linux/x86_64, out to dist/package
#
# Run scripts/compile.sh first (it writes dist/linux/x86_64/active.json).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DIST="$ROOT/dist/linux/x86_64"; OUT="$ROOT/dist/package"; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dist) DIST="$2"; shift ;;
    --out) OUT="$2"; shift ;;
    --name) NAME="$2"; shift ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -f "$DIST/active.json" ] || { echo "$DIST/active.json not found: run scripts/compile.sh first" >&2; exit 1; }
VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["manifest"].split("/")[0])' "$DIST/active.json")"
[ -d "$DIST/$VERSION" ] || { echo "$DIST/$VERSION (the version active.json points at) does not exist" >&2; exit 1; }
[ -n "$NAME" ] || NAME="ai-prompt-guard-rules-$VERSION-linux-x86_64"
PKG="$OUT/$NAME"
rm -rf "$PKG"; mkdir -p "$PKG"
cp -r "$DIST/$VERSION" "$PKG/$VERSION"
cp "$DIST/active.json" "$PKG/active.json"
( cd "$PKG" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
( cd "$OUT" && tar -czf "$NAME.tar.gz" "$NAME" )
echo "package: $PKG"
echo "archive: $OUT/$NAME.tar.gz ($(du -h "$OUT/$NAME.tar.gz" | cut -f1))"
echo "on the target machine:  tar xzf $NAME.tar.gz   then point the engine at  $NAME/active.json"
