#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/pc/dist"
mkdir -p "$OUT/classes"
javac --release 17 -d "$OUT/classes" $(find "$ROOT/core/src/main/java" "$ROOT/pc/src/main/java" -name '*.java')
PLATFORM="${TRACE_PLATFORM:-linux-x64}"
case "$PLATFORM" in
  windows-x64) NAME="TRACE-3.0.0-windows-x64"; EXT=".exe";;
  macos-arm64) NAME="TRACE-3.0.0-macos-arm64"; EXT="";;
  macos-x64) NAME="TRACE-3.0.0-macos-x64"; EXT="";;
  linux-x64) NAME="TRACE-3.0.0-linux-x64"; EXT="";;
  *) echo "Unsupported platform: $PLATFORM" >&2; exit 2;;
esac
jar --create --file "$OUT/$NAME.jar" --main-class com.trace.pc.TracePc -C "$OUT/classes" .
if command -v jpackage >/dev/null 2>&1; then
  APPDIR="$OUT/${NAME}-app"
  rm -rf "$APPDIR" "$OUT/$NAME.zip" "$OUT/$NAME.tar.gz"
  jpackage --type app-image --name "$NAME" --input "$OUT" --main-jar "$NAME.jar" --main-class com.trace.pc.TracePc --dest "$OUT" --app-version 3.0.0
  mv "$OUT/$NAME" "$APPDIR"
  if [[ "$PLATFORM" == windows-* || "$PLATFORM" == macos-* ]]; then jar --create --file "$OUT/$NAME.zip" -C "$OUT" "${NAME}-app"; fi
  if [[ "$PLATFORM" == linux-* ]]; then tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "${NAME}-app"; fi
else
  echo "jpackage unavailable; jar is a valid PC client but no native package was produced."
fi
for f in "$OUT"/$NAME*; do [[ -f "$f" ]] && sha256sum "$f" > "$f.sha256"; done
