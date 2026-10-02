#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/pc/dist"
mkdir -p "$OUT/classes"
javac --release 17 -d "$OUT/classes" $(find "$ROOT/core/src/main/java" "$ROOT/pc/src/main/java" -name '*.java')
PLATFORM="${TRACE_PLATFORM:-linux-x64}"
case "$PLATFORM" in
  windows-x64) NAME="TRACE-3.1.0-windows-x64"; EXT=".exe";;
  macos-arm64) NAME="TRACE-3.1.0-macos-arm64"; EXT="";;
  macos-x64) NAME="TRACE-3.1.0-macos-x64"; EXT="";;
  linux-x64) NAME="TRACE-3.1.0-linux-x64"; EXT="";;
  *) echo "Unsupported platform: $PLATFORM" >&2; exit 2;;
esac
jar --create --file "$OUT/$NAME.jar" --main-class com.trace.pc.TracePc -C "$OUT/classes" .
if [[ "$PLATFORM" == linux-* ]] && command -v jpackage >/dev/null 2>&1; then
  APPDIR="$OUT/${NAME}-app"
  rm -rf "$APPDIR" "$OUT/$NAME.zip" "$OUT/$NAME.tar.gz"
  INPUT="$(mktemp -d)"
  cp "$OUT/$NAME.jar" "$INPUT/"
  jpackage --type app-image --name "$NAME" --input "$INPUT" --main-jar "$NAME.jar" --main-class com.trace.pc.TracePc --dest "$OUT" --app-version 3.1.0
  rm -rf "$INPUT"
  mv "$OUT/$NAME" "$APPDIR"
  tar -C "$OUT" -czf "$OUT/$NAME.tar.gz" "${NAME}-app"
else
  # Windows and macOS use a real portable Java distribution. No fake native binary is emitted.
  PKGDIR="$OUT/${NAME}-package"
  rm -rf "$PKGDIR" "$OUT/$NAME.zip"
  mkdir -p "$PKGDIR"
  cp "$OUT/$NAME.jar" "$PKGDIR/"
  if [[ "$PLATFORM" == windows-* ]]; then
    printf '@echo off\r\njava -jar "%%~dp0%s.jar" %%*\r\n' "$NAME" > "$PKGDIR/TRACE.bat"
  else
    printf '#!/usr/bin/env bash\nexec java -jar "$(dirname "$0")/%s.jar" "$@"\n' "$NAME" > "$PKGDIR/TRACE"
    chmod +x "$PKGDIR/TRACE"
  fi
  jar --create --file "$OUT/$NAME.zip" -C "$OUT" "${NAME}-package"
fi
for f in "$OUT"/$NAME.zip "$OUT"/$NAME.tar.gz; do
  if [[ -f "$f" ]]; then
    if command -v sha256sum >/dev/null 2>&1; then (cd "$(dirname "$f")" && sha256sum "$(basename "$f")") > "$f.sha256"; else (cd "$(dirname "$f")" && shasum -a 256 "$(basename "$f")") > "$f.sha256"; fi
  fi
done
