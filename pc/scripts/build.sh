#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$ROOT/pc/dist"
rm -rf "$OUT/classes" "$OUT/TRACE-3.0.0-linux-x64-package" "$OUT/TRACE-3.0.0-linux-x64.tar.gz"
mkdir -p "$OUT/classes"
javac --release 17 -d "$OUT/classes" $(find "$ROOT/core/src/main/java" "$ROOT/pc/src/main/java" -name '*.java')
javac --release 17 -cp "$OUT/classes" -d "$OUT/classes" $(find "$ROOT/pc/src/test" -name '*.java')
java -cp "$OUT/classes" com.trace.pc.TraceCoreTest
jar --create --file "$OUT/TRACE-3.0.0-linux-x64.jar" --main-class com.trace.pc.TracePc -C "$OUT/classes" .
cat > "$OUT/TRACE-3.0.0-linux-x64" <<EOF
#!/usr/bin/env bash
exec java -jar "\$(dirname "\$0")/TRACE-3.0.0-linux-x64.jar" "\$@"
EOF
chmod +x "$OUT/TRACE-3.0.0-linux-x64"
mkdir -p "$OUT/TRACE-3.0.0-linux-x64-package"
cp "$OUT/TRACE-3.0.0-linux-x64.jar" "$OUT/TRACE-3.0.0-linux-x64-package/"
cp "$OUT/TRACE-3.0.0-linux-x64" "$OUT/TRACE-3.0.0-linux-x64-package/"
tar -C "$OUT" -czf "$OUT/TRACE-3.0.0-linux-x64.tar.gz" "TRACE-3.0.0-linux-x64-package"
sha256sum "$OUT/TRACE-3.0.0-linux-x64.tar.gz" > "$OUT/TRACE-3.0.0-linux-x64.tar.gz.sha256"
java -jar "$OUT/TRACE-3.0.0-linux-x64.jar" help
