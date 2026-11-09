#!/usr/bin/env bash
#
# Build both halves of SQLMM and stage a ready-to-copy package in dist/.
#
#   plugin : Linux x86_64 Metamod plugin  -> dist/addons/
#   relay  : Go daemon (linux/amd64, windows/amd64) -> dist/relay/
#
# Run it from WSL (the host toolchain is Linux clang + ambuild):
#
#   ./scripts/build-linux.sh
#
# Overrides:
#   HL2SDK_ROOT   directory that contains hl2sdk-cs2     (default: sibling CS2 project)
#   MMS_PATH      Metamod:Source source tree             (default: $HL2SDK_ROOT/metamod-source)
#   PLUGIN_ONLY=1 skip the Go relay build
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK_ROOT="${HL2SDK_ROOT:-/mnt/h/code/CS2PROJECT/cs2kz-metamod/cs2kz-metamod}"
MMS_ROOT="${MMS_PATH:-$SDK_ROOT/metamod-source}"
BUILD_DIR="$ROOT/build-linux"
DIST="$ROOT/dist"

if [ ! -d "$SDK_ROOT/hl2sdk-cs2" ]; then
    echo "hl2sdk-cs2 not found under $SDK_ROOT (set HL2SDK_ROOT)" >&2
    exit 1
fi
if [ ! -d "$MMS_ROOT/core" ]; then
    echo "Metamod:Source not found under $MMS_ROOT (set MMS_PATH)" >&2
    exit 1
fi
if [ ! -f "$MMS_ROOT/core/ISmmPlugin.h" ]; then
    echo "Metamod:Source headers not found under $MMS_ROOT/core" >&2
    exit 1
fi
# Metamod plugins need KHook's headers; it lives in a submodule that is empty
# after a plain clone, so fail loudly instead of at the first #include.
if [ ! -d "$MMS_ROOT/third_party/khook/include" ]; then
    echo "warning: $MMS_ROOT/third_party/khook is empty; run 'git submodule update --init' there" >&2
fi

echo "== plugin =="
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
python3 ../configure.py --enable-optimize --sdks cs2 \
    --mms_path "$MMS_ROOT" --hl2sdk-root "$SDK_ROOT"
ambuild

SO="$BUILD_DIR/package/addons/sql_mm/bin/linuxsteamrt64/sql_mm.so"
if [ ! -f "$SO" ]; then
    echo "build finished without producing $SO" >&2
    exit 1
fi

echo "== staging plugin =="
mkdir -p "$DIST/addons/sql_mm/bin/linuxsteamrt64" "$DIST/addons/metamod"
cp "$SO" "$DIST/addons/sql_mm/bin/linuxsteamrt64/sql_mm.so"
# Debug info is ~10 MB of the binary and is useless on a game server.
strip -g "$DIST/addons/sql_mm/bin/linuxsteamrt64/sql_mm.so"
cp "$BUILD_DIR/package/addons/metamod/sql_mm.vdf" "$DIST/addons/metamod/"
cp "$ROOT/cfg/sql_mm.cfg" "$DIST/addons/sql_mm/"

if [ "${PLUGIN_ONLY:-0}" != "1" ]; then
    echo "== relay =="
    mkdir -p "$DIST/relay"
    (
        cd "$ROOT/relay-server"
        # Static, stripped, reproducible: copy to any Linux box and run.
        CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 \
            go build -trimpath -ldflags '-s -w' -o "$DIST/relay/sqlmm-relay-linux-amd64" .
        CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
            go build -trimpath -ldflags '-s -w' -o "$DIST/relay/sqlmm-relay-windows-amd64.exe" .
    )
    cp "$ROOT/relay-server/config.example.json" "$DIST/relay/"
    cp "$ROOT/relay-server/README.md" "$DIST/relay/"
fi

echo "== done =="
cd "$DIST"
find . -type f -printf '%-60p %10s bytes\n' | sort
