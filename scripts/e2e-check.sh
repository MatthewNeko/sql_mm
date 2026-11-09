#!/usr/bin/env bash
#
# Smoke test: the shipped plugin client code against the shipped relay binary.
#
# Compiles tools/relay_e2e.cpp (which drives the real RelayLink/RelaySocket/
# crypto code) against a stub tier0, starts dist/relay/sqlmm-relay-linux-amd64
# with a throwaway PSK, and checks the encrypted handshake + PING/PONG.
#
#   ./scripts/e2e-check.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# RELAY lets CI (or a manual check) point at a binary that is not staged in
# dist/ yet, e.g. the artifact a build job just produced.
RELAY="${RELAY:-$ROOT/dist/relay/sqlmm-relay-linux-amd64}"
PORT="${PORT:-19330}"
PSK="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
WORK="$(mktemp -d)"
STUB="$WORK/stub"

trap 'rm -rf "$WORK"' EXIT
[ -x "$RELAY" ] || { echo "no relay binary at $RELAY (scripts/build-linux.sh, or set RELAY=...)" >&2; exit 1; }

mkdir -p "$STUB/tier0"
# tier0's logging is the only engine dependency this code path has.
cat > "$STUB/tier0/dbg.h" <<'EOF'
#pragma once
#include <cstdarg>
#include <cstdio>
inline void StubLog(const char *lvl, const char *fmt, va_list ap)
{
    std::printf("[%s] ", lvl);
    std::vprintf(fmt, ap);
    std::printf("\n");
}
inline void ConMsg(const char *fmt, ...) { va_list ap; va_start(ap, fmt); StubLog("con", fmt, ap); va_end(ap); }
inline void Msg(const char *fmt, ...) { va_list ap; va_start(ap, fmt); StubLog("msg", fmt, ap); va_end(ap); }
inline void Warning(const char *fmt, ...) { va_list ap; va_start(ap, fmt); StubLog("warn", fmt, ap); va_end(ap); }
inline void DevMsg(const char *fmt, ...) { (void)fmt; }
inline void Error(const char *fmt, ...) { va_list ap; va_start(ap, fmt); StubLog("error", fmt, ap); va_end(ap); }
EOF
# The real sql_mm.h pulls in Metamod; only the version string is needed here.
cat > "$STUB/sql_mm.h" <<'EOF'
#pragma once
#define SQLMM_VERSION "2.0.0"
#define META_CONPRINTF(...) ((void)0)
EOF

echo "== compiling harness =="
g++ -std=c++17 -O1 -g -Wall -Wextra -Wno-unused-parameter -fno-rtti -fno-exceptions \
    -I"$STUB" -I"$ROOT/src" -I"$ROOT/src/relay" -I"$ROOT/src/relay/crypto" \
    "$ROOT/tools/relay_e2e.cpp" \
    "$ROOT/src/relay/relay_link.cpp" \
    "$ROOT/src/relay/relay_socket.cpp" \
    "$ROOT/src/relay/relay_config.cpp" \
    "$ROOT/src/relay/crypto/sha256.cpp" \
    "$ROOT/src/relay/crypto/chacha20.cpp" \
    "$ROOT/src/relay/crypto/relay_cipher.cpp" \
    -o "$WORK/relay_e2e"

cat > "$WORK/relay.json" <<EOF
{
  "listen": "127.0.0.1:$PORT",
  "encryption": "psk",
  "psk": "$PSK",
  "log_level": "debug",
  "allow_client_dsn": false,
  "fallback": { "host": "127.0.0.1", "port": 1, "user": "x", "pass": "y", "database": "z" }
}
EOF

echo "== starting relay on $PORT =="
"$RELAY" -config "$WORK/relay.json" > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true; rm -rf "$WORK"' EXIT

for _ in $(seq 1 50); do
    grep -q "relay listening" "$WORK/relay.log" 2>/dev/null && break
    sleep 0.1
done
if ! kill -0 "$RELAY_PID" 2>/dev/null; then
    echo "relay died on startup:" >&2
    cat "$WORK/relay.log" >&2
    exit 1
fi

echo "== running harness =="
rc=0
"$WORK/relay_e2e" 127.0.0.1 "$PORT" "$PSK" || rc=$?

echo "== relay log =="
cat "$WORK/relay.log"
exit $rc
