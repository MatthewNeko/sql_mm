/**
 * =============================================================================
 * SQLMM relay client — end to end check
 *
 * Connects to a running sqlmm-relay, performs the encrypted handshake and
 * exchanges a PING/PONG, which exercises the sealed-frame path in both
 * directions without needing a MySQL server behind the relay.
 *
 *   ./relay_e2e 127.0.0.1 19330 <psk-hex>
 *
 * Exits non-zero on any mismatch, so it can be used as a smoke test after
 * touching either side of the protocol.
 * =============================================================================
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// Accesses the connection internals so the test can run the handshake without
// creating a MySQL session. Standard headers are included above on purpose:
// flipping `private` before <chrono>/<vector> is what breaks this trick.
#define private public
#include "relay_link.h"
#undef private

namespace
{
int g_failures = 0;

void Check(bool ok, const char *what)
{
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok)
    {
        g_failures++;
    }
}

RelayConfig MakeConfig(const char *host, uint16_t port, const char *psk)
{
    RelayConfig cfg;
    cfg.host = host;
    cfg.port = port;
    cfg.psk = psk;
    cfg.encryption = RelayEncryption::Psk;
    cfg.connectTimeoutMs = 3000;
    return cfg;
}

// Runs HELLO -> CHALLENGE -> FINISH -> OK and a PING. Returns true when the
// encrypted channel came up and the PONG decrypted correctly.
bool HandshakeAndPing(const RelayConfig &cfg, bool expectSuccess, std::string &err)
{
    RelayLink link;
    link.m_maxPayloadBytes = cfg.maxPayloadBytes;

    if (!link.m_socket.Connect(cfg.host.c_str(), cfg.port, cfg.connectTimeoutMs))
    {
        err = "tcp connect failed";
        return false;
    }
    link.m_socket.SetTimeouts(3000, 3000);

    if (!link.Handshake(cfg, err))
    {
        return false;
    }
    if (!expectSuccess)
    {
        return true;
    }
    if (!link.IsEncrypted())
    {
        err = "handshake completed without encryption";
        return false;
    }

    Relay::Writer ping(Relay::Message::Ping);
    std::vector<char> response;
    if (!link.Request(ping.Buffer(), response, err))
    {
        return false;
    }
    if (response.empty() || (uint8_t)response[0] != (uint8_t)Relay::Message::Pong)
    {
        err = "expected PONG";
        return false;
    }
    link.Close();
    return true;
}
} // namespace

int main(int argc, char **argv)
{
    if (argc < 4)
    {
        fprintf(stderr, "usage: %s <host> <port> <psk>\n", argv[0]);
        return 2;
    }
    const char *host = argv[1];
    uint16_t port = (uint16_t)atoi(argv[2]);
    const char *psk = argv[3];

    RelaySocket::GlobalInit();

    std::string err;
    bool ok = HandshakeAndPing(MakeConfig(host, port, psk), true, err);
    if (ok)
    {
        printf("ok   encrypted handshake + ping\n");
    }
    else
    {
        printf("FAIL encrypted handshake + ping: %s\n", err.c_str());
        g_failures++;
    }

    // A wrong key must not get past HELLO_FINISH.
    std::string wrongKey(32, 'x');
    err.clear();
    bool rejected = !HandshakeAndPing(MakeConfig(host, port, wrongKey.c_str()), false, err);
    Check(rejected, "wrong key is rejected");

    // Clear text must be refused when the server requires encryption.
    RelayConfig plaintext = MakeConfig(host, port, psk);
    plaintext.encryption = RelayEncryption::None;
    err.clear();
    bool refused = !HandshakeAndPing(plaintext, false, err);
    Check(refused, "plaintext is refused (downgrade protection)");

    RelaySocket::GlobalShutdown();

    if (g_failures != 0)
    {
        printf("%d FAILED\n", g_failures);
        return 1;
    }
    printf("all end-to-end checks pass\n");
    return 0;
}
