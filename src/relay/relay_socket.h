/**
 * =============================================================================
 * SQLMM relay client
 *
 * Minimal blocking TCP socket wrapper. The plugin keeps one socket per
 * ISQLConnection, and only ever touches it from that connection's worker
 * thread, so no locking is needed here.
 * =============================================================================
 */

#pragma once

#include <cstddef>
#include <cstdint>

// Fills buf with cryptographically secure random bytes. Returns false when the
// OS entropy source is unavailable, which the caller must treat as fatal for
// the handshake rather than falling back to something predictable.
bool RelayRandomBytes(void *buf, size_t len);

class RelaySocket
{
public:
    RelaySocket() = default;
    ~RelaySocket();

    RelaySocket(const RelaySocket &) = delete;
    RelaySocket &operator=(const RelaySocket &) = delete;

    // WSAStartup on Windows, no-op elsewhere. Safe to call more than once.
    static bool GlobalInit();
    static void GlobalShutdown();

    bool Connect(const char *host, uint16_t port, int timeoutMs);

    void Close();

    bool IsOpen() const
    {
        return m_sock >= 0;
    }

    // Both return false on timeout, disconnect or any short read/write. Once
    // either fails the framing is unrecoverable, so the caller must Close().
    bool SendAll(const void *data, size_t len);
    bool RecvAll(void *data, size_t len);

    // Milliseconds; 0 disables the timeout.
    void SetTimeouts(int recvMs, int sendMs);

private:
    // Deliberately an integer: keeping winsock types out of this header avoids
    // the windows.h/winsock2.h include-order mess in a Metamod plugin.
    intptr_t m_sock = -1;
};
