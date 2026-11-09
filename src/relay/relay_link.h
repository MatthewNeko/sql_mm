/**
 * =============================================================================
 * SQLMM relay client
 *
 * Owns one relay connection: TCP socket, handshake, session creation and
 * request/response framing. Every method here runs on the owning
 * ISQLConnection's worker thread; nothing in this class is thread safe.
 * =============================================================================
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "public/mysql_mm.h"
#include "crypto/relay_cipher.h"
#include "relay_config.h"
#include "relay_protocol.h"
#include "relay_socket.h"

class RelayLink
{
public:
    ~RelayLink();

    RelayLink(const RelayLink &) = delete;
    RelayLink &operator=(const RelayLink &) = delete;
    RelayLink() = default;

    // Connects and performs HELLO + CONNECT. Idempotent while the link is up.
    // On failure err holds a message suitable for the legacy "Failed to
    // establish a MySQL connection: %s" log line.
    //
    // Consecutive failures back off exponentially (1s .. 30s) so a dead relay
    // is not hammered by every queued query. force bypasses the backoff and is
    // used by an explicit Connect().
    bool EnsureSession(const MySQLConnectionInfo &info, std::string &err, bool force = false);

    void Close();

    bool IsOpen() const
    {
        return m_socket.IsOpen();
    }

    bool IsHandshaked() const
    {
        return m_handshaked;
    }

    uint32_t Features() const
    {
        return m_features;
    }

    bool IsEncrypted() const
    {
        return m_encrypted;
    }

    // request must already contain the message-type byte. On success response
    // holds the full response frame (type byte included).
    bool Request(const std::vector<char> &request, std::vector<char> &response, std::string &err);

private:
    bool TryEstablish(const MySQLConnectionInfo &info, std::string &err);
    bool Handshake(const RelayConfig &cfg, std::string &err);
    bool ReadFrame(std::vector<char> &out, std::string &err);
    bool SendFrame(const std::vector<char> &payload, std::string &err);
    bool WriteRawFrame(const std::vector<char> &payload, std::string &err);
    bool ReadRawFrame(std::vector<char> &out, std::string &err);

    RelaySocket m_socket;
    Relay::Cipher m_tx;
    Relay::Cipher m_rx;
    bool m_encrypted = false;
    std::vector<char> m_frame;
    bool m_handshaked = false;
    uint32_t m_features = 0;
    int m_recvTimeoutMs = 0;
    int m_sendTimeoutMs = 0;
    uint32_t m_maxPayloadBytes = Relay::kDefaultMaxPayloadBytes;

    int m_backoffMs = 1000;
    std::chrono::steady_clock::time_point m_retryAfter {};
};
