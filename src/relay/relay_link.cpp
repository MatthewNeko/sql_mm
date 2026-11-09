/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_link.h"

#include <cstdio>
#include <cstring>

#include "relay_config.h"
#include "sql_mm.h"
#include "tier0/dbg.h"

namespace
{
// Parses the ERROR body into a human readable string. The reader is positioned
// just after the message type.
void ReadErrorMessage(Relay::Reader &reader, std::string &err)
{
    uint32_t reqId = 0;
    uint8_t opcode = 0;
    int32_t failIndex = 0;
    std::string message;
    reader.U32(reqId);
    reader.U8(opcode);
    reader.I32(failIndex);
    reader.Str(message);
    err = message.empty() ? "relay rejected the request" : message;
}
} // namespace

RelayLink::~RelayLink()
{
    Close();
}

void RelayLink::Close()
{
    m_socket.Close();
    m_tx.Clear();
    m_rx.Clear();
    m_encrypted = false;
    m_handshaked = false;
}

bool RelayLink::WriteRawFrame(const std::vector<char> &payload, std::string &err)
{
    m_frame.resize(4 + payload.size());
    uint32_t size = (uint32_t)payload.size();
    m_frame[0] = (char)(size & 0xFF);
    m_frame[1] = (char)((size >> 8) & 0xFF);
    m_frame[2] = (char)((size >> 16) & 0xFF);
    m_frame[3] = (char)((size >> 24) & 0xFF);
    if (!payload.empty())
    {
        memcpy(m_frame.data() + 4, payload.data(), payload.size());
    }

    if (!m_socket.SendAll(m_frame.data(), m_frame.size()))
    {
        err = "relay write failed (connection lost)";
        Close();
        return false;
    }
    return true;
}

bool RelayLink::ReadRawFrame(std::vector<char> &out, std::string &err)
{
    char header[4];
    if (!m_socket.RecvAll(header, sizeof(header)))
    {
        err = "relay read failed (connection lost or timed out)";
        Close();
        return false;
    }

    uint32_t size = Relay::ReadU32(header);
    uint32_t cap = m_maxPayloadBytes;
    if (m_encrypted)
    {
        cap += (uint32_t)Relay::kFrameTagBytes;
    }
    if (size == 0 || size > cap)
    {
        // Framing is unrecoverable; do not try to resync.
        err = "relay sent an invalid frame length";
        Close();
        return false;
    }

    out.resize(size);
    if (!m_socket.RecvAll(out.data(), out.size()))
    {
        err = "relay read failed (connection lost or timed out)";
        Close();
        return false;
    }
    return true;
}

bool RelayLink::SendFrame(const std::vector<char> &payload, std::string &err)
{
    if (payload.empty() || payload.size() > m_maxPayloadBytes)
    {
        err = "relay request payload out of range";
        Close();
        return false;
    }

    if (!m_encrypted)
    {
        return WriteRawFrame(payload, err);
    }

    std::vector<char> sealed;
    if (!m_tx.Seal(payload.data(), payload.size(), sealed))
    {
        err = "relay encryption failed";
        Close();
        return false;
    }
    return WriteRawFrame(sealed, err);
}

bool RelayLink::ReadFrame(std::vector<char> &out, std::string &err)
{
    if (!ReadRawFrame(out, err))
    {
        return false;
    }
    if (!m_encrypted)
    {
        return true;
    }

    std::vector<char> plain;
    if (!m_rx.Open(out.data(), out.size(), plain))
    {
        // Either the key is wrong, the frame was tampered with, or the peer
        // replayed one. None of those are recoverable on this connection.
        err = "relay frame failed authentication (wrong key or tampered stream)";
        Close();
        return false;
    }
    out.swap(plain);
    return true;
}

bool RelayLink::Request(const std::vector<char> &request, std::vector<char> &response, std::string &err)
{
    if (!m_socket.IsOpen())
    {
        err = "relay connection is closed";
        return false;
    }
    if (!SendFrame(request, err))
    {
        return false;
    }
    return ReadFrame(response, err);
}

// HELLO -> CHALLENGE -> HELLO_FINISH -> HELLO_OK. Only the first two messages
// are clear text, and they carry nothing but versions and nonces. HELLO_FINISH
// is the first encrypted frame: if the plugin and the relay disagree on the
// key, its MAC fails on the server and the connection is dropped.
bool RelayLink::Handshake(const RelayConfig &cfg, std::string &err)
{
    uint8_t clientNonce[Relay::kNonceBytes];
    if (!RelayRandomBytes(clientNonce, sizeof(clientNonce)))
    {
        err = "relay handshake: cannot read OS entropy";
        return false;
    }

    uint8_t offeredSuite = cfg.encryption == RelayEncryption::Psk ? Relay::kSuiteChaCha20Hmac : Relay::kSuiteNone;
    Relay::Writer hello(Relay::Message::Hello);
    hello.U16(Relay::kProtocolVersion).U8(offeredSuite).Raw(clientNonce, sizeof(clientNonce));
    if (!SendFrame(hello.Buffer(), err))
    {
        return false;
    }

    std::vector<char> response;
    if (!ReadFrame(response, err))
    {
        return false;
    }

    Relay::Reader reader(response.data(), response.size());
    uint8_t type = 0;
    if (!reader.U8(type))
    {
        err = "relay handshake: truncated response";
        return false;
    }
    if (type == (uint8_t)Relay::Message::Error)
    {
        ReadErrorMessage(reader, err);
        return false;
    }
    if (type != (uint8_t)Relay::Message::HelloChallenge)
    {
        err = "relay handshake: unexpected response";
        return false;
    }

    uint16_t version = 0;
    uint8_t serverSuite = 0;
    const char *serverNonce = nullptr;
    std::string relayVersion;
    if (!reader.U16(version) || !reader.U8(serverSuite) || !reader.Raw(Relay::kNonceBytes, serverNonce) ||
        !reader.Str(relayVersion))
    {
        err = "relay handshake: malformed HELLO_CHALLENGE";
        return false;
    }

    if (version != Relay::kProtocolVersion)
    {
        char buffer[128];
        snprintf(buffer, sizeof(buffer), "relay protocol mismatch (plugin %u, server %u)", (unsigned)Relay::kProtocolVersion,
                 (unsigned)version);
        err = buffer;
        return false;
    }

    if (cfg.encryption == RelayEncryption::Psk)
    {
        if (serverSuite != Relay::kSuiteChaCha20Hmac)
        {
            // Do not silently continue in clear text: that is exactly the
            // downgrade an active attacker would try.
            err = "relay refused encryption (server is running encryption=none)";
            return false;
        }

        std::vector<uint8_t> key;
        std::string keyErr;
        if (!cfg.KeyMaterial(key, keyErr))
        {
            err = keyErr;
            return false;
        }
        if (!Relay::DeriveSessionKeys(key.data(), key.size(), clientNonce, (const uint8_t *)serverNonce, m_tx, m_rx))
        {
            err = "relay handshake: key derivation failed";
            return false;
        }
        m_encrypted = true;
    }
    else if (serverSuite != Relay::kSuiteNone)
    {
        err = "relay requires an encrypted channel; set relay_psk";
        return false;
    }

    Relay::Writer finish(Relay::Message::HelloFinish);
    finish.Str(SQLMM_VERSION, strlen(SQLMM_VERSION));
    if (!SendFrame(finish.Buffer(), err))
    {
        return false;
    }

    if (!ReadFrame(response, err))
    {
        return false;
    }

    Relay::Reader okReader(response.data(), response.size());
    if (!okReader.U8(type))
    {
        err = "relay handshake: truncated response";
        return false;
    }
    if (type == (uint8_t)Relay::Message::Error)
    {
        ReadErrorMessage(okReader, err);
        return false;
    }
    if (type != (uint8_t)Relay::Message::HelloOk)
    {
        err = "relay handshake: unexpected response";
        return false;
    }

    uint16_t okVersion = 0;
    if (!okReader.U16(okVersion) || !okReader.Str(relayVersion))
    {
        err = "relay handshake: malformed HELLO_OK";
        return false;
    }
    if (okVersion != Relay::kProtocolVersion)
    {
        err = "relay handshake: version changed mid-handshake";
        return false;
    }

    return true;
}

bool RelayLink::EnsureSession(const MySQLConnectionInfo &info, std::string &err, bool force)
{
    if (m_handshaked && m_socket.IsOpen())
    {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    if (!force && now < m_retryAfter)
    {
        err = "relay reconnect backoff in effect";
        return false;
    }

    if (TryEstablish(info, err))
    {
        m_backoffMs = 1000;
        m_retryAfter = std::chrono::steady_clock::time_point();
        return true;
    }

    // A remote relay that is down should not cost one TCP connect per queued
    // query; back off up to 30s between attempts.
    m_backoffMs = m_backoffMs * 2 > 30000 ? 30000 : m_backoffMs * 2;
    m_retryAfter = now + std::chrono::milliseconds(m_backoffMs);
    return false;
}

bool RelayLink::TryEstablish(const MySQLConnectionInfo &info, std::string &err)
{
    Close();

    const RelayConfig &cfg = RelayConfig::Get();
    m_maxPayloadBytes = cfg.maxPayloadBytes;

    if (!m_socket.Connect(cfg.host.c_str(), cfg.port, cfg.connectTimeoutMs))
    {
        char buffer[192];
        snprintf(buffer, sizeof(buffer), "cannot reach relay at %s:%u", cfg.host.c_str(), (unsigned)cfg.port);
        err = buffer;
        return false;
    }

    int ioTimeout = cfg.ioTimeoutMs > 0 ? cfg.ioTimeoutMs : (info.timeout > 0 ? info.timeout * 1000 : 0);
    m_recvTimeoutMs = ioTimeout;
    m_sendTimeoutMs = ioTimeout;
    m_socket.SetTimeouts(m_recvTimeoutMs, m_sendTimeoutMs);

    if (!Handshake(cfg, err))
    {
        Close();
        return false;
    }

    Relay::Writer connect(Relay::Message::Connect);
    connect.Str(info.host ? info.host : "", info.host ? strlen(info.host) : 0)
        .U16((uint16_t)(info.port > 0 ? info.port : 3306))
        .Str(info.user ? info.user : "", info.user ? strlen(info.user) : 0)
        .Str(info.pass ? info.pass : "", info.pass ? strlen(info.pass) : 0)
        .Str(info.database ? info.database : "", info.database ? strlen(info.database) : 0)
        .U16((uint16_t)(info.timeout > 0 ? info.timeout : 0));

    if (!SendFrame(connect.Buffer(), err))
    {
        return false;
    }

    std::vector<char> response;
    if (!ReadFrame(response, err))
    {
        return false;
    }

    Relay::Reader reader(response.data(), response.size());
    uint8_t type = 0;
    if (!reader.U8(type))
    {
        err = "relay connect: truncated response";
        Close();
        return false;
    }

    if (type == (uint8_t)Relay::Message::Error)
    {
        ReadErrorMessage(reader, err);
        Close();
        return false;
    }

    if (type != (uint8_t)Relay::Message::ConnectOk)
    {
        err = "relay connect: unexpected response";
        Close();
        return false;
    }

    uint32_t sessionId = 0;
    uint32_t features = 0;
    std::string serverVersion;
    std::string database;
    if (!reader.U32(sessionId) || !reader.U32(features) || !reader.Str(serverVersion) || !reader.Str(database))
    {
        err = "relay connect: malformed CONNECT_OK";
        Close();
        return false;
    }

    m_features = features;
    m_handshaked = true;

    Msg("[SQLMM] relay session %u established (mysql %s, db %s, %s)\n", sessionId, serverVersion.c_str(), database.c_str(),
        m_encrypted ? "encrypted" : "PLAIN TEXT");
    return true;
}
