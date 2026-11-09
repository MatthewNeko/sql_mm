/**
 * =============================================================================
 * SQLMM relay client
 *
 * Wire protocol shared with the Go relay server (relay-server/protocol.go).
 * Everything is little-endian. A frame is a 4-byte payload length followed by
 * the payload; payload[0] is the message type. Once the handshake installs
 * session keys, the payload is ciphertext followed by a 32 byte HMAC tag.
 *
 * Keep the constants below in sync with protocol.go. The version is checked
 * during the handshake, so a mismatch fails loudly instead of desyncing.
 * =============================================================================
 */

#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace Relay
{
constexpr uint16_t kProtocolVersion = 2;

// Cap on a single frame the client is willing to buffer. The server enforces
// its own limit; this one protects the game process from a hostile/garbled
// length prefix.
constexpr uint32_t kDefaultMaxPayloadBytes = 64u * 1024u * 1024u;

// Handshake nonce length. 32 bytes because it is also the HKDF salt material.
constexpr size_t kNonceBytes = 32;

// Cipher suites. The server answers with the suite it accepted; a client that
// asked for Psk aborts if the answer is None, so a downgrade is not silent.
constexpr uint8_t kSuiteNone = 0;
constexpr uint8_t kSuiteChaCha20Hmac = 1;

enum class Message : uint8_t
{
    Hello = 0x01,
    HelloOk = 0x02,
    Connect = 0x03,
    ConnectOk = 0x04,
    HelloChallenge = 0x05,
    HelloFinish = 0x06,
    Query = 0x10,
    Transaction = 0x11,
    Ping = 0x12,
    Close = 0x13,
    Result = 0x81,
    Error = 0x82,
    Pong = 0x84,
};

enum FeatureFlags : uint32_t
{
    // The server session runs with sql_mode NO_BACKSLASH_ESCAPES, so
    // Escape() must double quotes instead of using backslash escapes.
    FeatureNoBackslashEscapes = 1u << 0,
};

inline uint32_t ReadU32(const char *p)
{
    const auto *u = reinterpret_cast<const uint8_t *>(p);
    return (uint32_t)u[0] | ((uint32_t)u[1] << 8) | ((uint32_t)u[2] << 16) | ((uint32_t)u[3] << 24);
}

class Writer
{
public:
    explicit Writer(Message type)
    {
        m_buf.push_back((char)type);
    }

    Writer &U8(uint8_t v)
    {
        m_buf.push_back((char)v);
        return *this;
    }

    Writer &U16(uint16_t v)
    {
        m_buf.push_back((char)(v & 0xFF));
        m_buf.push_back((char)((v >> 8) & 0xFF));
        return *this;
    }

    Writer &U32(uint32_t v)
    {
        for (int i = 0; i < 4; i++)
        {
            m_buf.push_back((char)((v >> (i * 8)) & 0xFF));
        }
        return *this;
    }

    Writer &U64(uint64_t v)
    {
        for (int i = 0; i < 8; i++)
        {
            m_buf.push_back((char)((v >> (i * 8)) & 0xFF));
        }
        return *this;
    }

    Writer &I32(int32_t v)
    {
        return U32((uint32_t)v);
    }

    Writer &Str(const char *s, size_t len)
    {
        U32((uint32_t)len);
        m_buf.insert(m_buf.end(), s, s + len);
        return *this;
    }

    Writer &Str(const std::string &s)
    {
        return Str(s.data(), s.size());
    }

    // Raw bytes with no length prefix; handshake nonces are fixed size.
    Writer &Raw(const void *data, size_t len)
    {
        const char *p = (const char *)data;
        m_buf.insert(m_buf.end(), p, p + len);
        return *this;
    }

    const std::vector<char> &Buffer() const
    {
        return m_buf;
    }

private:
    std::vector<char> m_buf;
};

class Reader
{
public:
    // payload points at the whole frame buffer, including the message-type
    // byte. Callers must read the type first; the reader does not skip it.
    Reader(const char *payload, size_t size) : m_data(payload), m_size(size) {}

    bool U8(uint8_t &out)
    {
        if (m_size < 1)
        {
            return false;
        }
        out = (uint8_t)m_data[0];
        m_data += 1;
        m_size -= 1;
        return true;
    }

    bool U16(uint16_t &out)
    {
        if (m_size < 2)
        {
            return false;
        }
        const auto *u = reinterpret_cast<const uint8_t *>(m_data);
        out = (uint16_t)(u[0] | (u[1] << 8));
        m_data += 2;
        m_size -= 2;
        return true;
    }

    bool U32(uint32_t &out)
    {
        if (m_size < 4)
        {
            return false;
        }
        out = ReadU32(m_data);
        m_data += 4;
        m_size -= 4;
        return true;
    }

    bool I32(int32_t &out)
    {
        uint32_t v = 0;
        if (!U32(v))
        {
            return false;
        }
        out = (int32_t)v;
        return true;
    }

    bool U64(uint64_t &out)
    {
        if (m_size < 8)
        {
            return false;
        }
        const auto *u = reinterpret_cast<const uint8_t *>(m_data);
        out = 0;
        for (int i = 0; i < 8; i++)
        {
            out |= ((uint64_t)u[i]) << (i * 8);
        }
        m_data += 8;
        m_size -= 8;
        return true;
    }

    // Str returns a view into the frame buffer. The caller must not keep it
    // past the frame's lifetime.
    bool Str(const char *&out, uint32_t &len)
    {
        uint32_t n = 0;
        if (!U32(n))
        {
            return false;
        }
        if (m_size < n)
        {
            return false;
        }
        out = m_data;
        len = n;
        m_data += n;
        m_size -= n;
        return true;
    }

    bool Str(std::string &out)
    {
        const char *p = nullptr;
        uint32_t n = 0;
        if (!Str(p, n))
        {
            return false;
        }
        out.assign(p, n);
        return true;
    }

    // Raw returns a view of n bytes with no length prefix. Used for result
    // cells, whose length is already known from the preceding field.
    bool Raw(size_t n, const char *&out)
    {
        if (m_size < n)
        {
            return false;
        }
        out = m_data;
        m_data += n;
        m_size -= n;
        return true;
    }

    size_t Remaining() const
    {
        return m_size;
    }

private:
    const char *m_data;
    size_t m_size;
};
} // namespace Relay
