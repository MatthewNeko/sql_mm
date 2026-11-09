/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_cipher.h"

#include <cstring>

#include "chacha20.h"
#include "sha256.h"

namespace Relay
{
namespace
{
void WriteU64LE(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
    {
        p[i] = (uint8_t)(v >> (i * 8));
    }
}

void WriteU32LE(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void MakeNonce(uint64_t seq, uint8_t nonce[RelayCrypto::kChaCha20NonceBytes])
{
    WriteU64LE(nonce, seq);
    memset(nonce + 8, 0, 4);
}

void ComputeTag(const uint8_t *macKey, uint64_t seq, const char *ciphertext, size_t len, uint8_t out[32])
{
    uint8_t prefix[12];
    WriteU64LE(prefix, seq);
    WriteU32LE(prefix + 8, (uint32_t)len);

    RelayCrypto::HmacSha256 mac(macKey, 32);
    mac.Update(prefix, sizeof(prefix));
    mac.Update(ciphertext, len);
    mac.Final(out);
}
} // namespace

Cipher::~Cipher()
{
    Clear();
}

void Cipher::Init(const uint8_t material[kSessionKeyBytes])
{
    memcpy(m_encKey, material, 32);
    memcpy(m_macKey, material + 32, 32);
    m_seq = 0;
    m_ready = true;
}

void Cipher::Clear()
{
    RelayCrypto::SecureZero(m_encKey, sizeof(m_encKey));
    RelayCrypto::SecureZero(m_macKey, sizeof(m_macKey));
    m_seq = 0;
    m_ready = false;
}

bool Cipher::Seal(const char *plain, size_t len, std::vector<char> &out)
{
    if (!m_ready)
    {
        return false;
    }
    if (m_seq == UINT64_MAX)
    {
        // Never reuse a nonce; the caller must reconnect.
        return false;
    }

    out.resize(len + kFrameTagBytes);
    if (len > 0)
    {
        memcpy(out.data(), plain, len);
    }

    uint8_t nonce[RelayCrypto::kChaCha20NonceBytes];
    MakeNonce(m_seq, nonce);
    RelayCrypto::ChaCha20 stream(m_encKey, nonce);
    stream.XorKeyStream((uint8_t *)out.data(), len);

    ComputeTag(m_macKey, m_seq, out.data(), len, (uint8_t *)out.data() + len);
    m_seq++;
    return true;
}

bool Cipher::Open(const char *frame, size_t len, std::vector<char> &out)
{
    out.clear();
    if (!m_ready || len < kFrameTagBytes)
    {
        return false;
    }

    size_t plainLen = len - kFrameTagBytes;
    const char *ciphertext = frame;
    const char *tag = frame + plainLen;

    uint8_t want[32];
    ComputeTag(m_macKey, m_seq, ciphertext, plainLen, want);
    bool ok = RelayCrypto::ConstantTimeEqual(want, tag, sizeof(want));
    RelayCrypto::SecureZero(want, sizeof(want));
    if (!ok)
    {
        return false;
    }
    if (m_seq == UINT64_MAX)
    {
        return false;
    }

    out.resize(plainLen);
    if (plainLen > 0)
    {
        memcpy(out.data(), ciphertext, plainLen);
    }

    uint8_t nonce[RelayCrypto::kChaCha20NonceBytes];
    MakeNonce(m_seq, nonce);
    RelayCrypto::ChaCha20 stream(m_encKey, nonce);
    stream.XorKeyStream((uint8_t *)out.data(), plainLen);

    m_seq++;
    return true;
}

bool DeriveSessionKeys(const uint8_t *psk, size_t pskLen, const uint8_t clientNonce[kHandshakeNonceBytes],
                       const uint8_t serverNonce[kHandshakeNonceBytes], Cipher &clientToServer, Cipher &serverToClient)
{
    if (!psk || pskLen == 0)
    {
        return false;
    }

    uint8_t salt[kHandshakeNonceBytes * 2];
    memcpy(salt, clientNonce, kHandshakeNonceBytes);
    memcpy(salt + kHandshakeNonceBytes, serverNonce, kHandshakeNonceBytes);

    uint8_t c2s[kSessionKeyBytes];
    uint8_t s2c[kSessionKeyBytes];
    static const char kInfoC2S[] = "sqlmm-relay v2 client->server";
    static const char kInfoS2C[] = "sqlmm-relay v2 server->client";

    RelayCrypto::HkdfSha256(salt, sizeof(salt), psk, pskLen, kInfoC2S, sizeof(kInfoC2S) - 1, c2s, sizeof(c2s));
    RelayCrypto::HkdfSha256(salt, sizeof(salt), psk, pskLen, kInfoS2C, sizeof(kInfoS2C) - 1, s2c, sizeof(s2c));

    clientToServer.Init(c2s);
    serverToClient.Init(s2c);

    RelayCrypto::SecureZero(c2s, sizeof(c2s));
    RelayCrypto::SecureZero(s2c, sizeof(s2c));
    RelayCrypto::SecureZero(salt, sizeof(salt));
    return true;
}
} // namespace Relay
