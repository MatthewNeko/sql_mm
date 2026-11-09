/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "chacha20.h"

#include <cstring>

namespace RelayCrypto
{
namespace
{
inline uint32_t Rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

inline uint32_t Load32LE(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

inline void Store32LE(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

inline void QuarterRound(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d)
{
    a += b;
    d ^= a;
    d = Rotl32(d, 16);
    c += d;
    b ^= c;
    b = Rotl32(b, 12);
    a += b;
    d ^= a;
    d = Rotl32(d, 8);
    c += d;
    b ^= c;
    b = Rotl32(b, 7);
}

// "expand 32-byte k" as four little-endian words.
constexpr uint32_t kSigma[4] = {0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u};
} // namespace

ChaCha20::ChaCha20(const uint8_t key[kChaCha20KeyBytes], const uint8_t nonce[kChaCha20NonceBytes], uint32_t blockCounter)
{
    m_state[0] = kSigma[0];
    m_state[1] = kSigma[1];
    m_state[2] = kSigma[2];
    m_state[3] = kSigma[3];
    for (int i = 0; i < 8; i++)
    {
        m_state[4 + i] = Load32LE(key + i * 4);
    }
    m_state[12] = blockCounter;
    for (int i = 0; i < 3; i++)
    {
        m_state[13 + i] = Load32LE(nonce + i * 4);
    }
    memset(m_block, 0, sizeof(m_block));
    m_pos = sizeof(m_block);
}

void ChaCha20::GenerateBlock()
{
    uint32_t x[16];
    memcpy(x, m_state, sizeof(x));

    for (int i = 0; i < 10; i++)
    {
        QuarterRound(x[0], x[4], x[8], x[12]);
        QuarterRound(x[1], x[5], x[9], x[13]);
        QuarterRound(x[2], x[6], x[10], x[14]);
        QuarterRound(x[3], x[7], x[11], x[15]);
        QuarterRound(x[0], x[5], x[10], x[15]);
        QuarterRound(x[1], x[6], x[11], x[12]);
        QuarterRound(x[2], x[7], x[8], x[13]);
        QuarterRound(x[3], x[4], x[9], x[14]);
    }

    for (int i = 0; i < 16; i++)
    {
        Store32LE(m_block + i * 4, x[i] + m_state[i]);
    }

    m_state[12]++;
    m_pos = 0;
}

void ChaCha20::XorKeyStream(uint8_t *data, size_t len)
{
    while (len > 0)
    {
        if (m_pos == sizeof(m_block))
        {
            GenerateBlock();
        }
        size_t available = sizeof(m_block) - m_pos;
        size_t take = len < available ? len : available;
        for (size_t i = 0; i < take; i++)
        {
            data[i] ^= m_block[m_pos + i];
        }
        data += take;
        len -= take;
        m_pos += take;
    }
}
} // namespace RelayCrypto
