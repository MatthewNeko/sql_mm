/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "sha256.h"

#include <cstring>

namespace RelayCrypto
{
namespace
{
constexpr uint32_t kIv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

constexpr uint32_t kRoundConstants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

inline uint32_t Rotr(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

void Transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) | ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t t1 = h + s1 + ch + kRoundConstants[i] + w[i];
        uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void StoreState(const uint32_t state[8], uint8_t out[32])
{
    for (int i = 0; i < 8; i++)
    {
        out[i * 4] = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)state[i];
    }
}

// Appends the 0x80 marker and the 64-bit bit length, then runs the final one or
// two blocks. totalLen is the message length in bytes.
void Finish(uint32_t state[8], uint8_t block[64], size_t blockLen, uint64_t totalLen, uint8_t out[32])
{
    uint64_t bits = totalLen * 8u;
    block[blockLen++] = 0x80;

    if (blockLen > 56)
    {
        memset(block + blockLen, 0, 64 - blockLen);
        Transform(state, block);
        blockLen = 0;
    }

    memset(block + blockLen, 0, 56 - blockLen);
    for (int i = 0; i < 8; i++)
    {
        block[56 + i] = (uint8_t)(bits >> (56 - i * 8));
    }
    Transform(state, block);
    StoreState(state, out);
}
} // namespace

void Sha256(const void *data, size_t len, uint8_t out[kSha256Bytes])
{
    uint32_t state[8];
    memcpy(state, kIv, sizeof(state));

    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;
    while (remaining >= 64)
    {
        Transform(state, p);
        p += 64;
        remaining -= 64;
    }

    uint8_t block[64] = {};
    if (remaining > 0)
    {
        memcpy(block, p, remaining);
    }
    Finish(state, block, remaining, len, out);

    SecureZero(state, sizeof(state));
    SecureZero(block, sizeof(block));
}

HmacSha256::HmacSha256(const void *key, size_t keyLen)
{
    Init(key, keyLen);
}

void HmacSha256::Init(const void *key, size_t keyLen)
{
    uint8_t normalized[64] = {};
    if (keyLen > 64)
    {
        Sha256(key, keyLen, normalized);
    }
    else if (keyLen > 0)
    {
        memcpy(normalized, key, keyLen);
    }

    uint8_t ipad[64];
    for (int i = 0; i < 64; i++)
    {
        ipad[i] = (uint8_t)(normalized[i] ^ 0x36);
        m_keyPad[i] = (uint8_t)(normalized[i] ^ 0x5c);
    }

    memcpy(m_state, kIv, sizeof(m_state));
    m_blockLen = 0;
    // The inner digest covers ipad || message, so the ipad block counts toward
    // the length that ends up in the padding. Getting this wrong produces a
    // perfectly plausible but wrong MAC.
    m_totalLen = 64;
    memset(m_block, 0, sizeof(m_block));

    Transform(m_state, ipad);

    SecureZero(normalized, sizeof(normalized));
    SecureZero(ipad, sizeof(ipad));
}

void HmacSha256::Update(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    m_totalLen += len;

    while (len > 0)
    {
        size_t space = 64 - m_blockLen;
        size_t take = len < space ? len : space;
        memcpy(m_block + m_blockLen, p, take);
        m_blockLen += take;
        p += take;
        len -= take;

        if (m_blockLen == 64)
        {
            Transform(m_state, m_block);
            m_blockLen = 0;
        }
    }
}

void HmacSha256::Final(uint8_t out[kSha256Bytes])
{
    uint8_t inner[32];
    Finish(m_state, m_block, m_blockLen, m_totalLen, inner);

    // Outer hash: opad block, then the 32 byte inner digest, padded as a
    // 96 byte message (64 byte opad + 32 byte digest).
    uint32_t outer[8];
    memcpy(outer, kIv, sizeof(outer));
    Transform(outer, m_keyPad);

    uint8_t tail[64] = {};
    memcpy(tail, inner, 32);
    uint8_t outerDigest[32];
    Finish(outer, tail, 32, 64 + 32, outerDigest);
    memcpy(out, outerDigest, sizeof(outerDigest));

    SecureZero(inner, sizeof(inner));
    SecureZero(outer, sizeof(outer));
    SecureZero(outerDigest, sizeof(outerDigest));
    SecureZero(tail, sizeof(tail));
    SecureZero(m_block, sizeof(m_block));
}

void HkdfSha256(const void *salt, size_t saltLen, const void *ikm, size_t ikmLen, const void *info, size_t infoLen,
                uint8_t *out, size_t outLen)
{
    uint8_t prk[32];
    {
        HmacSha256 extract(salt, saltLen);
        extract.Update(ikm, ikmLen);
        extract.Final(prk);
    }

    uint8_t block[32];
    size_t blockLen = 0;
    size_t produced = 0;
    uint8_t counter = 1;

    while (produced < outLen)
    {
        HmacSha256 expand(prk, sizeof(prk));
        expand.Update(block, blockLen);
        expand.Update(info, infoLen);
        expand.Update(&counter, 1);
        expand.Final(block);
        blockLen = sizeof(block);

        size_t take = outLen - produced;
        if (take > sizeof(block))
        {
            take = sizeof(block);
        }
        memcpy(out + produced, block, take);
        produced += take;
        counter++;
    }

    SecureZero(prk, sizeof(prk));
    SecureZero(block, sizeof(block));
}

bool ConstantTimeEqual(const void *a, const void *b, size_t len)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return diff == 0;
}

void SecureZero(void *data, size_t len)
{
    // volatile stops the compiler from proving the store is dead and dropping
    // it, which is exactly what happens to a plain memset on key material.
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (len-- > 0)
    {
        *p++ = 0;
    }
}
} // namespace RelayCrypto
