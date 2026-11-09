/**
 * =============================================================================
 * SQLMM relay client
 *
 * SHA-256, HMAC-SHA256 and HKDF-SHA256 (RFC 6234 / RFC 2104 / RFC 5869).
 *
 * The plugin deliberately has no OpenSSL dependency: a Metamod plugin that
 * links libcrypto has to ship or find the right .so/.lib on every host, which
 * is the exact problem the relay was built to remove. These three primitives
 * are short enough to audit and every one of them is checked against its RFC
 * test vectors by crypto_selftest.cpp.
 * =============================================================================
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace RelayCrypto
{
constexpr size_t kSha256Bytes = 32;

void Sha256(const void *data, size_t len, uint8_t out[kSha256Bytes]);

class HmacSha256
{
public:
    HmacSha256(const void *key, size_t keyLen);

    void Update(const void *data, size_t len);
    void Final(uint8_t out[kSha256Bytes]);

private:
    void Init(const void *key, size_t keyLen);

    uint32_t m_state[8];
    uint8_t m_block[64];
    size_t m_blockLen = 0;
    uint64_t m_totalLen = 0;
    uint8_t m_keyPad[64] = {};
};

// HKDF-Extract + HKDF-Expand in one call. out may be any length up to 255*32.
void HkdfSha256(const void *salt, size_t saltLen, const void *ikm, size_t ikmLen, const void *info, size_t infoLen,
                uint8_t *out, size_t outLen);

// Compares without leaking where the first difference is.
bool ConstantTimeEqual(const void *a, const void *b, size_t len);

// Overwrites memory in a way the optimiser may not remove.
void SecureZero(void *data, size_t len);
} // namespace RelayCrypto
