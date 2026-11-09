/**
 * =============================================================================
 * SQLMM relay client
 *
 * ChaCha20 (RFC 8439) with the IETF layout: 32 byte key, 12 byte nonce,
 * 32-bit block counter starting at zero. Matches golang.org/x/crypto/chacha20,
 * which the relay uses on the other side, so both ends produce identical
 * keystreams for identical inputs.
 * =============================================================================
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace RelayCrypto
{
constexpr size_t kChaCha20KeyBytes = 32;
constexpr size_t kChaCha20NonceBytes = 12;

class ChaCha20
{
public:
    // blockCounter is exposed only so the RFC 8439 vectors (which start at
    // block 1) can be checked; the relay always starts each frame at 0.
    ChaCha20(const uint8_t key[kChaCha20KeyBytes], const uint8_t nonce[kChaCha20NonceBytes], uint32_t blockCounter = 0);

    // XORs the keystream into data in place. Consecutive calls continue the
    // same keystream, exactly like a stream cipher is supposed to.
    void XorKeyStream(uint8_t *data, size_t len);

private:
    void GenerateBlock();

    uint32_t m_state[16];
    uint8_t m_block[64];
    size_t m_pos = sizeof(m_block);
};
} // namespace RelayCrypto
