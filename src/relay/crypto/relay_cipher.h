/**
 * =============================================================================
 * SQLMM relay client
 *
 * One direction of the encrypted channel: ChaCha20 for confidentiality,
 * HMAC-SHA256 for integrity (encrypt-then-MAC, independent keys), and a
 * per-direction frame counter that doubles as the nonce.
 *
 * Wire layout of an encrypted frame:
 *
 *   ciphertext (plaintext length) || HMAC-SHA256(mac_key, seq || len || ct)
 *
 * The receiver checks the MAC before decrypting, so a forged frame never
 * reaches the SQL parser, and compares the sequence number so a captured
 * frame cannot be replayed into the same session.
 * =============================================================================
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace Relay
{
constexpr size_t kSessionKeyBytes = 64; // 32 byte cipher key + 32 byte MAC key
constexpr size_t kFrameTagBytes = 32;
constexpr size_t kHandshakeNonceBytes = 32;

class Cipher
{
public:
    Cipher() = default;
    ~Cipher();

    Cipher(const Cipher &) = delete;
    Cipher &operator=(const Cipher &) = delete;

    // material is enc_key || mac_key, as produced by DeriveSessionKeys.
    void Init(const uint8_t material[kSessionKeyBytes]);
    void Clear();

    bool IsReady() const
    {
        return m_ready;
    }

    // Seals plain into out (ciphertext + tag) and advances the counter.
    bool Seal(const char *plain, size_t len, std::vector<char> &out);

    // Authenticates and decrypts a frame produced by Seal. On failure out is
    // left empty and the connection must be dropped.
    bool Open(const char *frame, size_t len, std::vector<char> &out);

private:
    uint8_t m_encKey[32] = {};
    uint8_t m_macKey[32] = {};
    uint64_t m_seq = 0;
    bool m_ready = false;
};

// HKDF-SHA256 over both nonces. clientToServer and serverToClient end up with
// different keys, so a frame cannot be reflected back at its sender.
bool DeriveSessionKeys(const uint8_t *psk, size_t pskLen, const uint8_t clientNonce[kHandshakeNonceBytes],
                       const uint8_t serverNonce[kHandshakeNonceBytes], Cipher &clientToServer, Cipher &serverToClient);
} // namespace Relay
