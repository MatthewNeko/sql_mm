/**
 * =============================================================================
 * SQLMM relay client — crypto self test
 *
 * Not part of the plugin. Build and run it on a dev box to prove that the
 * hand-written primitives match their RFC test vectors, and that the derived
 * keys and sealed frames match the Go relay byte for byte:
 *
 *   g++ -std=c++17 -I../src/relay/crypto crypto_selftest.cpp \
 *       ../src/relay/crypto/sha256.cpp ../src/relay/crypto/chacha20.cpp \
 *       ../src/relay/crypto/relay_cipher.cpp -o selftest && ./selftest
 *
 * The CROSS lines are compared against `go test -run TestCrossVectors -v` in
 * relay-server; a mismatch means the two ends would never complete a
 * handshake.
 * =============================================================================
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "chacha20.h"
#include "relay_cipher.h"
#include "sha256.h"

namespace
{
int g_failures = 0;

std::string ToHex(const uint8_t *data, size_t len)
{
    static const char *kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++)
    {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0F]);
    }
    return out;
}

void Check(const char *name, const void *got, size_t len, const char *wantHex)
{
    std::string hex = ToHex((const uint8_t *)got, len);
    if (hex == wantHex)
    {
        printf("ok   %s\n", name);
        return;
    }
    printf("FAIL %s\n  got  %s\n  want %s\n", name, hex.c_str(), wantHex);
    g_failures++;
}

void FromHex(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        unsigned v = 0;
        sscanf(hex + i * 2, "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

void TestSha256()
{
    uint8_t digest[32];

    RelayCrypto::Sha256("abc", 3, digest);
    Check("sha256(\"abc\")", digest, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    RelayCrypto::Sha256("", 0, digest);
    Check("sha256(\"\")", digest, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const char *twoBlocks = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    RelayCrypto::Sha256(twoBlocks, strlen(twoBlocks), digest);
    Check("sha256(448-bit)", digest, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

void TestHmac()
{
    uint8_t mac[32];
    const char *msg = "what do ya want for nothing?";

    RelayCrypto::HmacSha256 hmac("Jefe", 4);
    hmac.Update(msg, strlen(msg));
    hmac.Final(mac);
    Check("hmac-sha256 rfc4231 #2", mac, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    // Long key: exercises the "hash the key first" path.
    uint8_t longKey[131];
    memset(longKey, 0xaa, sizeof(longKey));
    RelayCrypto::HmacSha256 hmac2(longKey, sizeof(longKey));
    const char *msg2 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac2.Update(msg2, strlen(msg2));
    hmac2.Final(mac);
    Check("hmac-sha256 rfc4231 #6", mac, 32, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

void TestHkdf()
{
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    uint8_t salt[13];
    FromHex("000102030405060708090a0b0c", salt, sizeof(salt));
    uint8_t info[10];
    FromHex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));

    uint8_t okm[42];
    RelayCrypto::HkdfSha256(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), okm, sizeof(okm));
    Check("hkdf-sha256 rfc5869 #1", okm, sizeof(okm),
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

void TestChaCha20()
{
    // RFC 8439 section 2.4.2.
    uint8_t key[32];
    for (int i = 0; i < 32; i++)
    {
        key[i] = (uint8_t)i;
    }
    uint8_t nonce[12];
    FromHex("000000000000004a00000000", nonce, sizeof(nonce));

    const char *plain = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
                        "sunscreen would be it.";
    size_t len = strlen(plain);

    std::vector<uint8_t> buf(len);
    memcpy(buf.data(), plain, len);

    RelayCrypto::ChaCha20 stream(key, nonce, 1);
    stream.XorKeyStream(buf.data(), buf.size());

    Check("chacha20 rfc8439 2.4.2", buf.data(), buf.size(),
          "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e651"
          "52ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8ee"
          "df2785e42874d");
}

// Vectors mirrored by relay-server/crosscheck_test.go.
void PrintCrossVectors()
{
    uint8_t key[32];
    for (int i = 0; i < 32; i++)
    {
        key[i] = (uint8_t)i;
    }
    uint8_t nonce[12];
    FromHex("000102030405060708090a0b", nonce, sizeof(nonce));
    const char *plain = "sqlmm relay cross-check payload";

    std::vector<uint8_t> buf(strlen(plain));
    memcpy(buf.data(), plain, buf.size());
    RelayCrypto::ChaCha20 stream(key, nonce);
    stream.XorKeyStream(buf.data(), buf.size());
    printf("CROSS chacha20 %s\n", ToHex(buf.data(), buf.size()).c_str());

    uint8_t clientNonce[32];
    uint8_t serverNonce[32];
    for (int i = 0; i < 32; i++)
    {
        clientNonce[i] = (uint8_t)i;
        serverNonce[i] = (uint8_t)(0x20 + i);
    }
    const char *psk = "0123456789abcdef0123456789abcdef";

    Relay::Cipher c2s;
    Relay::Cipher s2c;
    Relay::DeriveSessionKeys((const uint8_t *)psk, strlen(psk), clientNonce, serverNonce, c2s, s2c);

    std::vector<char> sealed;
    c2s.Seal("SELECT 1", 8, sealed);
    printf("CROSS sealed %s\n", ToHex((const uint8_t *)sealed.data(), sealed.size()).c_str());
}
} // namespace

int main()
{
    TestSha256();
    TestHmac();
    TestHkdf();
    TestChaCha20();
    PrintCrossVectors();

    if (g_failures != 0)
    {
        printf("%d FAILED\n", g_failures);
        return 1;
    }
    printf("all vectors pass\n");
    return 0;
}
