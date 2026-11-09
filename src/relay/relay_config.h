/**
 * =============================================================================
 * SQLMM relay client
 *
 * Where the relay server lives and how the channel is protected. Read once at
 * plugin load from addons/sql_mm/sql_mm.cfg, with environment overrides for
 * containers.
 *
 * The file is optional: with no config the plugin talks to 127.0.0.1:9330 and
 * refuses to start because no key is configured. Encryption is on by default;
 * turning it off requires relay_encryption = none.
 * =============================================================================
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "relay_protocol.h"

enum class RelayEncryption
{
    // ChaCha20 + HMAC-SHA256 with a pre-shared key. The key never travels.
    Psk,
    // Legacy clear text, for a relay on the same box.
    None,
};

struct RelayConfig
{
    std::string host = "127.0.0.1";
    uint16_t port = 9330;

    RelayEncryption encryption = RelayEncryption::Psk;

    // Shared secret. A 64 character hex string is decoded to 32 raw bytes,
    // anything else is used verbatim (so a long passphrase works). Must be at
    // least 32 bytes; the plugin refuses to connect otherwise.
    std::string psk;

    // 0 means "use the MySQLConnectionInfo timeout of each connection".
    int connectTimeoutMs = 5000;
    int ioTimeoutMs = 0;

    uint32_t maxPayloadBytes = Relay::kDefaultMaxPayloadBytes;

    // Decoded key material. Only meaningful when encryption == Psk.
    bool KeyMaterial(std::vector<uint8_t> &out, std::string &err) const;

    // Cross-field checks that need the parsed key. Returns false and fills err
    // when the plugin must not start.
    bool Validate(std::string &err) const;

    // Loads the config, logging the effective values. Called once from
    // SQLPlugin::Load; the returned reference stays valid for the plugin's
    // lifetime.
    static const RelayConfig &Get();

    std::string Describe() const;
};

// Parses "addons/sql_mm/sql_mm.cfg". Exposed for tests and for Get().
RelayConfig LoadRelayConfig(const char *path);

// Applies SQLMM_RELAY_* environment overrides. Also exposed for tests.
void ApplyRelayEnv(RelayConfig &cfg);
