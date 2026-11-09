/**
 * =============================================================================
 * SQLMM relay client
 * =============================================================================
 */

#include "relay_config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "tier0/dbg.h"

namespace
{
// Absolute path of this shared object, or empty when it cannot be resolved.
// Resolving the config relative to the plugin instead of the process working
// directory is what makes the file findable regardless of how srcds was
// launched: the server's cwd is often game/bin/linuxsteamrt64, while the cfg
// lives in game/csgo/addons/sql_mm/.
std::string ModulePath()
{
#ifdef _WIN32
    HMODULE module = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)&ModulePath, &module))
    {
        return std::string();
    }
    char buffer[MAX_PATH] = {};
    DWORD len = GetModuleFileNameA(module, buffer, (DWORD)sizeof(buffer));
    if (len == 0 || len >= sizeof(buffer))
    {
        return std::string();
    }
    return std::string(buffer, len);
#else
    Dl_info info;
    if (dladdr((void *)&ModulePath, &info) && info.dli_fname != nullptr)
    {
        return std::string(info.dli_fname);
    }
    return std::string();
#endif
}

std::string DirName(const std::string &path)
{
    size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos)
    {
        return std::string();
    }
    return path.substr(0, slash);
}

bool FileExists(const std::string &path)
{
    if (path.empty())
    {
        return false;
    }
    FILE *probe = fopen(path.c_str(), "rb");
    if (!probe)
    {
        return false;
    }
    fclose(probe);
    return true;
}
std::string Trim(const std::string &in)
{
    size_t begin = in.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
    {
        return std::string();
    }
    size_t end = in.find_last_not_of(" \t\r\n");
    return in.substr(begin, end - begin + 1);
}

std::string StripQuotes(const std::string &in)
{
    if (in.size() >= 2 && ((in.front() == '"' && in.back() == '"') || (in.front() == '\'' && in.back() == '\'')))
    {
        return in.substr(1, in.size() - 2);
    }
    return in;
}

bool StartsWith(const std::string &haystack, const char *needle)
{
    size_t len = strlen(needle);
    return haystack.size() >= len && haystack.compare(0, len, needle) == 0;
}

int HexValue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

// Accepts only an even-length, all-hex string. Returns false for anything
// else so a passphrase that happens to be 64 characters is not mangled.
bool DecodeHex(const std::string &in, std::vector<uint8_t> &out)
{
    if (in.empty() || (in.size() % 2) != 0)
    {
        return false;
    }
    std::vector<uint8_t> decoded;
    decoded.reserve(in.size() / 2);
    for (size_t i = 0; i < in.size(); i += 2)
    {
        int hi = HexValue(in[i]);
        int lo = HexValue(in[i + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        decoded.push_back((uint8_t)((hi << 4) | lo));
    }
    out.swap(decoded);
    return true;
}

void ApplyPair(RelayConfig &cfg, const std::string &key, const std::string &value)
{
    if (key == "relay_host" || key == "host")
    {
        cfg.host = value;
    }
    else if (key == "relay_port" || key == "port")
    {
        cfg.port = (uint16_t)atoi(value.c_str());
    }
    else if (key == "relay_psk" || key == "psk" || key == "relay_token" || key == "token")
    {
        // relay_token is the pre-2.0 name; it is now simply the key.
        cfg.psk = value;
    }
    else if (key == "relay_encryption" || key == "encryption")
    {
        std::string mode = Trim(value);
        for (char &c : mode)
        {
            if (c >= 'A' && c <= 'Z')
            {
                c = (char)(c - 'A' + 'a');
            }
        }
        if (mode == "none" || mode == "off" || mode == "plain" || mode == "plaintext")
        {
            cfg.encryption = RelayEncryption::None;
        }
        else
        {
            cfg.encryption = RelayEncryption::Psk;
        }
    }
    else if (key == "relay_connect_timeout" || key == "connect_timeout")
    {
        cfg.connectTimeoutMs = atoi(value.c_str()) * 1000;
    }
    else if (key == "relay_io_timeout" || key == "io_timeout")
    {
        cfg.ioTimeoutMs = atoi(value.c_str()) * 1000;
    }
    else if (key == "relay_max_response_mb" || key == "max_response_mb")
    {
        long long mb = atoll(value.c_str());
        if (mb > 0)
        {
            cfg.maxPayloadBytes = (uint32_t)(mb * 1024ull * 1024ull);
        }
    }
}
} // namespace

void ApplyRelayEnv(RelayConfig &cfg)
{
    const char *host = getenv("SQLMM_RELAY_HOST");
    if (host && host[0])
    {
        cfg.host = host;
    }
    const char *port = getenv("SQLMM_RELAY_PORT");
    if (port && port[0])
    {
        cfg.port = (uint16_t)atoi(port);
    }
    const char *psk = getenv("SQLMM_RELAY_PSK");
    if (!psk)
    {
        psk = getenv("SQLMM_RELAY_TOKEN");
    }
    if (psk)
    {
        cfg.psk = psk;
    }
    const char *encryption = getenv("SQLMM_RELAY_ENCRYPTION");
    if (encryption && encryption[0])
    {
        cfg.encryption = Trim(encryption) == "none" ? RelayEncryption::None : RelayEncryption::Psk;
    }
}

RelayConfig LoadRelayConfig(const char *path)
{
    RelayConfig cfg;

    std::ifstream file(path);
    if (!file.is_open())
    {
        return cfg;
    }

    std::string line;
    bool firstLine = true;
    while (std::getline(file, line))
    {
        // Editors on Windows happily write a UTF-8 BOM; without this the first
        // line's key gains three junk bytes and stops matching.
        if (firstLine && line.size() >= 3 && (unsigned char)line[0] == 0xEF && (unsigned char)line[1] == 0xBB &&
            (unsigned char)line[2] == 0xBF)
        {
            line.erase(0, 3);
        }
        firstLine = false;

        // Strip comments. '#' and ';' are honoured at any position; "//" only
        // at the start so Windows paths survive.
        std::string trimmed = Trim(line);
        if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';' || StartsWith(trimmed, "//"))
        {
            continue;
        }

        // Only treat '#' and ';' as comment starters when they begin the line
        // or follow whitespace, so keys and paths may contain them.
        for (size_t i = 0; i < trimmed.size(); i++)
        {
            char c = trimmed[i];
            if ((c == '#' || c == ';') && (i == 0 || trimmed[i - 1] == ' ' || trimmed[i - 1] == '\t'))
            {
                trimmed = Trim(trimmed.substr(0, i));
                break;
            }
        }

        size_t sep = trimmed.find_first_of("=:");
        if (sep == std::string::npos)
        {
            continue;
        }

        std::string key = Trim(trimmed.substr(0, sep));
        std::string value = StripQuotes(Trim(trimmed.substr(sep + 1)));
        ApplyPair(cfg, key, value);
    }

    return cfg;
}

bool RelayConfig::KeyMaterial(std::vector<uint8_t> &out, std::string &err) const
{
    out.clear();
    if (encryption == RelayEncryption::None)
    {
        err.clear();
        return true;
    }

    std::string material = Trim(psk);
    if (material.empty())
    {
        err = "relay_psk is empty; set it in addons/sql_mm/sql_mm.cfg or SQLMM_RELAY_PSK "
              "(the \"relay config:\" line above names the file that was read)";
        return false;
    }

    if (material.size() == 64 && DecodeHex(material, out))
    {
        return true;
    }

    out.assign(material.begin(), material.end());
    return true;
}

bool RelayConfig::Validate(std::string &err) const
{
    if (encryption == RelayEncryption::None)
    {
        err.clear();
        return true;
    }

    std::vector<uint8_t> key;
    if (!KeyMaterial(key, err))
    {
        return false;
    }
    if (key.size() < 32)
    {
        char buffer[224];
        snprintf(buffer, sizeof(buffer),
                 "relay_psk is %u bytes, need at least 32 (run: openssl rand -hex 32, then paste it as relay_psk)",
                 (unsigned)key.size());
        err = buffer;
        return false;
    }
    err.clear();
    return true;
}

std::string RelayConfig::Describe() const
{
    char buffer[320];
    snprintf(buffer, sizeof(buffer), "%s:%u (encryption %s, key %s, connect timeout %dms, max response %uMB)", host.c_str(),
             (unsigned)port, encryption == RelayEncryption::Psk ? "psk/chacha20+hmac" : "NONE (clear text)",
             psk.empty() ? "missing" : "set", connectTimeoutMs, (unsigned)(maxPayloadBytes / (1024u * 1024u)));
    return std::string(buffer);
}

const RelayConfig &RelayConfig::Get()
{
    static RelayConfig cfg;
    static bool loaded = false;

    if (loaded)
    {
        return cfg;
    }
    loaded = true;

    const char *explicitPath = getenv("SQLMM_RELAY_CONFIG");
    std::string loadedPath;
    if (explicitPath && explicitPath[0])
    {
        if (FileExists(explicitPath))
        {
            cfg = LoadRelayConfig(explicitPath);
            loadedPath = explicitPath;
        }
        else
        {
            Warning("[SQLMM] SQLMM_RELAY_CONFIG points at %s, which does not exist\n", explicitPath);
        }
    }

    if (loadedPath.empty())
    {
        // Order matters: the plugin-relative locations are authoritative, since
        // the process working directory varies between hosts (game/csgo,
        // game/bin/linuxsteamrt64, the serverfiles root, ...).
        std::vector<std::string> candidates;
        const std::string moduleDir = DirName(ModulePath());
        if (!moduleDir.empty())
        {
            // addons/sql_mm/sql_mm.cfg when the .so sits in bin/<platform>/
            candidates.push_back(moduleDir + "/../../sql_mm.cfg");
            // ...and when the .so sits directly in addons/sql_mm/
            candidates.push_back(moduleDir + "/sql_mm.cfg");
        }
        candidates.push_back("addons/sql_mm/sql_mm.cfg");
        candidates.push_back("csgo/addons/sql_mm/sql_mm.cfg");

        for (const std::string &candidate : candidates)
        {
            if (!FileExists(candidate))
            {
                continue;
            }
            cfg = LoadRelayConfig(candidate.c_str());
            loadedPath = candidate;
            break;
        }

        if (loadedPath.empty())
        {
            std::string list;
            for (const std::string &candidate : candidates)
            {
                list += list.empty() ? "" : ", ";
                list += candidate;
            }
            Warning("[SQLMM] no relay config found (looked for: %s); using defaults\n", list.c_str());
        }
    }

    if (!loadedPath.empty())
    {
        Msg("[SQLMM] relay config: %s\n", loadedPath.c_str());
    }

    ApplyRelayEnv(cfg);

    if (cfg.port == 0)
    {
        cfg.port = 9330;
    }
    if (cfg.connectTimeoutMs <= 0)
    {
        cfg.connectTimeoutMs = 5000;
    }

    Msg("[SQLMM] MySQL relay: %s\n", cfg.Describe().c_str());

    std::string err;
    if (!cfg.Validate(err))
    {
        // Not fatal here: SQLPlugin::Load validates the same thing and refuses
        // to load with a readable error. Error() would kill the whole server.
        Warning("[SQLMM] relay configuration is unusable: %s\n", err.c_str());
    }
    else if (cfg.encryption == RelayEncryption::None)
    {
        Warning("[SQLMM] relay encryption is disabled; tokens and SQL travel in clear text.\n");
    }

    return cfg;
}
