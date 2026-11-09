# SQLMM

SQLMM provides non-blocking MySQL/SQLite connectors for MetaMod.

Since 2.0 MySQL no longer goes through libmysqlclient inside the game process.
The plugin is a thin client that forwards SQL to a small Go daemon, the **relay**
(`relay-server/`), which owns the MySQL connections. From the game's point of
view nothing changed: the `ISQLInterface` / `ISQLConnection` API and its
callback semantics are identical.

```
srcds (sql_mm.so)  ──encrypted TCP──▶  sqlmm-relay (Go)  ──▶  MySQL
   SQLite stays local, untouched
```

Why:

- No `default-libmysqlclient-dev` on Linux, no 76 MB `mysqlclient.lib` on
  Windows, no client DLL to ship next to `sql_mm.so`.
- One relay serves many game servers; DB credentials and DB-side pooling live in
  one place instead of on every server.
- The game process cannot block on a database: every call is serialised onto the
  relay socket on a worker thread, exactly like before, but there is no MySQL
  client library misbehaving inside `srcds`.
- The link is encrypted and authenticated with a pre-shared key, so tokens, SQL
  text and result rows are no longer readable on the network. The crypto is
  built into the plugin (no OpenSSL), and every primitive is checked against its
  RFC test vectors.

# Features

- Non-blocking MySQL/SQLite queries/transactions
- Windows & Linux support
- Simple API
- MySQL session affinity: one relay session == one physical MySQL connection, so
  `BEGIN`/`COMMIT` spanning several statements plus `LAST_INSERT_ID()`, user
  variables and temp tables keep working
- Multiple game servers per relay, one MySQL connection each
- ChaCha20 + HMAC-SHA256 session encryption with HKDF-SHA256 key derivation and
  per-frame sequence numbers (replay/reorder protection)

# Interface

SQLMM will expose an interface in `OnMetamodQuery` which can then be queried with `(ISQLInterface*)g_SMAPI->MetaFactory(SQLMM_INTERFACE, &ret, NULL);` by other plugins.
Example:
```c++
  ISQLiteClient *g_pSQLiteClient;
	g_pSQLiteClient = ((ISQLInterface *)g_SMAPI->MetaFactory(SQLMM_INTERFACE, nullptr, nullptr))->GetSQLiteClient();
	g_SMAPI->PathFormat(buffer, sizeof(buffer), "path/to/database/db.sqlite3");
	if (g_pSQLiteClient)
	{
		SQLiteConnectionInfo info;
		info.database = buffer;
		conn = g_pSQLiteClient->CreateSQLiteConnection(info);
		conn->Connect(
			[](bool success)
			{
        //...
			});
	}
```

Interface definition can be found in `src/public`.

MySQL connections are created the same way, from a `MySQLConnectionInfo`
(host/user/pass/database/port/timeout). When the relay runs with
`allow_client_dsn: false`, those fields are ignored and the relay's own
credentials are used.

## Relay configuration (plugin side)

`addons/sql_mm/sql_mm.cfg`, read once at plugin load. Encryption is on by
default and `relay_psk` is mandatory in that mode — the plugin refuses to load
without it rather than silently connecting in clear text.

The file is located relative to the plugin binary, so it is found no matter
which directory srcds was started from: `<plugin dir>/../../sql_mm.cfg`
(the normal `addons/sql_mm/sql_mm.cfg`), then `<plugin dir>/sql_mm.cfg`, then
`./addons/sql_mm/sql_mm.cfg` and `./csgo/addons/sql_mm/sql_mm.cfg`.
`SQLMM_RELAY_CONFIG` overrides the search entirely. The server log prints
`[SQLMM] relay config: <path>` on load, and lists every candidate when none
exists — check that line first if the key appears to be missing.

```
# Where the relay daemon listens.
relay_host = 127.0.0.1
relay_port = 9330

# psk (default) or none. Must match the relay's encryption setting.
relay_encryption = psk

# Shared key; must match the relay's "psk".
# Generate with: sqlmm-relay -genkey   (64 hex chars = 32 bytes)
relay_psk =

# TCP connect timeout, seconds.
relay_connect_timeout = 5

# Socket read/write timeout, seconds. 0 = use each connection's
# MySQLConnectionInfo.timeout (the old libmysqlclient behaviour).
relay_io_timeout = 0

# Largest relay response the plugin will buffer, MB.
relay_max_response_mb = 64
```

Environment overrides, useful in containers: `SQLMM_RELAY_HOST`,
`SQLMM_RELAY_PORT`, `SQLMM_RELAY_PSK`, `SQLMM_RELAY_ENCRYPTION`.
`SQLMM_RELAY_CONFIG` points at a different config file.

A plugin set to `psk` aborts the handshake when the relay answers with a clear
text suite, so an attacker cannot strip the encryption by pretending to be an
older server.

## Building the relay

```bash
cd relay-server
go build -o sqlmm-relay .
./sqlmm-relay -genkey        # paste into config.json "psk" and relay_psk
./sqlmm-relay -config config.json
```

See [relay-server/README.md](relay-server/README.md) for the config reference
and [relay-server/PROTOCOL.md](relay-server/PROTOCOL.md) for the wire format.

## Compilation

### Requirements

- [Metamod:Source](https://www.sourcemm.net/downloads.php/?branch=master) 2.0.0.1462 or higher, which uses
  [KHook](https://github.com/Kenzzer/KHook) instead of SourceHook. Clone it with `--recursive`; KHook is a submodule
  of it and its headers are needed to build.
- [s2sdk](https://github.com/alliedmodders/s2sdk), `cs2` branch. The `cs2` branch of hl2sdk is no longer maintained.
- [AMBuild](https://wiki.alliedmods.net/Ambuild)
- On Linux, the `lld` package. **The MySQL client development package is no
  longer required.**

```bash
git clone https://github.com/zer0k-z/sql_mm && cd sql_mm
git submodule update --init

export MMSOURCE20=/path/to/metamod-source/
export HL2SDKCS2=/path/to/hl2sdk-cs2

mkdir build && cd build
python3 ../configure.py -s cs2
ambuild
```

The package is written to `build/package`.

### One-shot build (Linux, plugin + relay)

`scripts/build-linux.sh` does the whole thing in one go and stages a
ready-to-copy tree in `dist/`:

```
dist/
├── addons/
│   ├── metamod/sql_mm.vdf
│   └── sql_mm/
│       ├── sql_mm.cfg
│       └── bin/linuxsteamrt64/sql_mm.so     # stripped
└── relay/
    ├── sqlmm-relay-linux-amd64              # static, CGO disabled
    ├── sqlmm-relay-windows-amd64.exe
    ├── config.example.json
    └── README.md
```

```bash
./scripts/build-linux.sh                 # HL2SDK_ROOT / MMS_PATH override the defaults
PLUGIN_ONLY=1 ./scripts/build-linux.sh   # plugin only
./scripts/e2e-check.sh                   # handshake smoke test of the built pair
```

Build notes, in case you point it at a different SDK snapshot:

- The plugin needs the SDK's generated netmessages protobufs (`engine2` headers
  include them), so `AMBuilder` runs protoc over every `common/*.proto`.
- Source 2 SDK snapshots disagree on where `convar.cpp` lives
  (`tier0_perproject/` vs `tier1/`); `AMBuildScript` picks whichever exists.
- Metamod:Source trees trimmed for Source 2 drop SourceHook, others require it;
  the include path is only added when that directory is present.
- Link with `lld` (`-Wl,--no-gnu-unique` keeps KHook's `STB_GNU_UNIQUE` symbols
  from pinning the plugin in memory after `dlclose`).

## Migrating from 1.x

1. Start `sqlmm-relay` somewhere the game servers can reach, configured with
   credentials for the database.
2. Generate a key with `sqlmm-relay -genkey` and put the same value in the
   relay's `psk` and in each `addons/sql_mm/sql_mm.cfg` as `relay_psk`. A key
   shorter than 32 bytes is refused on both sides.
3. Drop `addons/sql_mm/sql_mm.cfg` next to the plugin (see above).
4. Replace the plugin binary. Nothing else changes; consumers keep their
   `MySQLConnectionInfo` values, which the relay honours by default.

Protocol v2 is not wire compatible with v1: upgrade the relay and the plugin
together, and do not expect an old plugin to connect (it will fail the version
check with a clear message).

Behaviour notes:

- A dropped relay connection is not retried mid-flight (that would risk
  duplicating non-idempotent statements). The failed call reports an error and
  the next call re-establishes the session after a 1s→30s backoff.
- A frame that fails authentication (wrong key, tampered stream) drops the
  connection instead of being retried, and the next call reconnects.
- `Escape()` is now done in-process with the same byte-wise rules as
  `mysql_real_escape_string`, including `NO_BACKSLASH_ESCAPES` detection. It no
  longer needs a live connection, so it works before `Connect()` completes.
- `GetFieldType()` returns the MySQL field type reported by the driver; exotic
  types fall back to `MM_MYSQL_TYPE_UNKNOWN`.

## Security notes

- The pre-shared key authenticates both ends and encrypts the stream. It has no
  forward secrecy: if the key leaks, recorded traffic can be decrypted. Rotate
  the key by changing it on both sides and restarting.
- The key is never sent over the wire; only nonces are. A captured handshake
  does not help an attacker without the key.
- `relay_encryption = none` exists for a relay on the same machine. It logs a
  warning, and a plugin set to `psk` will not fall back to it.
