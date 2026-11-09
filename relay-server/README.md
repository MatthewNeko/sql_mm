# sqlmm-relay

The MySQL side of [SQLMM](../README.md). Game servers run a Metamod plugin that
speaks a small framed protocol over TCP; this daemon turns those requests into
real MySQL traffic.

```
game servers (sql_mm) ──TCP──▶ sqlmm-relay ──▶ MySQL
```

One relay handles many game servers. Each relay **session** owns exactly one
physical MySQL connection, never a shared pooled one — the plugin implements
transactions by shipping `BEGIN`/`COMMIT` as plain statements, and callers rely
on `LAST_INSERT_ID()`, user variables and temp tables surviving between
statements. Pooling those together would corrupt transactions in ways that are
very hard to notice.

## Build

```bash
go build -o sqlmm-relay .
```

Cross-compile for a Linux box:

```bash
GOOS=linux GOARCH=amd64 go build -o sqlmm-relay .
```

Only dependency: `github.com/go-sql-driver/mysql` plus `golang.org/x/crypto`
(for ChaCha20).

## Run

```bash
cp config.example.json config.json
./sqlmm-relay -genkey        # prints 64 hex characters = 32 bytes
$EDITOR config.json          # paste it into "psk"
./sqlmm-relay -config config.json
```

Flags: `-config <path>` (default `config.json`), `-listen <addr>` to override the
bind address, `-genkey` to print a fresh pre-shared key, `-version`.

Put the same key in each game server's `addons/sql_mm/sql_mm.cfg` as
`relay_psk`. Both sides refuse to start/connect otherwise.

## Configuration

| key | default | meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:9330` | Bind address. Use `0.0.0.0:9330` only behind a private network or an allowlist. |
| `encryption` | `psk` | `psk` = ChaCha20 + HMAC-SHA256 with a shared key. `none` = clear text (legacy, loopback only). |
| `psk` | `""` | Shared key. 64 hex characters are decoded to 32 raw bytes; anything else is used verbatim and must be at least 32 bytes. Falls back to `token` when empty. |
| `token` | `""` | Pre-2.0 name for the shared secret. Still accepted as the key source; no longer sent over the wire. |
| `log_level` | `info` | `error`, `warn`, `info`, `debug`. `debug` logs every query. |
| `max_payload_bytes` | `16777216` | Max plaintext frame size (16 MiB). Larger results are rejected instead of buffered. Hard ceiling 256 MiB, because every live session can hold one frame. |
| `allow_client_dsn` | `false` | Honour the host/user/pass/database the plugin passes. Off by default: with it on, anyone holding the PSK can point the relay at a host of their choosing. |
| `allowed_client_hosts` | `[]` | Required when `allow_client_dsn` is on. Entries are IPs, hostnames or Unix socket paths. Empty list refuses **every** client-supplied host; `["*"]` explicitly disables the check. Matching is done on resolved addresses and the matched address is what gets dialled, so a name cannot be re-pointed between check and connect. |
| `allowed_client_databases` | `[]` | Database names a client may select. Empty = any schema the relay's account can reach. This is a convenience filter, **not** a security boundary: it gates the database in `CONNECT`, and a client can still issue `USE other_db` or `other_db.table`. The real limit is the MySQL account's grants. |
| `fallback` | `127.0.0.1:3306` | DSN used when `allow_client_dsn` is off or the client sends an empty host. |
| `allowed_peers` | `[]` | CIDR allowlist for source addresses. Empty = any. |
| `dial_timeout_seconds` | `10` | Timeout for connecting to MySQL. |
| `read_timeout_seconds` / `write_timeout_seconds` | `120` / `60` | Per-socket timeouts towards MySQL. The read side is floored at 120 s so a stalled query cannot pin a session forever; the plugin's `MySQLConnectionInfo.timeout` overrides it when set. |
| `query_timeout_seconds` | `0` | `0` = a slow statement blocks its own session only (legacy behaviour). Non-zero cancels it, which drops the MySQL connection and its session state. |
| `max_sessions` | `64` | Concurrent sessions. Each one holds a MySQL connection. |
| `max_sessions_per_peer` | `16` | Sessions allowed from a single source address. Several srcds instances often share one IP. |

## Annotated config

`config.example.json` is the same thing without comments (JSON has none). This
variant trusts any source address and any MySQL host, and restricts only the
database names — the smallest config that still keeps one game server out of
another server's schema.

```jsonc
{
  // Reachable from the game servers. The port is protected by the PSK, not by
  // a source-address allowlist.
  "listen": "0.0.0.0:9330",

  "encryption": "psk",
  "psk": "<output of: sqlmm-relay -genkey>",

  "log_level": "info",

  // Frames are buffered whole; 16 MiB is plenty for plugin-sized result sets.
  "max_payload_bytes": 16777216,

  // Let the plugin name the target. Required for allowed_client_databases to
  // mean anything.
  "allow_client_dsn": true,

  // "*" = no host restriction. Replace with the addresses the relay is allowed
  // to dial if it can reach MySQL instances your game servers should not touch.
  "allowed_client_hosts": ["*"],

  // The one restriction in this setup: the schema named in CONNECT must be on
  // this list. It filters CONNECT only — a connected client can still run
  // `USE other_db`. Scope the MySQL account if you need a hard boundary.
  "allowed_client_databases": ["cs2kz", "cs2kz_stats"],

  // Used when a client sends an empty host, and always when allow_client_dsn
  // is false.
  "fallback": {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "cs2",
    "pass": "<password>",
    "database": "cs2kz"
  },

  // Empty = accept any source address. Filling it in costs nothing and keeps
  // port scans away from the handshake; do it once the game servers have fixed
  // addresses.
  "allowed_peers": [],

  "dial_timeout_seconds": 10,
  // Never below 120: a stalled query must not pin a session forever.
  "read_timeout_seconds": 120,
  "write_timeout_seconds": 60,
  // 0 keeps legacy behaviour (a slow statement blocks only its own session).
  "query_timeout_seconds": 0,

  // One MySQL connection per session; keep this under max_connections.
  "max_sessions": 128,
  "max_sessions_per_peer": 4
}
```

## Two deployment shapes

**One relay, many databases** (`allow_client_dsn: true`). Each game server keeps
its own credentials in `addons/sql_mm/sql_mm.cfg` / its plugin config and the
relay just forwards them. `allowed_client_hosts` must be set:

- list the MySQL addresses the relay may dial, or
- `["*"]` to skip the host check entirely and rely on `allowed_client_databases`
  plus the MySQL account's grants.

`["*"]` is a deliberate hole: anyone holding the PSK can point the relay at any
MySQL host it can reach, including one that trusts the relay's source address.
The relay logs a warning at startup. The database allowlist does not close it —
it only filters the schema named in `CONNECT`.

**One relay, one database** (`allow_client_dsn: false`, the default). The relay
holds the only credentials; game servers cannot choose a target. This is the
right shape when the relay sits on the DB host and every game server should hit
the same schema. Need several databases? Run several instances on different
ports — the binary is a few megabytes and idles at ~10 MB RSS with a handful of
sessions.

## Capacity

- Put the relay **next to MySQL**, not next to the game servers. Every query
  pays one round trip to the relay, and the relay pays one to MySQL; keeping the
  second hop local keeps query latency at roughly one network RTT.
- Sessions are cheap: one goroutine pair, one MySQL connection, plus the result
  set being materialised.
- `N` game servers need `N` MySQL connections (each SQLMM connection opens one
  session). Raise MySQL's `max_connections` accordingly and keep
  `max_sessions` below it.
- Result sets are buffered whole, because `ISQLResult` must support `Rewind()`
  and `GetRowCount()`. Cap them with `LIMIT` — this is the same constraint the
  old `mysql_store_result` path had.
- The relay is a single point of failure for every server pointed at it. Run it
  under systemd with `Restart=always`; plugin sessions reconnect on their own.

## Security

- The channel is encrypted: ChaCha20 for confidentiality, HMAC-SHA256 for
  integrity, keys derived per connection with HKDF-SHA256 from the shared key
  and both nonces. See `PROTOCOL.md` for the exact construction.
- What it does **not** give you: forward secrecy. A leaked PSK decrypts captured
  traffic. Rotate the key if it may have leaked; both sides must be updated
  together.
- A wrong key is indistinguishable from a broken relay at the plugin, by design:
  the server closes without explaining which side was wrong. Check the relay log
  (`client failed authentication (wrong key)`) when a plugin suddenly cannot
  connect after a key change.
- Bind to loopback when the game server and the relay are on the same box.
- Use `allowed_peers` even on a private network — it costs nothing and stops a
  forgotten public bind from becoming an open SQL proxy. Encryption is not a
  substitute for an allowlist: it authenticates peers, it does not restrict who
  may try.
- Prefer a dedicated MySQL user limited to the schema the plugins need.
- `encryption: "none"` exists for the single-box case only and refuses to start
  on anything but a loopback `listen` address. A plugin configured for `psk`
  will refuse to talk to it.
- Resource limits: a semaphore caps total TCP connections at
  `max_sessions * 2 + 16` (handshakes included), the session counter is claimed
  with an atomic increment rather than a check-then-act, and the handshake has a
  15 s read deadline. Together these stop an unauthenticated client from pinning
  goroutines or file descriptors.
- Error text is redacted before it leaves the process: the internal MySQL
  address never appears in plugin logs, and messages are truncated to one line
  so a hostile server cannot forge log entries.
- Sessions with `sql_mode = NO_BACKSLASH_ESCAPES` are rewritten to drop the flag;
  if that is impossible the session is **refused**, because the plugin escapes
  with backslashes and would otherwise be injectable.

### systemd unit

```ini
[Unit]
Description=SQLMM MySQL relay
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/sqlmm-relay
ExecStart=/opt/sqlmm-relay/sqlmm-relay -config /opt/sqlmm-relay/config.json
Restart=always
RestartSec=2
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
```

## Testing

```bash
go test ./...                       # framing, handshake, crypto, allowlists
go test -run TestCrossVectors -v    # prints vectors to compare with the plugin
```

The unit tests cover framing, the encrypted handshake (good key, wrong key,
clear text refusal, protocol-version mismatch), HKDF against RFC 5869, tag
tampering, replay, the peer allowlist and concurrent clients. They deliberately
do not require a MySQL server; for a smoke test against a real database, point
`fallback` at one and run a `SELECT 1` through a game server (or the plugin's
own health check).

The plugin has its own C++ implementation of the same primitives. Two checks
keep them honest:

- `tools/crypto_selftest.cpp` runs the RFC 4231 / RFC 5869 / RFC 8439 vectors.
- `tools/relay_e2e.cpp` connects to a live relay and exercises the encrypted
  handshake, PING/PONG, a wrong key and a downgrade attempt.

Both print `CROSS` lines from `TestCrossVectors`; they must stay byte identical.
Changing the nonce layout, the HKDF `info` string or the MAC input on one side
without the other breaks every handshake, and this is the cheapest way to catch
it before deploying.

## Behaviour worth knowing

- Statement dispatch: statements starting with `SELECT`, `WITH`, `SHOW`,
  `DESCRIBE`, `EXPLAIN`, `TABLE`, `VALUES`, `ANALYZE`, `CHECK`, `CHECKSUM`,
  `HELP`, `HANDLER` or `CALL` go through the row-returning path; everything else
  goes through `Exec`, which is what exposes `LastInsertId`/`RowsAffected`.
- A transaction returns one result per statement, in order, even for statements
  with no result set — the plugin's callback hands callers a positional
  `std::vector<ISQLQuery*>`.
- `sql_mode`: the relay clears `NO_BACKSLASH_ESCAPES` on its own session and
  refuses the session when it cannot, so `Escape()` on the plugin side is always
  backslash escaping. The `FeatureNoBackslashEscapes` bit is still honoured for
  relays built before that guarantee.
