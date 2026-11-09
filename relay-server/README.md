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
| `max_payload_bytes` | `67108864` | Max plaintext frame size. Larger results are rejected instead of buffered. |
| `allow_client_dsn` | `true` | Honour the host/user/pass/database the plugin passes. |
| `allowed_client_hosts` | `[]` | When `allow_client_dsn` is on, the only `host` values a client may request. Empty = any (SSRF risk). |
| `allowed_client_databases` | `[]` | Same, for database names. |
| `fallback` | `127.0.0.1:3306` | DSN used when `allow_client_dsn` is off or the client sends an empty host. |
| `allowed_peers` | `[]` | CIDR allowlist for source addresses. Empty = any. |
| `dial_timeout_seconds` | `10` | Timeout for connecting to MySQL. |
| `read_timeout_seconds` / `write_timeout_seconds` | `60` | Per-socket timeouts towards MySQL. The plugin's `MySQLConnectionInfo.timeout` overrides the read side when set. |
| `query_timeout_seconds` | `0` | `0` = a slow statement blocks its own session only (legacy behaviour). Non-zero cancels it, which drops the MySQL connection and its session state. |
| `max_sessions` | `64` | Concurrent sessions. Each one holds a MySQL connection. |
| `max_sessions_per_peer` | `16` | Sessions allowed from a single source address. Several srcds instances often share one IP. |

## Two deployment shapes

**One relay, many databases** (`allow_client_dsn: true`). Each game server keeps
its own credentials in `addons/sql_mm/sql_mm.cfg` / its plugin config and the
relay just forwards them. Fill in `allowed_client_hosts` and
`allowed_client_databases` if the relay is reachable from anywhere you do not
fully control.

**One relay, one database** (`allow_client_dsn: false`). The relay holds the only
credentials; game servers cannot choose a target. This is the right shape when
the relay sits on the DB host and every game server should hit the same schema.
Need several databases? Run several instances on different ports — the binary is
a few megabytes and idles at ~10 MB RSS with a handful of sessions.

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
- `encryption: "none"` exists for the single-box case and logs a warning on both
  ends. A plugin configured for `psk` will refuse to talk to it.

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
- `NO_BACKSLASH_ESCAPES` is detected per session and reported to the plugin, so
  `Escape()` stays correct.
