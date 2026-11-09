# SQLMM relay protocol (v2)

Little-endian everywhere. A frame is a 4-byte payload length followed by the
payload; `payload[0]` is the message type. Lengths are payload-only and never
include the 4-byte header.

Strings are a `u32` byte count followed by exactly that many bytes. They are
never NUL terminated and may contain NULs (SQL text can).

Fixed-point:
- `i32` is written as unsigned and reinterpreted; `-1` means SQL NULL for a cell.

## Encrypted channel

v2 wraps everything after `HELLO_CHALLENGE` in a PSK authenticated channel.
The shared key never crosses the wire: it is only used as HKDF input.

```
suite 0  none            clear text (legacy; only when both sides opt out)
suite 1  chacha20-hmac   ChaCha20 + HMAC-SHA256, encrypt-then-MAC
```

Key schedule, per connection:

```
salt  = clientNonce (32) || serverNonce (32)
PRK   = HMAC-SHA256(salt, psk)                                  (HKDF-Extract)
c2s   = HKDF-Expand(PRK, "sqlmm-relay v2 client->server", 64)
s2c   = HKDF-Expand(PRK, "sqlmm-relay v2 server->client", 64)
key   = c2s[0..32]   macKey = c2s[32..64]   (and the same for s2c)
```

An encrypted frame is:

```
u32 frameLength   (= plaintext length + 32)
ciphertext        (plaintext XOR ChaCha20 keystream)
tag               (32 bytes)
```

- ChaCha20 nonce: `frameSeq` as 8 little-endian bytes followed by four zero
  bytes; the block counter starts at 0 for every frame.
- `tag` is `HMAC-SHA256(macKey, frameSeq (8 LE) || plaintextLen (4 LE) || ciphertext)`.
- `frameSeq` starts at 0 per direction and increments by one per frame. Both
  sides send on their own counter and expect the peer's counter to match
  exactly, so replayed, reordered or truncated frames are rejected.
- The receiver verifies the tag before decrypting. A bad tag is fatal: the
  connection is closed, never resynchronised.

There is no forward secrecy. Anyone who obtains the PSK can decrypt recorded
traffic. Rotate the key if it may have leaked.

## Handshake

Four messages. Only the first two are clear text, and they carry nothing but
versions and nonces.

```
C→S  HELLO            u16 protocolVersion, u8 suite, bytes[32] clientNonce
S→C  HELLO_CHALLENGE  u16 protocolVersion, u8 suite, bytes[32] serverNonce,
                      str relayVersion
C→S  HELLO_FINISH     str clientName                      (encrypted)
S→C  HELLO_OK         u16 protocolVersion, str relayVersion (encrypted)
S→C  ERROR            ...                                  (clear, only before keys exist)
```

Rules:

- A server with `encryption = psk` rejects a client offering `suite 0` with a
  clear text `ERROR`, before deriving anything.
- A client configured for `psk` aborts if `HELLO_CHALLENGE` comes back with
  `suite 0`. Silently continuing in clear text is exactly the downgrade an
  active attacker would attempt, so it is a hard failure.
- `HELLO_FINISH` is the first frame that proves knowledge of the key. A wrong
  PSK fails its tag on the server, and the server drops the connection without
  replying: answering would confirm which half of the guess was wrong.
- The handshake must complete within 15 seconds.

## Session

One connection carries at most one session. `CONNECT` binds it to a physical
MySQL connection which stays with the session until it closes.

```
C→S  CONNECT    str host, u16 port, str user, str pass, str database, u16 timeoutSeconds
S→C  CONNECT_OK u32 sessionId, u32 features, str serverVersion, str database
S→C  ERROR      ...
```

`timeoutSeconds` is the plugin's `MySQLConnectionInfo.timeout`; it overrides the
relay's read/write timeout for this session. `host` beginning with `/` means a
Unix socket path.

Feature flags in `CONNECT_OK`:

| bit | name | meaning |
| --- | --- | --- |
| 0 | `NO_BACKSLASH_ESCAPES` | Session `sql_mode` disables backslash escapes; the plugin must double quotes when escaping. |

## Requests

Both requests are answered by exactly one frame, in order. There is no
pipelining: the plugin serialises operations per connection.

```
C→S  QUERY        u32 requestId, str sql
C→S  TRANSACTION  u32 requestId, u16 statementCount, str sql[statementCount]
C→S  PING
C→S  CLOSE
```

`TRANSACTION` is executed as `BEGIN`, each statement, then `COMMIT`. Callers of
the plugin API depend on one result per statement, positionally, including
statements that return no rows.

## Responses

```
S→C  RESULT  u32 requestId,
             u16 statementCount,
             per statement:
               u64 insertId,
               u64 affectedRows,
               u16 resultSetCount,
               per result set:
                 u16 columnCount,
                 per column: str name, u16 type,
                 u32 rowCount,
                 per row, per column:
                   i32 byteLength        (-1 = NULL)
                   bytes[byteLength]     (omitted when -1)

S→C  ERROR   u32 requestId, u8 requestOpcode, i32 failIndex, str message
S→C  PONG    (no body)
```

`failIndex` is the index inside `TRANSACTION`'s statement list that failed, or
`-1` when the failure was `BEGIN`/`COMMIT`/connection-level. The plugin mirrors
the old `TransactionFailureCallbackFunc(error, failIndex)` contract.

`type` is a MySQL field type number, i.e. the value of `MM_MYSQL_TYPE_*` in
`src/public/mysql_mm.h` (1 = TINY, 3 = LONG, 8 = LONGLONG, 246 = NEWDECIMAL,
252 = BLOB, 253 = VAR_STRING, ...).

## Compatibility rules

- Bump `protocolVersion` for any incompatible change; both sides refuse to talk
  across a mismatch instead of half-working. v2 is not compatible with v1.
- New message types are safe to add; unknown ones close the connection.
- `ERROR` is always attributable: `requestId` matches the request, and
  `requestOpcode` identifies what the server was answering.
- The Go server uses `golang.org/x/crypto/chacha20`; the plugin has its own
  implementation. `tools/crypto_selftest.cpp` and
  `relay-server/crypto_test.go` print the same `CROSS` vectors, which must stay
  byte identical.
