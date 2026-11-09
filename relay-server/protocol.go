// Package main implements the SQLMM relay server.
//
// The server owns every MySQL connection. Game servers (through the SQLMM
// Metamod plugin) speak a small framed binary protocol over loopback TCP and
// never link against libmysqlclient themselves.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// protocolVersion is bumped whenever the wire format changes in an
// incompatible way. The client refuses to talk to a server with a different
// major version.
//
// v2 wraps the session in a PSK encrypted channel (see crypto.go).
const protocolVersion uint16 = 2

// Message types. Client -> server are 0x0*, server -> client are 0x8*.
const (
	msgHello          byte = 0x01
	msgHelloOK        byte = 0x02
	msgConnect        byte = 0x03
	msgConnectOK      byte = 0x04
	msgHelloChallenge byte = 0x05
	msgHelloFinish    byte = 0x06
	msgQuery          byte = 0x10
	msgTransaction    byte = 0x11
	msgPing           byte = 0x12
	msgClose          byte = 0x13
	msgResult         byte = 0x81
	msgError          byte = 0x82
	msgPong           byte = 0x84
)

// Feature flags reported in ConnectOK. Must stay in sync with
// sql_mm/src/relay/relay_protocol.h.
const (
	// flagNoBackslashEscapes is legacy: relays before the sql_mode
	// normalisation used to report it whenever the MySQL server enforced
	// NO_BACKSLASH_ESCAPES, and the plugin switched to '' quoting. Current
	// relays refuse such a session instead (see session.normaliseSQLMode), so
	// this is only ever sent to a client by an older build.
	flagNoBackslashEscapes uint32 = 1 << 0
)

// Protocol type codes. These are the MySQL field type numbers the client
// re-exports as MM_MYSQL_TYPE_*; see relay_protocol.h.
const (
	typeTiny      uint16 = 1
	typeShort     uint16 = 2
	typeLong      uint16 = 3
	typeFloat     uint16 = 4
	typeDouble    uint16 = 5
	typeNull      uint16 = 6
	typeTimestamp uint16 = 7
	typeLongLong  uint16 = 8
	typeInt24     uint16 = 9
	typeDate      uint16 = 10
	typeTime      uint16 = 11
	typeDateTime  uint16 = 12
	typeYear      uint16 = 13
	typeVarchar   uint16 = 15
	typeBit       uint16 = 16
	typeUnknown   uint16 = 20
	typeJSON      uint16 = 245
	typeNewDec    uint16 = 246
	typeEnum      uint16 = 247
	typeSet       uint16 = 248
	typeTinyBlob  uint16 = 249
	typeMedBlob   uint16 = 250
	typeLongBlob  uint16 = 251
	typeBlob      uint16 = 252
	typeVarString uint16 = 253
	typeString    uint16 = 254
	typeGeometry  uint16 = 255
)

var errPayloadTooLarge = errors.New("payload exceeds configured maximum")

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

// writeFrame writes a length-prefixed payload. The 4 byte little-endian
// length counts the payload only.
func writeFrame(w *bufio.Writer, payload []byte) error {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return w.Flush()
}

func readFrame(r *bufio.Reader, maxPayload int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(hdr[:])
	if int(size) > maxPayload {
		return nil, fmt.Errorf("%w: %d > %d", errPayloadTooLarge, size, maxPayload)
	}
	if size == 0 {
		return nil, errors.New("empty frame")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

type writer struct {
	buf []byte
}

func newWriter(msgType byte) *writer {
	return &writer{buf: []byte{msgType}}
}

func (w *writer) u8(v byte) *writer {
	w.buf = append(w.buf, v)
	return w
}

func (w *writer) u16(v uint16) *writer {
	w.buf = binary.LittleEndian.AppendUint16(w.buf, v)
	return w
}

func (w *writer) u32(v uint32) *writer {
	w.buf = binary.LittleEndian.AppendUint32(w.buf, v)
	return w
}

func (w *writer) u64(v uint64) *writer {
	w.buf = binary.LittleEndian.AppendUint64(w.buf, v)
	return w
}

func (w *writer) i32(v int32) *writer {
	return w.u32(uint32(v))
}

// str writes a length-prefixed byte string. Strings are never NUL terminated
// on the wire; the length is authoritative (queries may contain NUL bytes).
func (w *writer) str(s string) *writer {
	w.u32(uint32(len(s)))
	w.buf = append(w.buf, s...)
	return w
}

func (w *writer) bytes(b []byte) *writer {
	w.u32(uint32(len(b)))
	w.buf = append(w.buf, b...)
	return w
}

// raw appends bytes with no length prefix; the caller already wrote the length.
func (w *writer) raw(b []byte) *writer {
	w.buf = append(w.buf, b...)
	return w
}

type reader struct {
	buf []byte
	off int
	err error
}

// newReader skips the leading message type byte; the dispatcher reads it via
// msgType before constructing the reader.
func newReader(payload []byte) *reader {
	if len(payload) == 0 {
		return &reader{err: io.ErrUnexpectedEOF}
	}
	return &reader{buf: payload, off: 1}
}

func (r *reader) fail() {
	if r.err == nil {
		r.err = io.ErrUnexpectedEOF
	}
}

func (r *reader) remaining() int {
	return len(r.buf) - r.off
}

func (r *reader) u8() byte {
	if r.err != nil || r.remaining() < 1 {
		r.fail()
		return 0
	}
	v := r.buf[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if r.err != nil || r.remaining() < 2 {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if r.err != nil || r.remaining() < 4 {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if r.err != nil || r.remaining() < 8 {
		r.fail()
		return 0
	}
	v := binary.LittleEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v
}

func (r *reader) str() string {
	if r.err != nil || r.remaining() < 4 {
		r.fail()
		return ""
	}
	n := int(binary.LittleEndian.Uint32(r.buf[r.off:]))
	r.off += 4
	if n < 0 || r.remaining() < n {
		r.fail()
		return ""
	}
	s := string(r.buf[r.off : r.off+n])
	r.off += n
	return s
}

// raw returns n bytes with no length prefix. Used for handshake nonces, which
// are fixed size.
func (r *reader) raw(n int) []byte {
	if r.err != nil || n < 0 || r.remaining() < n {
		r.fail()
		return nil
	}
	b := r.buf[r.off : r.off+n]
	r.off += n
	return b
}
