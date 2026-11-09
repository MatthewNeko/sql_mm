package main

// framedConn is the only place that touches the socket. It owns framing and,
// once the handshake has derived keys, transparently encrypts every payload.
//
// Plaintext mode (suiteNone) is a straight pass-through so an operator who
// explicitly disables encryption keeps the v1 behaviour. The plugin refuses to
// run plaintext when it asked for encryption, so the two sides cannot be
// downgraded into disagreeing silently.

import (
	"bufio"
	"errors"
	"net"
)

type framedConn struct {
	conn     net.Conn
	br       *bufio.Reader
	bw       *bufio.Writer
	maxPlain int

	// nil means "this direction is not encrypted yet".
	tx *cipherState
	rx *cipherState
}

func newFramedConn(conn net.Conn, maxPlain int) *framedConn {
	return &framedConn{
		conn:     conn,
		br:       bufio.NewReaderSize(conn, 64*1024),
		bw:       bufio.NewWriterSize(conn, 64*1024),
		maxPlain: maxPlain,
	}
}

// sealTx starts encrypting outgoing frames.
func (f *framedConn) sealTx(c *cipherState) { f.tx = c }

// openRx starts requiring encryption on incoming frames.
func (f *framedConn) openRx(c *cipherState) { f.rx = c }

// encrypted reports whether the channel is up (both directions are always
// enabled together).
func (f *framedConn) encrypted() bool { return f.tx != nil }

func (f *framedConn) Send(payload []byte) error {
	if len(payload) == 0 {
		return errors.New("refusing to send an empty frame")
	}
	if len(payload) > f.maxPlain {
		return errors.New("outgoing frame exceeds max_payload_bytes")
	}
	if f.tx == nil {
		return writeFrame(f.bw, payload)
	}
	sealed, err := f.tx.seal(payload)
	if err != nil {
		return err
	}
	return writeFrame(f.bw, sealed)
}

func (f *framedConn) Recv() ([]byte, error) {
	limit := f.maxPlain
	if f.rx != nil {
		limit += relayMACBytes
	}
	frame, err := readFrame(f.br, limit)
	if err != nil {
		return nil, err
	}
	if f.rx == nil {
		return frame, nil
	}
	plain, err := f.rx.open(frame)
	if err != nil {
		return nil, err
	}
	if len(plain) == 0 {
		return nil, errors.New("empty frame")
	}
	return plain, nil
}

// sendError writes an ERROR frame. During the handshake — before any key is
// installed — this is sent in clear so the operator gets a readable reason;
// once encryption is up it travels inside the channel like everything else.
func (f *framedConn) sendError(reqID uint32, opcode byte, failIndex int, msg string) {
	w := newWriter(msgError)
	writeError(w, reqID, opcode, failIndex, msg)
	_ = f.Send(w.buf)
}

// flush pushes buffered output. Best effort: the socket is usually already
// gone when this matters.
func (f *framedConn) flush() {
	_ = f.bw.Flush()
}
