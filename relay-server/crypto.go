package main

// Session encryption for the relay protocol.
//
// The plugin used to send its token in clear text and then ran every SQL
// statement over a plain TCP stream: on a public network that leaks both the
// credentials and the data. v2 wraps the whole conversation in a PSK
// authenticated channel: the shared secret never crosses the wire, and both
// directions are encrypted and integrity protected.
//
// Construction. This is deliberately built from primitives that are trivially
// verifiable against their RFC test vectors rather than from a hand written
// AEAD:
//
//	PRK   = HMAC-SHA256(client_nonce || server_nonce, psk)     (HKDF-Extract)
//	c2s   = HKDF-Expand(PRK, "sqlmm-relay v2 client->server", 64)
//	s2c   = HKDF-Expand(PRK, "sqlmm-relay v2 server->client", 64)
//	key   = first 32 bytes, mac_key = last 32 bytes
//	nonce = little-endian frame sequence number, zero padded to 12 bytes
//	frame = ChaCha20(key, nonce, plaintext) || HMAC-SHA256(mac_key, seq||len||ct)
//
// Encrypt-then-MAC with independent keys, monotonic per-direction sequence
// numbers checked on receipt: replaying or reordering a frame fails the MAC
// or the sequence check. There is no forward secrecy (a stolen PSK decrypts
// captured traffic); see README for what that implies.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20"
)

const (
	// suiteNone keeps the old clear-text framing. It exists only so an
	// operator can explicitly opt out on a trusted host; the plugin refuses
	// to fall back to it when it was configured to encrypt.
	suiteNone byte = 0
	// suiteChaCha20HMAC is the only encrypted suite.
	suiteChaCha20HMAC byte = 1

	relayNonceBytes = 32
	relayKeyBytes   = 32
	relayMACBytes   = sha256.Size
	// relaySessionKeyBytes is what HKDF produces per direction.
	relaySessionKeyBytes = relayKeyBytes + relayMACBytes
)

var (
	errEmptyPSK   = errors.New("encryption is enabled but neither psk nor token is set")
	errWeakPSK    = errors.New("relay key is too short: use at least 32 bytes of key material (openssl rand -hex 32)")
	errBadMAC     = errors.New("frame failed authentication (wrong key or tampered stream)")
	errSeqExhaust = errors.New("frame sequence exhausted; reconnect")
)

// parseKeyMaterial turns a configured secret into raw key bytes. A 64 char hex
// string is decoded (that is what "openssl rand -hex 32" prints); anything else
// is used verbatim so plain passphrases keep working.
//
// The plugin implements the exact same rule; if this changes, relay_link.cpp
// must change with it.
func parseKeyMaterial(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errEmptyPSK
	}
	if len(s) == 2*relayKeyBytes {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return []byte(s), nil
}

// hkdfExtract is RFC 5869 section 2.2. A zero-length salt is replaced by
// HashLen zero bytes, which HMAC already does for an empty key.
func hkdfExtract(salt, ikm []byte) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	return m.Sum(nil)
}

// hkdfExpand is RFC 5869 section 2.3.
func hkdfExpand(prk, info []byte, length int) []byte {
	out := make([]byte, 0, length+sha256.Size)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		m := hmac.New(sha256.New, prk)
		m.Write(block)
		m.Write(info)
		m.Write([]byte{counter})
		block = m.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

// sessionKeys holds both directions of one connection.
type sessionKeys struct {
	clientToServer *cipherState
	serverToClient *cipherState
}

// deriveSessionKeys mixes the shared secret with both nonces. Because the
// server nonce is fresh per connection, identical plugin configs still produce
// different keys, so a captured frame cannot be replayed into a new session.
func deriveSessionKeys(psk, clientNonce, serverNonce []byte) (*sessionKeys, error) {
	if len(clientNonce) != relayNonceBytes || len(serverNonce) != relayNonceBytes {
		return nil, fmt.Errorf("nonce must be %d bytes", relayNonceBytes)
	}
	salt := make([]byte, 0, len(clientNonce)+len(serverNonce))
	salt = append(salt, clientNonce...)
	salt = append(salt, serverNonce...)

	prk := hkdfExtract(salt, psk)
	c2s := hkdfExpand(prk, []byte("sqlmm-relay v2 client->server"), relaySessionKeyBytes)
	s2c := hkdfExpand(prk, []byte("sqlmm-relay v2 server->client"), relaySessionKeyBytes)

	return &sessionKeys{
		clientToServer: newCipherState(c2s),
		serverToClient: newCipherState(s2c),
	}, nil
}

// cipherState is one direction of an encrypted connection.
type cipherState struct {
	encKey [relayKeyBytes]byte
	macKey [relayMACBytes]byte
	seq    uint64
}

func newCipherState(material []byte) *cipherState {
	if len(material) != relaySessionKeyBytes {
		panic("cipher material must be 64 bytes")
	}
	c := &cipherState{}
	copy(c.encKey[:], material[:relayKeyBytes])
	copy(c.macKey[:], material[relayKeyBytes:])
	return c
}

func frameNonce(seq uint64) []byte {
	var nonce [chacha20.NonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], seq)
	return nonce[:]
}

func frameMAC(macKey []byte, seq uint64, ciphertext []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	var prefix [12]byte
	binary.LittleEndian.PutUint64(prefix[:8], seq)
	binary.LittleEndian.PutUint32(prefix[8:], uint32(len(ciphertext)))
	m.Write(prefix[:])
	m.Write(ciphertext)
	return m.Sum(nil)
}

// seal returns ciphertext || tag. The caller owns the result.
func (c *cipherState) seal(plaintext []byte) ([]byte, error) {
	if c.seq == ^uint64(0) {
		return nil, errSeqExhaust
	}
	out := make([]byte, len(plaintext)+relayMACBytes)
	stream, err := chacha20.NewUnauthenticatedCipher(c.encKey[:], frameNonce(c.seq))
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(out[:len(plaintext)], plaintext)
	copy(out[len(plaintext):], frameMAC(c.macKey[:], c.seq, out[:len(plaintext)]))
	c.seq++
	return out, nil
}

// open authenticates first and only then decrypts, so a forged frame never
// reaches the SQL parser.
func (c *cipherState) open(frame []byte) ([]byte, error) {
	if len(frame) < relayMACBytes {
		return nil, errBadMAC
	}
	ciphertext := frame[:len(frame)-relayMACBytes]
	tag := frame[len(frame)-relayMACBytes:]

	want := frameMAC(c.macKey[:], c.seq, ciphertext)
	if subtle.ConstantTimeCompare(want, tag) != 1 {
		return nil, errBadMAC
	}
	if c.seq == ^uint64(0) {
		return nil, errSeqExhaust
	}
	out := make([]byte, len(ciphertext))
	stream, err := chacha20.NewUnauthenticatedCipher(c.encKey[:], frameNonce(c.seq))
	if err != nil {
		return nil, err
	}
	stream.XORKeyStream(out, ciphertext)
	c.seq++
	return out, nil
}
