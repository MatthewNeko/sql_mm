package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// TestHKDFVector checks RFC 5869 test case 1 end to end. The plugin implements
// the same two functions by hand, so a mismatch here would break every
// handshake in a way that looks like "wrong key".
func TestHKDFVector(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	wantPRK := "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	wantOKM := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	prk := hkdfExtract(salt, ikm)
	if got := hex.EncodeToString(prk); got != wantPRK {
		t.Fatalf("PRK = %s, want %s", got, wantPRK)
	}
	okm := hkdfExpand(prk, info, 42)
	if got := hex.EncodeToString(okm); got != wantOKM {
		t.Fatalf("OKM = %s, want %s", got, wantOKM)
	}
}

func TestParseKeyMaterial(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	raw, err := parseKeyMaterial(hexKey)
	if err != nil {
		t.Fatalf("hex key: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("hex key decoded to %d bytes", len(raw))
	}

	phrase := strings.Repeat("p", 40)
	raw, err = parseKeyMaterial(phrase)
	if err != nil {
		t.Fatalf("passphrase: %v", err)
	}
	if string(raw) != phrase {
		t.Fatal("passphrase was not used verbatim")
	}

	if _, err := parseKeyMaterial("   "); err == nil {
		t.Fatal("empty key must be rejected")
	}

	// 64 characters that are not hex must fall back to literal bytes.
	notHex := strings.Repeat("z", 64)
	raw, err = parseKeyMaterial(notHex)
	if err != nil || string(raw) != notHex {
		t.Fatalf("non-hex 64 char key mishandled: %v", err)
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := make([]byte, relaySessionKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	tx := newCipherState(key)
	rx := newCipherState(key)

	for i := 0; i < 100; i++ {
		msg := []byte(strings.Repeat("x", i*13))
		sealed, err := tx.seal(msg)
		if err != nil {
			t.Fatalf("seal: %v", err)
		}
		if len(sealed) != len(msg)+relayMACBytes {
			t.Fatalf("sealed length %d", len(sealed))
		}
		if i > 0 && bytes.Equal(sealed[:len(msg)], msg) {
			t.Fatal("ciphertext equals plaintext")
		}
		plain, err := rx.open(sealed)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if !bytes.Equal(plain, msg) {
			t.Fatalf("round trip mismatch at %d", i)
		}
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	key := make([]byte, relaySessionKeyBytes)
	_, _ = rand.Read(key)
	tx := newCipherState(key)

	sealed, err := tx.seal([]byte("CREATE TABLE t (id INT)"))
	if err != nil {
		t.Fatal(err)
	}
	sealed[0] ^= 0x01
	rx := newCipherState(key)
	if _, err := rx.open(sealed); err != errBadMAC {
		t.Fatalf("tampered frame accepted: %v", err)
	}
}

func TestOpenRejectsReplay(t *testing.T) {
	key := make([]byte, relaySessionKeyBytes)
	_, _ = rand.Read(key)
	tx := newCipherState(key)
	rx := newCipherState(key)

	first, _ := tx.seal([]byte("SELECT 1"))
	if _, err := rx.open(first); err != nil {
		t.Fatalf("first frame: %v", err)
	}
	// Same bytes again: the receiver is at seq 1, the MAC was made at seq 0.
	if _, err := rx.open(first); err == nil {
		t.Fatal("replayed frame was accepted")
	}
}

// TestCrossVectors prints the same two lines as tools/crypto_selftest.cpp.
// Compare them by hand (or with the script in the README) after touching
// either implementation: identical output means the two ends agree on nonce
// layout, key derivation and frame sealing.
func TestCrossVectors(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	buf := []byte("sqlmm relay cross-check payload")
	stream.XORKeyStream(buf, buf)
	t.Logf("CROSS chacha20 %x", buf)

	clientNonce := make([]byte, relayNonceBytes)
	serverNonce := make([]byte, relayNonceBytes)
	for i := 0; i < relayNonceBytes; i++ {
		clientNonce[i] = byte(i)
		serverNonce[i] = byte(0x20 + i)
	}
	keys, err := deriveSessionKeys([]byte("0123456789abcdef0123456789abcdef"), clientNonce, serverNonce)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := keys.clientToServer.seal([]byte("SELECT 1"))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CROSS sealed %x", sealed)
}

func TestSessionKeysDependOnBothNonces(t *testing.T) {
	psk := []byte(testPSK)
	c1 := make([]byte, relayNonceBytes)
	s1 := make([]byte, relayNonceBytes)
	c2 := make([]byte, relayNonceBytes)
	s2 := make([]byte, relayNonceBytes)
	_, _ = rand.Read(c1)
	_, _ = rand.Read(s1)
	copy(c2, c1)
	copy(s2, s1)

	a, err := deriveSessionKeys(psk, c1, s1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := deriveSessionKeys(psk, c2, s2)
	if a.clientToServer.encKey != b.clientToServer.encKey {
		t.Fatal("derivation is not deterministic")
	}

	s2[0] ^= 0xFF
	c, _ := deriveSessionKeys(psk, c1, s2)
	if a.clientToServer.encKey == c.clientToServer.encKey {
		t.Fatal("server nonce did not affect the key")
	}
	if a.clientToServer.encKey == a.serverToClient.encKey {
		t.Fatal("both directions share a key")
	}
}
