package main

import (
	"bufio"
	"crypto/rand"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPSK is 32 bytes so it passes the weak-key check.
var testPSK = strings.Repeat("k3y", 11) + "abc"

func startTestServer(t *testing.T, cfg *Config) (net.Listener, func()) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	logger := log.New(io.Discard, "", 0)
	if testing.Verbose() {
		logger = log.New(testWriter{t}, "", 0)
	}

	srv, err := NewServer(cfg, logger)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	go srv.Serve(ln)

	return ln, func() { ln.Close() }
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}

func testConfig() *Config {
	cfg := defaultConfig()
	cfg.PSK = testPSK
	cfg.Listen = "127.0.0.1:0"
	// Point at a port nothing listens on so CONNECT fails deterministically
	// instead of depending on a local MySQL install.
	cfg.Fallback = DSN{Host: "127.0.0.1", Port: 1, User: "x", Pass: "y", Database: "z"}
	cfg.AllowClientDSN = false
	cfg.DialTimeoutSeconds = 2
	cfg.MaxSessionsPerPeer = 8
	if err := cfg.finalize(); err != nil {
		panic(err)
	}
	return cfg
}

func plaintextConfig() *Config {
	cfg := testConfig()
	cfg.Encryption = "none"
	cfg.sessionKey = nil
	return cfg
}

type testClient struct {
	conn net.Conn
	fc   *framedConn
	name string
}

func dialTestClient(t *testing.T, ln net.Listener) *testClient {
	t.Helper()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return &testClient{conn: conn, fc: newFramedConn(conn, 1<<20), name: "test"}
}

func (c *testClient) send(w *writer) error {
	return c.fc.Send(w.buf)
}

func (c *testClient) recv() (byte, *reader, error) {
	payload, err := c.fc.Recv()
	if err != nil {
		return 0, nil, err
	}
	return payload[0], newReader(payload), nil
}

// handshake runs the client half of the v2 handshake. suite selects what the
// client claims to support; psk is the key it derives with (empty for clear
// text).
func (c *testClient) handshake(psk string, suite byte) (byte, *reader, error) {
	clientNonce := make([]byte, relayNonceBytes)
	if _, err := rand.Read(clientNonce); err != nil {
		return 0, nil, err
	}

	hello := newWriter(msgHello).u16(protocolVersion).u8(suite).raw(clientNonce)
	if err := c.send(hello); err != nil {
		return 0, nil, err
	}

	typ, r, err := c.recv()
	if err != nil {
		return 0, nil, err
	}
	if typ != msgHelloChallenge {
		return typ, r, nil
	}

	version := r.u16()
	gotSuite := r.u8()
	serverNonce := append([]byte(nil), r.raw(relayNonceBytes)...)
	_ = r.str()
	if r.err != nil {
		return typ, r, r.err
	}
	if version != protocolVersion {
		return typ, r, nil
	}
	if gotSuite != suite {
		// The server downgraded (or refused) encryption; report it and stop.
		return typ, r, nil
	}

	if suite == suiteChaCha20HMAC {
		keys, err := deriveSessionKeys([]byte(psk), clientNonce, serverNonce)
		if err != nil {
			return typ, r, err
		}
		c.fc.sealTx(keys.clientToServer)
		c.fc.openRx(keys.serverToClient)
	}

	if err := c.send(newWriter(msgHelloFinish).str(c.name)); err != nil {
		return 0, nil, err
	}
	return c.recv()
}

func TestHandshakeRejectsBadKey(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	// The server cannot tell the key is wrong until HELLO_FINISH, and it will
	// not answer with an ERROR (that would confirm the guess was wrong). It
	// just drops the connection.
	if _, _, err := c.handshake(strings.Repeat("x", 32), suiteChaCha20HMAC); err == nil {
		t.Fatal("expected the handshake to fail with a wrong key")
	}
}

func TestHandshakeAcceptsGoodKey(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	typ, r, err := c.handshake(testPSK, suiteChaCha20HMAC)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if typ != msgHelloOK {
		t.Fatalf("expected msgHelloOK, got 0x%02x", typ)
	}
	if v := r.u16(); v != protocolVersion {
		t.Fatalf("protocol version %d", v)
	}
	if ver := r.str(); ver == "" {
		t.Fatal("empty relay version")
	}
}

// TestPlaintextModeStillWorks covers the explicit opt-out. The server must
// complete the same four message handshake, just without installing keys.
func TestPlaintextModeStillWorks(t *testing.T) {
	ln, done := startTestServer(t, plaintextConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	if typ, _, err := c.handshake("", suiteNone); err != nil || typ != msgHelloOK {
		t.Fatalf("plain handshake failed: type=0x%02x err=%v", typ, err)
	}
	if err := c.send(newWriter(msgPing)); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	if typ, _, err := c.recv(); err != nil || typ != msgPong {
		t.Fatalf("expected pong, got 0x%02x err=%v", typ, err)
	}
}

func TestServerRejectsPlaintextWhenEncryptionRequired(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	typ, r, err := c.handshake("", suiteNone)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if typ != msgError {
		t.Fatalf("expected msgError, got 0x%02x", typ)
	}
	_ = r.u32()
	_ = r.u8()
	_ = r.u32()
	if msg := r.str(); !strings.Contains(msg, "encrypted") {
		t.Fatalf("unexpected error message %q", msg)
	}
}

func TestConnectFailureIsReported(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	if typ, _, err := c.handshake(testPSK, suiteChaCha20HMAC); err != nil || typ != msgHelloOK {
		t.Fatalf("handshake failed: type=0x%02x err=%v", typ, err)
	}

	// Client DSN is ignored (allow_client_dsn=false) and the fallback port is
	// dead, so this must fail with a clear error rather than hanging.
	connect := newWriter(msgConnect).str("ignored").u16(3306).str("u").str("p").str("d").u16(5)
	if err := c.send(connect); err != nil {
		t.Fatalf("send connect: %v", err)
	}

	typ, r, err := c.recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if typ != msgError {
		t.Fatalf("expected msgError, got 0x%02x", typ)
	}
	_ = r.u32()
	_ = r.u8()
	_ = r.u32()
	if msg := r.str(); msg == "" {
		t.Fatal("connect error carried no message")
	}
}

func TestQueryWithoutSession(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()

	if typ, _, err := c.handshake(testPSK, suiteChaCha20HMAC); err != nil || typ != msgHelloOK {
		t.Fatalf("handshake failed: type=0x%02x err=%v", typ, err)
	}

	if err := c.send(newWriter(msgQuery).u32(7).str("SELECT 1")); err != nil {
		t.Fatalf("send query: %v", err)
	}
	typ, r, err := c.recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if typ != msgError {
		t.Fatalf("expected msgError, got 0x%02x", typ)
	}
	if id := r.u32(); id != 7 {
		t.Fatalf("request id echoed as %d, want 7", id)
	}
}

func TestPingPong(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	c := dialTestClient(t, ln)
	defer c.conn.Close()
	if typ, _, err := c.handshake(testPSK, suiteChaCha20HMAC); err != nil || typ != msgHelloOK {
		t.Fatalf("handshake failed: type=0x%02x err=%v", typ, err)
	}

	if err := c.send(newWriter(msgPing)); err != nil {
		t.Fatalf("send ping: %v", err)
	}
	if typ, _, err := c.recv(); err != nil || typ != msgPong {
		t.Fatalf("expected pong, got 0x%02x err=%v", typ, err)
	}
}

func TestProtocolVersionMismatch(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(raw)
	bw := bufio.NewWriter(raw)

	nonce := make([]byte, relayNonceBytes)
	if err := writeFrame(bw, newWriter(msgHello).u16(protocolVersion+1).u8(suiteChaCha20HMAC).raw(nonce).buf); err != nil {
		t.Fatalf("send: %v", err)
	}
	payload, err := readFrame(br, 1<<20)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	if payload[0] != msgError {
		t.Fatalf("expected msgError, got 0x%02x", payload[0])
	}
}

// TestConcurrentClients covers the multi-game-server case: several plugins
// connecting at once must each get their own handshake and key.
func TestConcurrentClients(t *testing.T) {
	ln, done := startTestServer(t, testConfig())
	defer done()

	const clients = 8
	var wg sync.WaitGroup
	errs := make(chan error, clients)

	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

			c := &testClient{conn: conn, fc: newFramedConn(conn, 1<<20), name: "test"}
			typ, _, err := c.handshake(testPSK, suiteChaCha20HMAC)
			if err != nil {
				errs <- err
				return
			}
			if typ != msgHelloOK {
				errs <- io.ErrUnexpectedEOF
			}
		}()
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent client failed: %v", err)
	}
}

func TestPeerFilter(t *testing.T) {
	f, err := NewPeerFilter([]string{"10.0.0.0/8", "192.168.1.5"})
	if err != nil {
		t.Fatalf("filter: %v", err)
	}
	if !f.Allows(net.ParseIP("10.1.2.3")) {
		t.Fatal("10.1.2.3 should be allowed")
	}
	if !f.Allows(net.ParseIP("192.168.1.5")) {
		t.Fatal("192.168.1.5 should be allowed")
	}
	if f.Allows(net.ParseIP("8.8.8.8")) {
		t.Fatal("8.8.8.8 should be rejected")
	}
	if !(&PeerFilter{}).Allows(net.ParseIP("8.8.8.8")) {
		t.Fatal("empty filter should allow everything")
	}
}

func TestFirstKeyword(t *testing.T) {
	cases := map[string]string{
		"SELECT 1":                      "SELECT",
		"  /* hi */ select * from t":    "SELECT",
		"-- note\nINSERT INTO t VALUES": "INSERT",
		"# note\nUPDATE t SET a=1":      "UPDATE",
		"":                              "",
		"   ":                           "",
	}
	for in, want := range cases {
		if got := firstKeyword(in); got != want {
			t.Fatalf("firstKeyword(%q) = %q, want %q", in, got, want)
		}
	}
}
