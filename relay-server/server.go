package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const relayVersion = "2.0.0"

type logLevel int

const (
	lvlError logLevel = iota
	lvlWarn
	lvlInfo
	lvlDebug
)

func parseLevel(s string) logLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error":
		return lvlError
	case "warn", "warning":
		return lvlWarn
	case "debug":
		return lvlDebug
	default:
		return lvlInfo
	}
}

// errRejected marks a handshake that already answered the client with an
// ERROR frame. It is not logged again, so a misconfigured plugin does not
// produce two lines per reconnect.
var errRejected = errors.New("handshake rejected")

// Server accepts plugin connections. Each connection carries at most one MySQL
// session, matching the plugin's one-socket-per-connection design. Multiple
// game servers connect concurrently; each gets its own dedicated MySQL
// connection, never a shared one.
type Server struct {
	cfg    *Config
	level  logLevel
	logger *log.Logger
	active atomic.Int32
	nextID atomic.Uint64
	peers  *PeerFilter

	peerMu       sync.Mutex
	peerSessions map[string]int
}

func NewServer(cfg *Config, logger *log.Logger) (*Server, error) {
	peers, err := NewPeerFilter(cfg.AllowedPeers)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:          cfg,
		level:        parseLevel(cfg.LogLevel),
		logger:       logger,
		peers:        peers,
		peerSessions: make(map[string]int),
	}, nil
}

func (s *Server) tryAcquirePeer(key string) bool {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerSessions[key] >= s.cfg.MaxSessionsPerPeer {
		return false
	}
	s.peerSessions[key]++
	return true
}

func (s *Server) releasePeer(key string) {
	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if n := s.peerSessions[key]; n <= 1 {
		delete(s.peerSessions, key)
	} else {
		s.peerSessions[key] = n - 1
	}
}

func (s *Server) logf(l logLevel, format string, args ...any) {
	if l > s.level {
		return
	}
	s.logger.Printf(format, args...)
}

func (s *Server) encrypted() bool {
	return s.cfg.Encryption == "psk"
}

func describePeers(list []string) string {
	if len(list) == 0 {
		return "any"
	}
	return strings.Join(list, ",")
}

// ListenAndServe binds and blocks. The caller is responsible for closing the
// listener on shutdown.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	return s.Serve(ln)
}

// Serve accepts connections on an existing listener. Split out so tests can
// bind port 0.
func (s *Server) Serve(ln net.Listener) error {
	mode := "encrypted (chacha20 + hmac-sha256, psk)"
	if !s.encrypted() {
		mode = "PLAIN TEXT"
	}
	s.logf(lvlInfo, "relay listening on %s (%s, client dsn %v, max payload %d bytes, max sessions %d, peers %s)",
		ln.Addr(), mode, s.cfg.AllowClientDSN, s.cfg.MaxPayloadBytes, s.cfg.MaxSessions, describePeers(s.cfg.AllowedPeers))
	if !s.encrypted() {
		s.logf(lvlWarn, "encryption is off: tokens, SQL and result sets cross the network in clear text")
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handleConn(conn)
	}
}

// handshake runs HELLO -> CHALLENGE -> FINISH -> OK and installs the session
// keys. It returns the client name the plugin reported.
//
// All four messages carry a version and a suite byte, so a peer that does not
// understand encryption cannot be talked into skipping it: a client that asked
// for "psk" aborts when CHALLENGE comes back with suiteNone, and a server
// configured for "psk" rejects a clear text HELLO before any key is derived.
func (s *Server) handshake(fc *framedConn, remote string) (string, error) {
	payload, err := fc.Recv()
	if err != nil {
		return "", fmt.Errorf("read HELLO: %w", err)
	}
	if payload[0] != msgHello {
		return "", fmt.Errorf("expected HELLO, got 0x%02x", payload[0])
	}

	r := newReader(payload)
	version := r.u16()
	suite := r.u8()
	clientNonce := append([]byte(nil), r.raw(relayNonceBytes)...)
	if r.err != nil || len(clientNonce) != relayNonceBytes {
		return "", errors.New("malformed HELLO")
	}

	if version != protocolVersion {
		s.logf(lvlWarn, "%s: protocol version %d, want %d", remote, version, protocolVersion)
		fc.sendError(0, msgHello, -1, fmt.Sprintf("protocol version mismatch: client %d, server %d", version, protocolVersion))
		return "", errRejected
	}

	required := s.encrypted()
	if required && suite != suiteChaCha20HMAC {
		s.logf(lvlWarn, "%s: client offered suite %d but encryption is mandatory", remote, suite)
		fc.sendError(0, msgHello, -1, "this relay requires an encrypted channel; update the plugin to protocol v2 or set encryption=none")
		return "", errRejected
	}
	actualSuite := suiteNone
	if required {
		actualSuite = suiteChaCha20HMAC
	}

	serverNonce := make([]byte, relayNonceBytes)
	if _, err := rand.Read(serverNonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	challenge := newWriter(msgHelloChallenge).
		u16(protocolVersion).
		u8(actualSuite).
		raw(serverNonce).
		str(relayVersion)
	if err := fc.Send(challenge.buf); err != nil {
		return "", err
	}

	if required {
		keys, err := deriveSessionKeys(s.cfg.sessionKey, clientNonce, serverNonce)
		if err != nil {
			return "", err
		}
		fc.sealTx(keys.serverToClient)
		fc.openRx(keys.clientToServer)
	}

	// HELLO_FINISH is the first frame that proves knowledge of the key: with a
	// wrong PSK its MAC does not verify and Recv fails here.
	finish, err := fc.Recv()
	if err != nil {
		if required && errors.Is(err, errBadMAC) {
			return "", fmt.Errorf("client failed authentication (wrong key)")
		}
		return "", fmt.Errorf("read HELLO_FINISH: %w", err)
	}
	if finish[0] != msgHelloFinish {
		return "", fmt.Errorf("expected HELLO_FINISH, got 0x%02x", finish[0])
	}
	fr := newReader(finish)
	clientName := fr.str()
	if fr.err != nil {
		return "", errors.New("malformed HELLO_FINISH")
	}

	ok := newWriter(msgHelloOK).u16(protocolVersion).str(relayVersion)
	if err := fc.Send(ok.buf); err != nil {
		return "", err
	}
	return clientName, nil
}

func (s *Server) handleConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	defer func() {
		if rec := recover(); rec != nil {
			s.logf(lvlError, "%s: panic: %v", remote, rec)
		}
		conn.Close()
	}()

	peerIP := net.IP(nil)
	if host, _, err := net.SplitHostPort(remote); err == nil {
		peerIP = net.ParseIP(host)
	}
	if !s.peers.Allows(peerIP) {
		s.logf(lvlWarn, "%s: rejected by allowed_peers", remote)
		return
	}
	peerKey := remote
	if peerIP != nil {
		peerKey = peerIP.String()
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}

	// Handshake must complete quickly; otherwise a stray TCP client can pin a
	// goroutine forever.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	fc := newFramedConn(conn, 64*1024)
	clientName, err := s.handshake(fc, remote)
	if err != nil {
		if !errors.Is(err, errRejected) {
			s.logf(lvlWarn, "%s: handshake failed: %v", remote, err)
		}
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	fc.maxPlain = s.cfg.MaxPayloadBytes

	channel := "encrypted"
	if !fc.encrypted() {
		channel = "plain text"
	}
	s.logf(lvlInfo, "%s: client %q connected (%s)", remote, clientName, channel)

	var sess *session
	peerHeld := false
	defer func() {
		if sess != nil {
			sess.Close()
			s.active.Add(-1)
			s.logf(lvlInfo, "%s: session %d closed", remote, sess.id)
		}
		if peerHeld {
			s.releasePeer(peerKey)
		}
	}()

	for {
		payload, err := fc.Recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logf(lvlDebug, "%s: read failed: %v", remote, err)
			}
			return
		}
		if len(payload) == 0 {
			return
		}

		opcode := payload[0]
		r := newReader(payload)

		switch opcode {
		case msgConnect:
			if sess != nil {
				fc.sendError(0, opcode, -1, "session already established on this connection")
				continue
			}
			req := dsnRequest{
				Host:           r.str(),
				Port:           r.u16(),
				User:           r.str(),
				Pass:           r.str(),
				Database:       r.str(),
				TimeoutSeconds: r.u16(),
			}
			if r.err != nil {
				fc.sendError(0, opcode, -1, "malformed CONNECT")
				continue
			}

			if int(s.active.Load()) >= s.cfg.MaxSessions {
				fc.sendError(0, opcode, -1, "relay session limit reached")
				continue
			}

			if err := s.cfg.clientDSNAllowed(req); err != nil {
				s.logf(lvlWarn, "%s: refused DSN: %v", remote, err)
				fc.sendError(0, opcode, -1, errText(err))
				continue
			}

			if !s.tryAcquirePeer(peerKey) {
				fc.sendError(0, opcode, -1, "too many sessions from this address")
				continue
			}

			id := s.nextID.Add(1)
			// The dial itself must be bounded even when the MySQL host black-holes.
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.dialTimeout()+5*time.Second)
			newSess, err := newSession(ctx, s.cfg, id, req)
			cancel()
			if err != nil {
				s.releasePeer(peerKey)
				s.logf(lvlWarn, "%s: connect failed: %v", remote, err)
				fc.sendError(0, opcode, -1, errText(err))
				continue
			}
			peerHeld = true
			sess = newSess
			s.active.Add(1)
			s.logf(lvlInfo, "%s: session %d -> %s/%s", remote, id, req.Host, req.Database)

			connectOK := newWriter(msgConnectOK).
				u32(uint32(id)).
				u32(sess.features).
				str(sess.version).
				str(req.Database)
			if err := fc.Send(connectOK.buf); err != nil {
				return
			}

		case msgQuery:
			reqID := r.u32()
			query := r.str()
			if r.err != nil {
				fc.sendError(reqID, opcode, -1, "malformed QUERY")
				continue
			}
			if sess == nil {
				fc.sendError(reqID, opcode, -1, "no session; send CONNECT first")
				continue
			}
			s.logf(lvlDebug, "session %d query: %s", sess.id, query)
			st, err := sess.run(query)
			if err != nil {
				s.logf(lvlWarn, "session %d query error: %v", sess.id, err)
				fc.sendError(reqID, opcode, -1, errText(err))
				continue
			}
			if err := fc.Send(resultWriter(reqID, []*statement{st}).buf); err != nil {
				return
			}

		case msgTransaction:
			reqID := r.u32()
			count := int(r.u16())
			queries := make([]string, 0, count)
			for i := 0; i < count; i++ {
				queries = append(queries, r.str())
			}
			if r.err != nil {
				fc.sendError(reqID, opcode, -1, "malformed TRANSACTION")
				continue
			}
			if sess == nil {
				fc.sendError(reqID, opcode, -1, "no session; send CONNECT first")
				continue
			}
			s.logf(lvlDebug, "session %d transaction with %d statements", sess.id, count)
			stmts, failIndex, err := sess.runTransaction(queries)
			if err != nil {
				s.logf(lvlWarn, "session %d transaction error at %d: %v", sess.id, failIndex, err)
				fc.sendError(reqID, opcode, failIndex, errText(err))
				continue
			}
			if err := fc.Send(resultWriter(reqID, stmts).buf); err != nil {
				return
			}

		case msgPing:
			if err := fc.Send(newWriter(msgPong).buf); err != nil {
				return
			}

		case msgClose:
			if sess != nil {
				sess.Close()
				s.active.Add(-1)
				s.logf(lvlInfo, "%s: session %d closed by client", remote, sess.id)
				sess = nil
			}
			return

		default:
			s.logf(lvlWarn, "%s: unknown message 0x%02x", remote, opcode)
			return
		}
	}
}

func resultWriter(reqID uint32, stmts []*statement) *writer {
	w := newWriter(msgResult)
	writeResult(w, reqID, stmts)
	return w
}
