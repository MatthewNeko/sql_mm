package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// maxPayloadCeiling is the hard limit for max_payload_bytes. Every concurrently
// connected session can be holding one payload in flight, so the configured
// value multiplies by max_sessions: 16 MiB x 64 sessions is already 1 GiB of
// peak transient memory.
const maxPayloadCeiling = 256 << 20

// minReadTimeout is the floor applied to the MySQL socket read timeout. A zero
// (or absurdly small) value lets a single stalled query pin a session, its
// worker goroutine and its MySQL connection forever.
const minReadTimeout = 120 * time.Second

// defaultMaxPayload is deliberately smaller than the old 64 MiB: relay frames
// are fully buffered on both sides, and a result set that big is a bug on the
// caller's side rather than something to support.
const defaultMaxPayload = 16 << 20

// DSN describes where MySQL actually lives. It is only read from the server
// config; the plugin never sees it unless centralised credentials are off.
type DSN struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Pass     string `json:"pass"`
	Database string `json:"database"`
}

// Config is the on-disk configuration of the relay.
type Config struct {
	// Listen is the loopback address the relay binds to. Do not expose it
	// publicly: the token is the only barrier between the port and your DB.
	Listen string `json:"listen"`

	// Encryption selects the channel mode:
	//
	//	"psk"  (default) every frame after the handshake is ChaCha20 encrypted
	//	       and HMAC authenticated with a pre-shared key.
	//	"none" legacy clear text; only for a relay bound to loopback on a
	//	       host you fully trust.
	//
	// The plugin's own relay_encryption setting must match, and a plugin
	// configured for "psk" refuses a server that answers in clear text.
	Encryption string `json:"encryption"`

	// PSK is the shared secret used by the encrypted channel. A 64 character
	// hex string is decoded (openssl rand -hex 32); anything else is used
	// verbatim, so a passphrase works as long as it is at least 32 bytes.
	//
	// When empty, Token is used instead, which keeps existing single-secret
	// deployments working. The value never travels over the wire.
	PSK string `json:"psk"`

	// Token is the legacy shared secret. With encryption "psk" it doubles as
	// the key when PSK is empty; with encryption "none" it is no longer used
	// for anything and may be left empty.
	Token string `json:"token"`

	// LogLevel is one of error, warn, info, debug.
	LogLevel string `json:"log_level"`

	// MaxPayloadBytes caps a single request/response frame. A result set
	// larger than this is rejected instead of being buffered.
	MaxPayloadBytes int `json:"max_payload_bytes"`

	// AllowClientDSN controls whether the address/user/pass/database the
	// plugin passes to CreateMySQLConnection are honoured. When false, every
	// session uses Fallback.
	//
	// Defaults to false. Turning it on lets anyone holding the PSK point the
	// relay at a host of their choosing, which is an SSRF primitive unless
	// AllowedClientHosts is filled in and the peer list is tight. Leave it off
	// when the relay is shared.
	AllowClientDSN bool `json:"allow_client_dsn"`

	// AllowedClientHosts is mandatory when AllowClientDSN is true: with an
	// empty list every client-supplied host is refused and clients must send
	// an empty host to use Fallback.
	//
	// A single "*" entry disables the check instead — explicit, because letting
	// clients pick any host the relay can reach is a decision worth writing
	// down. Entries may be IP literals, hostnames or Unix socket paths.
	// Hostnames are resolved at startup; matching is done on IPs and the relay
	// dials the IP that matched, so a DNS answer cannot change between the
	// check and the connection.
	AllowedClientHosts []string `json:"allowed_client_hosts"`

	// AllowedClientDatabases constrains the database name a client may select.
	// An empty list accepts any database on the allowed host; that is only
	// reasonable when the relay's MySQL account itself is scoped to one schema.
	AllowedClientDatabases []string `json:"allowed_client_databases"`

	// AllowedPeers is a list of CIDRs permitted to connect at all. Empty means
	// any address. Use it to pin the relay to your game servers' network.
	AllowedPeers []string `json:"allowed_peers"`

	// Fallback is used when AllowClientDSN is false, or when the plugin
	// passes an empty host.
	Fallback DSN `json:"fallback"`

	DialTimeoutSeconds  int `json:"dial_timeout_seconds"`
	ReadTimeoutSeconds  int `json:"read_timeout_seconds"`
	WriteTimeoutSeconds int `json:"write_timeout_seconds"`

	// QueryTimeoutSeconds, when > 0, aborts a single statement that runs
	// longer than this. Note that cancelling a statement makes the driver
	// drop the underlying MySQL connection, which also drops session state
	// (LAST_INSERT_ID, temp tables). 0 keeps the legacy behaviour where the
	// statement simply blocks its session.
	QueryTimeoutSeconds int `json:"query_timeout_seconds"`

	// MaxSessions caps the number of concurrently connected game-server
	// sessions. Each one holds a dedicated MySQL connection, so keep it below
	// MySQL's max_connections divided by the number of relay instances.
	MaxSessions int `json:"max_sessions"`

	// MaxSessionsPerPeer caps sessions from a single source address. One game
	// server normally needs one.
	MaxSessionsPerPeer int `json:"max_sessions_per_peer"`

	// sessionKey is the parsed PSK. Never serialised.
	sessionKey []byte
}

func defaultConfig() *Config {
	return &Config{
		Listen:             "127.0.0.1:9330",
		Encryption:         "psk",
		Token:              "",
		LogLevel:           "info",
		MaxPayloadBytes:    defaultMaxPayload,
		AllowClientDSN:     false,
		Fallback:           DSN{Host: "127.0.0.1", Port: 3306},
		DialTimeoutSeconds: 10,
		// The floor below is re-applied on load; 120s is long enough for a
		// schema migration and short enough that a dead MySQL does not pin
		// every session forever.
		ReadTimeoutSeconds:  120,
		WriteTimeoutSeconds: 60,
		QueryTimeoutSeconds: 0,
		MaxSessions:         64,
		MaxSessionsPerPeer:  16,
	}
}

// LoadConfig reads path, falling back to defaults for absent keys.
func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}

	if cfg.Listen == "" {
		cfg.Listen = defaultConfig().Listen
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = defaultMaxPayload
	}
	if cfg.DialTimeoutSeconds <= 0 {
		cfg.DialTimeoutSeconds = 10
	}
	if cfg.ReadTimeoutSeconds <= 0 {
		cfg.ReadTimeoutSeconds = int(minReadTimeout / time.Second)
	}
	if cfg.WriteTimeoutSeconds <= 0 {
		cfg.WriteTimeoutSeconds = 60
	}
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	if cfg.MaxSessionsPerPeer <= 0 {
		// Several srcds instances usually share one host/IP; 16 is generous
		// enough for that while still catching a reconnect loop.
		cfg.MaxSessionsPerPeer = 16
	}
	if cfg.Fallback.Port == 0 {
		cfg.Fallback.Port = 3306
	}

	if err := cfg.finalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// finalize normalises and validates everything that depends on several keys at
// once. Kept separate from LoadConfig so tests (and future callers that build a
// Config by hand) get the same checks.
func (cfg *Config) finalize() error {
	// Frames are fully buffered on both sides, so the configured payload size
	// multiplies by the number of live sessions.
	if cfg.MaxPayloadBytes > maxPayloadCeiling {
		return fmt.Errorf("max_payload_bytes %d exceeds the %d byte ceiling (each session buffers one frame)",
			cfg.MaxPayloadBytes, maxPayloadCeiling)
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Encryption)) {
	case "", "psk":
		cfg.Encryption = "psk"
		source := cfg.PSK
		if strings.TrimSpace(source) == "" {
			source = cfg.Token
		}
		key, err := parseKeyMaterial(source)
		if err != nil {
			return fmt.Errorf("encryption=psk: %w", err)
		}
		if len(key) < relayKeyBytes {
			return fmt.Errorf("encryption=psk: %w", errWeakPSK)
		}
		cfg.sessionKey = key
	case "none":
		cfg.Encryption = "none"
		cfg.sessionKey = nil
		// An unauthenticated SQL proxy on a public interface is not a
		// misconfiguration worth tolerating: anyone who can reach the port can
		// run queries as the relay's MySQL user.
		if err := cfg.checkPlaintextListen(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("encryption: unknown mode %q (use \"psk\" or \"none\")", cfg.Encryption)
	}
	return nil
}

// checkPlaintextListen refuses encryption=none unless the relay only accepts
// loopback connections. Re-run it after the listen address is overridden on
// the command line.
func (cfg *Config) checkPlaintextListen() error {
	if cfg.Encryption != "none" {
		return nil
	}
	if isLoopbackListen(cfg.Listen) {
		return nil
	}
	return fmt.Errorf("encryption=none is only allowed on a loopback listen address (got %q); "+
		"use encryption=psk for anything reachable from the network", cfg.Listen)
}

func isLoopbackListen(addr string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Config) dialTimeout() time.Duration {
	return time.Duration(c.DialTimeoutSeconds) * time.Second
}

// connLimit bounds the number of TCP connections the process will hold at once,
// handshakes included. It is deliberately larger than MaxSessions so a game
// server that reconnects before the old socket is reaped is not refused.
func (c *Config) connLimit() int {
	return c.MaxSessions*2 + 16
}

// redact removes internal addresses from text that is about to be logged or
// returned to a client. Non-empty secrets shorter than 4 bytes are skipped so a
// port number cannot shred unrelated digits.
func redact(text string, secrets ...string) string {
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if len(secret) < 4 {
			continue
		}
		text = strings.ReplaceAll(text, secret, "[mysql]")
	}
	return text
}

func (c *Config) queryTimeout() time.Duration {
	if c.QueryTimeoutSeconds <= 0 {
		return 0
	}
	return time.Duration(c.QueryTimeoutSeconds) * time.Second
}

// PeerFilter implements AllowedPeers. A zero-value filter allows everything.
type PeerFilter struct {
	nets []*net.IPNet
}

func NewPeerFilter(cidrs []string) (*PeerFilter, error) {
	f := &PeerFilter{}
	for _, entry := range cidrs {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		if !strings.Contains(trimmed, "/") {
			// Bare address: treat as a single-host network.
			if ip := net.ParseIP(trimmed); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				f.nets = append(f.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			return nil, fmt.Errorf("allowed_peers: %q is not an IP or CIDR", entry)
		}
		_, block, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("allowed_peers: %w", err)
		}
		f.nets = append(f.nets, block)
	}
	return f, nil
}

func (f *PeerFilter) Allows(ip net.IP) bool {
	if f == nil || len(f.nets) == 0 {
		return true
	}
	for _, block := range f.nets {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// clientDSNAllowed validates the database half of a plugin-supplied DSN. The
// host half is handled by ClientHostFilter, which also returns the address the
// relay must dial (see Canonical).
func (c *Config) clientDSNAllowed(req dsnRequest) error {
	if !c.AllowClientDSN {
		return nil
	}
	if len(c.AllowedClientDatabases) == 0 {
		return nil
	}
	for _, db := range c.AllowedClientDatabases {
		if strings.EqualFold(strings.TrimSpace(db), req.Database) {
			return nil
		}
	}
	return fmt.Errorf("client requested an unlisted database %q", req.Database)
}

// clientHostEntry is one allowed_client_hosts entry after normalisation. text
// keeps the configured spelling (needed for Unix socket paths and for names
// that cannot be resolved at startup); ip is set for every address the entry
// stands for.
type clientHostEntry struct {
	text string
	ip   net.IP
	unix bool
}

// ClientHostFilter validates and canonicalises the host a plugin asks the relay
// to dial.
//
// The comparison is done on addresses, not on strings: "localhost" and
// "127.0.0.1" denote the same host, and a name that resolves into the allowlist
// must not become a way to make the relay dial something else. The address that
// matched is what gets dialled, so a DNS answer cannot be swapped between the
// check and the connection.
type ClientHostFilter struct {
	entries []clientHostEntry
	// closed means no allowlist was configured. Every client-supplied host is
	// then refused; the client must pass an empty host to use Fallback.
	closed bool
	// any is set by an explicit "*" entry: every host is allowed. Spelled out
	// rather than implied by an empty list, because turning the check off is a
	// decision that should be visible in the config file.
	any bool
}

// NewClientHostFilter resolves the configured entries once at startup.
func NewClientHostFilter(entries []string) *ClientHostFilter {
	f := &ClientHostFilter{closed: len(entries) == 0}
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if entry == "*" {
			f.any = true
			continue
		}
		if strings.HasPrefix(entry, "/") {
			// Unix socket path.
			f.entries = append(f.entries, clientHostEntry{text: entry, unix: true})
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			f.entries = append(f.entries, clientHostEntry{text: entry, ip: ip})
			continue
		}
		ips, err := lookupIPs(entry)
		if err != nil || len(ips) == 0 {
			// Keep it as an exact-match name; Canonical falls back to string
			// comparison when the client's host cannot be resolved either.
			f.entries = append(f.entries, clientHostEntry{text: strings.ToLower(entry)})
			continue
		}
		for _, ip := range ips {
			f.entries = append(f.entries, clientHostEntry{text: strings.ToLower(entry), ip: ip})
		}
	}
	return f
}

// Canonical returns the address the relay should dial for a client-supplied
// host, or an error when that host is not on the allowlist.
func (f *ClientHostFilter) Canonical(host string) (string, error) {
	if host == "" {
		return "", errors.New("empty host")
	}
	if f == nil || f.closed {
		return "", errors.New("this relay does not accept client supplied hosts; " +
			"send an empty host to use the relay's own database")
	}
	if f.any {
		// Nothing to pin the check to, so dial the name as given. The database
		// allowlist and the MySQL account's own grants are the only limits
		// left; the relay logs a warning at startup.
		return host, nil
	}
	if strings.HasPrefix(host, "/") {
		for _, e := range f.entries {
			if e.unix && e.text == host {
				return host, nil
			}
		}
		return "", fmt.Errorf("client requested an unlisted socket %q", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		for _, e := range f.entries {
			if e.ip != nil && e.ip.Equal(ip) {
				return ip.String(), nil
			}
		}
		return "", fmt.Errorf("client requested an unlisted host %q", host)
	}
	// A name: resolve it, then match the answers against the allowlist. The
	// matched address is dialled, not the name, so a second lookup cannot
	// point somewhere else.
	ips, err := lookupIPs(host)
	if err == nil {
		for _, ip := range ips {
			for _, e := range f.entries {
				if e.ip != nil && e.ip.Equal(ip) {
					return ip.String(), nil
				}
			}
		}
	}
	for _, e := range f.entries {
		if e.text == strings.ToLower(host) {
			return host, nil
		}
	}
	return "", fmt.Errorf("client requested an unlisted host %q", host)
}

func lookupIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// connectErrText renders a dial/login failure for the plugin. The reason is
// useful ("access denied", "unknown database") but the message must not carry
// the internal MySQL address, because the plugin log is usually less protected
// than this process.
func (c *Config) connectErrText(err error, req dsnRequest, dialHost string) string {
	if err == nil {
		return ""
	}
	secrets := []string{c.Fallback.Host, fmt.Sprintf("%s:%d", c.Fallback.Host, c.Fallback.Port)}
	if dialHost != "" {
		secrets = append(secrets, dialHost, net.JoinHostPort(dialHost, fmt.Sprintf("%d", req.Port)))
	}
	if req.Host != "" {
		secrets = append(secrets, req.Host)
	}
	return truncateForLog(redact(fmt.Sprintf("%v", err), secrets...), 400)
}
