package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

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
	// Leave it true when each game server owns its own database, false when the
	// relay is shared and its credentials should be the only way in.
	AllowClientDSN bool `json:"allow_client_dsn"`

	// AllowedClientHosts / AllowedClientDatabases constrain what a client may
	// ask for when AllowClientDSN is true. Empty lists mean "anything", which
	// on an internet-facing relay is an SSRF hole: any client holding the token
	// could point the relay at an arbitrary MySQL host. Fill them in.
	AllowedClientHosts     []string `json:"allowed_client_hosts"`
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
		Listen:               "127.0.0.1:9330",
		Encryption:           "psk",
		Token:                "",
		LogLevel:             "info",
		MaxPayloadBytes:      64 * 1024 * 1024,
		AllowClientDSN:       true,
		Fallback:             DSN{Host: "127.0.0.1", Port: 3306},
		DialTimeoutSeconds:   10,
		ReadTimeoutSeconds:   60,
		WriteTimeoutSeconds:  60,
		QueryTimeoutSeconds:  0,
		MaxSessions:          64,
		MaxSessionsPerPeer:   16,
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
		cfg.MaxPayloadBytes = defaultConfig().MaxPayloadBytes
	}
	if cfg.DialTimeoutSeconds <= 0 {
		cfg.DialTimeoutSeconds = 10
	}
	if cfg.ReadTimeoutSeconds <= 0 {
		cfg.ReadTimeoutSeconds = 60
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
	default:
		return fmt.Errorf("encryption: unknown mode %q (use \"psk\" or \"none\")", cfg.Encryption)
	}
	return nil
}

func (c *Config) dialTimeout() time.Duration {
	return time.Duration(c.DialTimeoutSeconds) * time.Second
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

// clientDSNAllowed validates a plugin-supplied DSN against the allowlists.
func (c *Config) clientDSNAllowed(req dsnRequest) error {
	if !c.AllowClientDSN {
		return nil
	}
	if len(c.AllowedClientHosts) > 0 {
		ok := false
		for _, host := range c.AllowedClientHosts {
			if strings.EqualFold(strings.TrimSpace(host), req.Host) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("client requested an unlisted host %q", req.Host)
		}
	}
	if len(c.AllowedClientDatabases) > 0 {
		ok := false
		for _, db := range c.AllowedClientDatabases {
			if strings.EqualFold(strings.TrimSpace(db), req.Database) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("client requested an unlisted database %q", req.Database)
		}
	}
	return nil
}
