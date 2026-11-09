package main

import (
	"strings"
	"testing"
)

// A clear-text relay on a public interface is an unauthenticated SQL proxy;
// startup must refuse it.
func TestPlaintextRefusedOffLoopback(t *testing.T) {
	cfg := testConfig()
	cfg.Encryption = "none"
	cfg.Listen = "0.0.0.0:9330"
	if err := cfg.finalize(); err == nil {
		t.Fatal("expected encryption=none on 0.0.0.0 to be refused")
	}

	for _, addr := range []string{"127.0.0.1:9330", "[::1]:9330", "localhost:9330"} {
		cfg := testConfig()
		cfg.Encryption = "none"
		cfg.Listen = addr
		if err := cfg.finalize(); err != nil {
			t.Fatalf("loopback listen %q should be accepted: %v", addr, err)
		}
	}
}

// checkPlaintextListen is re-run by main after -listen overrides the config.
func TestPlaintextListenOverride(t *testing.T) {
	cfg := testConfig()
	cfg.Encryption = "none"
	if err := cfg.finalize(); err != nil {
		t.Fatalf("loopback config should load: %v", err)
	}
	cfg.Listen = "0.0.0.0:9330"
	if err := cfg.checkPlaintextListen(); err == nil {
		t.Fatal("-listen 0.0.0.0 must be rejected when encryption=none")
	}
}

func TestMaxPayloadCeiling(t *testing.T) {
	cfg := defaultConfig()
	cfg.PSK = testPSK
	cfg.MaxPayloadBytes = maxPayloadCeiling + 1
	if err := cfg.finalize(); err == nil {
		t.Fatal("expected an oversized max_payload_bytes to be rejected")
	}
}

func TestClientHostFilterIPs(t *testing.T) {
	f := NewClientHostFilter([]string{"127.0.0.1", "10.0.0.0/8 is not a CIDR entry"})
	if f.closed {
		t.Fatal("filter should be open with entries configured")
	}

	got, err := f.Canonical("127.0.0.1")
	if err != nil || got != "127.0.0.1" {
		t.Fatalf("literal IP: got %q, %v", got, err)
	}

	// A name that resolves to an allowlisted address must be dialled as that
	// address: the validated IP is what gets connected to, not the name.
	got, err = f.Canonical("localhost")
	if err != nil {
		t.Fatalf("localhost should resolve into the allowlist: %v", err)
	}
	if got != "127.0.0.1" {
		t.Fatalf("localhost should canonicalise to 127.0.0.1, got %q", got)
	}

	if _, err := f.Canonical("192.0.2.7"); err == nil {
		t.Fatal("unlisted address must be refused")
	}
	if _, err := f.Canonical(""); err == nil {
		t.Fatal("empty host must be refused so callers fall back explicitly")
	}
}

// The shipped example must stay loadable and keep the documented shape: no
// source-address allowlist, no host restriction, database names filtered.
func TestExampleConfigLoads(t *testing.T) {
	cfg, err := LoadConfig("config.example.json")
	if err != nil {
		t.Fatalf("config.example.json does not load: %v", err)
	}
	if !cfg.AllowClientDSN {
		t.Fatal("example should let clients name the target")
	}
	if !NewClientHostFilter(cfg.AllowedClientHosts).any {
		t.Fatalf("example should not pin hosts, got %v", cfg.AllowedClientHosts)
	}
	if len(cfg.AllowedClientDatabases) == 0 {
		t.Fatal("example should restrict database names")
	}
	if len(cfg.AllowedPeers) != 0 {
		t.Fatalf("example should not ship a source-address allowlist, got %v", cfg.AllowedPeers)
	}
}

func TestClientHostFilterWildcard(t *testing.T) {
	f := NewClientHostFilter([]string{"*"})
	if f.closed {
		t.Fatal("a wildcard entry means the host check is off, not closed")
	}
	if !f.any {
		t.Fatal("wildcard should set any")
	}
	for _, host := range []string{"127.0.0.1", "192.0.2.7", "db.internal", "::1"} {
		got, err := f.Canonical(host)
		if err != nil || got != host {
			t.Fatalf("wildcard should pass %q through, got %q, %v", host, got, err)
		}
	}
	if _, err := f.Canonical(""); err == nil {
		t.Fatal("empty host is still an error: it is not a host someone asked for")
	}
	// A wildcard mixed with real entries still means "anything".
	mixed := NewClientHostFilter([]string{"127.0.0.1", "*"})
	if _, err := mixed.Canonical("198.51.100.9"); err != nil {
		t.Fatalf("mixed list with a wildcard should allow anything: %v", err)
	}
}

func TestClientHostFilterClosedByEmptyList(t *testing.T) {
	f := NewClientHostFilter(nil)
	if _, err := f.Canonical("127.0.0.1"); err == nil {
		t.Fatal("empty allowlist must refuse every client supplied host")
	}
	// A nil receiver (AllowClientDSN off) behaves the same, defensively.
	var nilFilter *ClientHostFilter
	if _, err := nilFilter.Canonical("127.0.0.1"); err == nil {
		t.Fatal("nil filter must refuse client supplied hosts")
	}
}

func TestClientHostFilterUnixSocket(t *testing.T) {
	f := NewClientHostFilter([]string{"/run/mysqld/mysqld.sock"})
	got, err := f.Canonical("/run/mysqld/mysqld.sock")
	if err != nil || got != "/run/mysqld/mysqld.sock" {
		t.Fatalf("unix socket: got %q, %v", got, err)
	}
	if _, err := f.Canonical("/tmp/other.sock"); err == nil {
		t.Fatal("unlisted socket must be refused")
	}
}

func TestRemoveSQLMode(t *testing.T) {
	got, changed := removeSQLMode("STRICT_TRANS_TABLES,NO_BACKSLASH_ESCAPES,ANSI_QUOTES", "NO_BACKSLASH_ESCAPES")
	if !changed || got != "STRICT_TRANS_TABLES,ANSI_QUOTES" {
		t.Fatalf("got %q (changed=%v)", got, changed)
	}
	got, changed = removeSQLMode("no_backslash_escapes", "NO_BACKSLASH_ESCAPES")
	if !changed || got != "" {
		t.Fatalf("single element: got %q (changed=%v)", got, changed)
	}
	got, changed = removeSQLMode("STRICT_TRANS_TABLES", "NO_BACKSLASH_ESCAPES")
	if changed || got != "STRICT_TRANS_TABLES" {
		t.Fatalf("untouched mode: got %q (changed=%v)", got, changed)
	}
}

func TestSQLModeListValidation(t *testing.T) {
	if !isSQLModeList("STRICT_TRANS_TABLES,ANSI_QUOTES") {
		t.Fatal("ordinary mode list should validate")
	}
	if !isSQLModeList("") {
		t.Fatal("empty mode list is legal (sql_mode='')")
	}
	for _, bad := range []string{"STRICT' ,", "MODE;DROP", "MODE\n", "MODE\""} {
		if isSQLModeList(bad) {
			t.Fatalf("%q must not be spliced into SET SESSION sql_mode", bad)
		}
	}
}

// Error text travels to the plugin's log, which is usually less protected than
// the relay process: internal addresses must not survive.
func TestRedactHidesAddresses(t *testing.T) {
	msg := "dial tcp 10.4.4.9:3306: connect: connection refused"
	out := redact(msg, "10.4.4.9:3306", "10.4.4.9")
	if strings.Contains(out, "10.4.4.9") {
		t.Fatalf("address leaked: %q", out)
	}
	if !strings.Contains(out, "connection refused") {
		t.Fatalf("reason should survive redaction: %q", out)
	}
	// Short values are skipped so a port number cannot mangle the message.
	if got := redact("error 1045", "104"); got != "error 1045" {
		t.Fatalf("short secret must be ignored, got %q", got)
	}
}

func TestOneLineAndTruncate(t *testing.T) {
	if got := oneLine("a\nb\rc"); got != "a b c" {
		t.Fatalf("oneLine: %q", got)
	}
	long := strings.Repeat("x", 500)
	got := truncateForLog(long, 100)
	if len(got) > 120 || !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("truncate: len=%d %q", len(got), got[len(got)-20:])
	}
}
