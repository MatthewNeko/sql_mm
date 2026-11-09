package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

// dsnRequest mirrors the SQLMM MySQLConnectionInfo the plugin forwards.
type dsnRequest struct {
	Host           string
	Port           uint16
	User           string
	Pass           string
	Database       string
	TimeoutSeconds uint16
}

// column is one field of a result set.
type column struct {
	name string
	typ  uint16
}

// resultSet holds a fully materialised result set. cells is a flat array of
// rowCount*len(columns) entries; nil means SQL NULL.
type resultSet struct {
	columns []column
	cells   [][]byte
	rows    int
}

// statement is one executed SQL string. A transaction produces one statement
// per query, in order, because ISQLQuery vectors passed to the transaction
// callbacks are indexed positionally by callers.
type statement struct {
	sets         []*resultSet
	insertID     int64
	affectedRows int64
}

// session owns exactly one physical MySQL connection for its whole lifetime.
//
// This is not an optimisation detail: the plugin implements transactions by
// sending BEGIN/COMMIT as ordinary statements and callers rely on
// LAST_INSERT_ID(), user variables and temporary tables surviving between
// statements. A shared pool would silently spread those across connections.
type session struct {
	id      uint64
	cfg     *Config
	db      *sql.DB
	conn    *sql.Conn
	version string

	// features is the ConnectOK feature bitmask mirrored to the plugin.
	features uint32

	// lastInsertID tracks mysql_insert_id() semantics: it survives non-INSERT
	// statements, which is what the legacy direct-connect path exposed.
	lastInsertID int64

	// secrets are strings that must never leave the process in an error
	// message: the real MySQL address, and the account name when it differs
	// from what the client sent.
	secrets []string
}

// newSession dials MySQL for one plugin connection. dialHost is the address
// ClientHostFilter validated; it is empty when the client asked for the relay's
// own database.
func newSession(ctx context.Context, cfg *Config, id uint64, req dsnRequest, dialHost string) (*session, error) {
	d := cfg.Fallback
	if cfg.AllowClientDSN && req.Host != "" && dialHost != "" {
		d = DSN{Host: dialHost, Port: int(req.Port), User: req.User, Pass: req.Pass, Database: req.Database}
	}
	if d.Port == 0 {
		d.Port = 3306
	}

	mc := mysql.NewConfig()
	mc.User = d.User
	mc.Passwd = d.Pass
	mc.DBName = d.Database
	if strings.HasPrefix(d.Host, "/") {
		// Unix socket path, same convention as libmysqlclient.
		mc.Net = "unix"
		mc.Addr = d.Host
	} else {
		mc.Net = "tcp"
		mc.Addr = net.JoinHostPort(d.Host, strconv.Itoa(d.Port))
	}

	mc.Timeout = cfg.dialTimeout()

	// Realistic reads: the plugin's MySQLConnectionInfo.timeout is the
	// libmysqlclient read timeout, so honour it when provided. When it is not,
	// never go below minReadTimeout — a zero socket timeout lets one stalled
	// statement pin this session (and its goroutine) for the process lifetime.
	ioTimeout := time.Duration(cfg.ReadTimeoutSeconds) * time.Second
	if ioTimeout < minReadTimeout {
		ioTimeout = minReadTimeout
	}
	if req.TimeoutSeconds > 0 {
		ioTimeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	mc.ReadTimeout = ioTimeout
	mc.WriteTimeout = ioTimeout

	mc.MultiStatements = true
	mc.ParseTime = false // keep DATETIME/TIMESTAMP as text, like the text protocol
	mc.Params = map[string]string{"charset": "utf8mb4"}

	db, err := sql.Open("mysql", mc.FormatDSN())
	if err != nil {
		return nil, err
	}
	// One session == one physical connection. Never let the pool recycle it:
	// a recycled connection loses session state the caller depends on.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)

	dialCtx, cancel := context.WithTimeout(ctx, cfg.dialTimeout())
	defer cancel()

	if err := db.PingContext(dialCtx); err != nil {
		db.Close()
		return nil, err
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		db.Close()
		return nil, err
	}

	s := &session{id: id, cfg: cfg, db: db, conn: conn}
	if mc.Net == "tcp" {
		s.secrets = []string{mc.Addr, d.Host}
	} else {
		s.secrets = []string{d.Host}
	}

	if err := s.normaliseSQLMode(ctx); err != nil {
		conn.Close()
		db.Close()
		return nil, err
	}
	if err := conn.QueryRowContext(ctx, "SELECT VERSION()").Scan(&s.version); err != nil {
		s.version = "unknown"
	}

	return s, nil
}

// normaliseSQLMode makes the relay's escaping rules true for this session.
//
// The plugin escapes with backslashes: there is no live server handle on its
// side, and mysql_real_escape_string is gone. If the server's sql_mode contains
// NO_BACKSLASH_ESCAPES then \' does not terminate an escaped quote, and every
// escaped literal silently becomes an injection point. Rather than trying to
// mirror that mode over the wire, the relay drops the flag for its own session
// and *refuses the session* if it cannot. One safe mode beats two modes that
// have to be kept in sync across a protocol boundary.
func (s *session) normaliseSQLMode(ctx context.Context) error {
	var mode string
	if err := s.conn.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode").Scan(&mode); err != nil {
		return fmt.Errorf("cannot read sql_mode, refusing a session whose escaping rules are unknown: %w", err)
	}
	if !strings.Contains(strings.ToUpper(mode), "NO_BACKSLASH_ESCAPES") {
		return nil
	}

	cleaned, _ := removeSQLMode(mode, "NO_BACKSLASH_ESCAPES")
	// sql_mode is a comma separated list of identifiers. Validate that shape
	// and splice it in, rather than relying on a parameter marker inside SET
	// (which not every server/proxy combination accepts).
	if !isSQLModeList(cleaned) {
		return fmt.Errorf("sql_mode %q is not a plain list of modes, refusing to rewrite it", mode)
	}
	if _, err := s.conn.ExecContext(ctx, "SET SESSION sql_mode = '"+cleaned+"'"); err != nil {
		return fmt.Errorf("server sql_mode has NO_BACKSLASH_ESCAPES and SET SESSION sql_mode failed; "+
			"backslash escaping would be unsafe on this session: %w", err)
	}

	// Verify rather than trust: a proxy or a read-only replica can accept the
	// statement and ignore it.
	var verified string
	if err := s.conn.QueryRowContext(ctx, "SELECT @@SESSION.sql_mode").Scan(&verified); err != nil {
		return fmt.Errorf("cannot verify sql_mode after clearing NO_BACKSLASH_ESCAPES: %w", err)
	}
	if strings.Contains(strings.ToUpper(verified), "NO_BACKSLASH_ESCAPES") {
		return errors.New("server kept NO_BACKSLASH_ESCAPES after SET SESSION sql_mode; " +
			"backslash escaping would be unsafe on this session")
	}
	return nil
}

// isSQLModeList reports whether s looks like a sql_mode value: identifiers
// separated by commas, nothing else.
func isSQLModeList(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == ',':
		default:
			return false
		}
	}
	return true
}

// removeSQLMode drops one element from a comma separated sql_mode value.
func removeSQLMode(mode, drop string) (string, bool) {
	parts := strings.Split(mode, ",")
	out := make([]string, 0, len(parts))
	changed := false
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if strings.EqualFold(trimmed, drop) {
			changed = true
			continue
		}
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, ","), changed
}

func (s *session) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
	if s.db != nil {
		s.db.Close()
	}
}

func (s *session) ctx() (context.Context, context.CancelFunc) {
	if d := s.cfg.queryTimeout(); d > 0 {
		return context.WithTimeout(context.Background(), d)
	}
	return context.WithCancel(context.Background())
}

// run executes a single SQL string and materialises whatever it returns.
func (s *session) run(query string) (*statement, error) {
	ctx, cancel := s.ctx()
	defer cancel()
	return s.runWithContext(ctx, query)
}

// queryRows drains every result set produced by the statement. Statements with
// no columns at all (the driver can route INSERT/DDL here for odd SQL) produce
// zero sets, which the plugin reports as a NULL result set.
func (s *session) queryRows(ctx context.Context, query string) ([]*resultSet, error) {
	rows, err := s.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sets []*resultSet
	budget := s.cfg.MaxPayloadBytes

	for {
		cols, err := rows.Columns()
		if err != nil {
			return nil, err
		}
		types, err := rows.ColumnTypes()
		if err != nil {
			return nil, err
		}

		if len(cols) == 0 {
			// No tabular output; nothing to publish for this set.
			if !rows.NextResultSet() {
				break
			}
			continue
		}

		rs := &resultSet{columns: make([]column, len(cols))}
		for i := range cols {
			typName := ""
			if i < len(types) && types[i] != nil {
				typName = types[i].DatabaseTypeName()
			}
			rs.columns[i] = column{name: cols[i], typ: mapColumnType(typName)}
			budget -= len(cols[i]) + 8
		}

		raw := make([]sql.RawBytes, len(cols))
		dest := make([]any, len(cols))
		for i := range raw {
			dest[i] = &raw[i]
		}

		for rows.Next() {
			if err := rows.Scan(dest...); err != nil {
				return nil, err
			}
			for _, v := range raw {
				if v == nil {
					rs.cells = append(rs.cells, nil)
					budget -= 4
				} else {
					cell := make([]byte, len(v))
					copy(cell, v)
					rs.cells = append(rs.cells, cell)
					budget -= len(cell) + 4
				}
			}
			rs.rows++
			if budget < 0 {
				return nil, errPayloadTooLarge
			}
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}

		sets = append(sets, rs)

		if !rows.NextResultSet() {
			if err := rows.Err(); err != nil {
				return nil, err
			}
			break
		}
	}

	return sets, nil
}

// runTransaction mirrors the legacy TMySQLTransactOp: BEGIN, run each query in
// order, COMMIT. On failure the transaction is rolled back and the index of the
// offending query is reported so callers can keep logging what they used to.
func (s *session) runTransaction(queries []string) ([]*statement, int, error) {
	ctx, cancel := s.ctx()
	defer cancel()

	if _, err := s.conn.ExecContext(ctx, "BEGIN"); err != nil {
		return nil, -1, err
	}

	out := make([]*statement, 0, len(queries))
	for i, q := range queries {
		st, err := s.runWithContext(ctx, q)
		if err != nil {
			s.rollback()
			return nil, i, err
		}
		out = append(out, st)
	}

	if _, err := s.conn.ExecContext(ctx, "COMMIT"); err != nil {
		s.rollback()
		return nil, -1, err
	}
	return out, -1, nil
}

func (s *session) rollback() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = s.conn.ExecContext(ctx, "ROLLBACK")
}

// runWithContext is run() reusing an existing context/connection, so transaction
// member statements do not get their own per-statement timeout.
func (s *session) runWithContext(ctx context.Context, query string) (*statement, error) {
	st := &statement{}
	if isRowReturning(query) {
		sets, err := s.queryRows(ctx, query)
		if err != nil {
			return nil, err
		}
		st.sets = sets
		if len(sets) > 0 {
			// libmysqlclient reports the result row count through
			// mysql_affected_rows() for SELECT-shaped statements.
			st.affectedRows = int64(sets[0].rows)
		}
		st.insertID = s.lastInsertID
		return st, nil
	}
	res, err := s.conn.ExecContext(ctx, query)
	if err != nil {
		return nil, err
	}
	if id, idErr := res.LastInsertId(); idErr == nil {
		st.insertID = id
		s.lastInsertID = id
	} else {
		s.lastInsertID = 0
	}
	if n, nErr := res.RowsAffected(); nErr == nil {
		st.affectedRows = n
	}
	return st, nil
}

// writeResult serialises a successful response.
func writeResult(w *writer, reqID uint32, stmts []*statement) {
	w.u32(reqID)
	w.u16(uint16(len(stmts)))
	for _, st := range stmts {
		w.u64(uint64(st.insertID))
		w.u64(uint64(st.affectedRows))
		w.u16(uint16(len(st.sets)))
		for _, rs := range st.sets {
			w.u16(uint16(len(rs.columns)))
			for _, c := range rs.columns {
				w.str(c.name)
				w.u16(c.typ)
			}
			w.u32(uint32(rs.rows))
			for _, cell := range rs.cells {
				if cell == nil {
					w.i32(-1)
					continue
				}
				// Length first, then the raw bytes: the plugin copies the cell
				// into its own arena and relies on the length being exact.
				// Raw bytes are re-emitted verbatim, so GetInt/GetFloat parse
				// text exactly as atoi/atof did.
				w.i32(int32(len(cell)))
				w.raw(cell)
			}
		}
	}
}

func writeError(w *writer, reqID uint32, opcode byte, failIndex int, msg string) {
	w.u32(reqID)
	w.u8(opcode)
	w.i32(int32(failIndex))
	w.str(msg)
}

// errText renders an error for the wire and for the log, with anything that
// identifies the internal MySQL endpoint redacted.
func (s *session) errText(err error) string {
	if err == nil {
		return ""
	}
	return truncateForLog(redact(fmt.Sprintf("%v", err), s.secrets...), 400)
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}
