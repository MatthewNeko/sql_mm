package main

import "strings"

// mapColumnType translates the driver's DatabaseTypeName() into the MySQL
// protocol field type the plugin exposes as MM_MYSQL_TYPE_*. Values follow
// libmysqlclient's enum, not the driver's naming, because consumers of
// ISQLResult::GetFieldType() compare against that enum.
func mapColumnType(name string) uint16 {
	switch strings.ToUpper(name) {
	case "TINYINT", "BOOL", "BOOLEAN":
		return typeTiny
	case "SMALLINT":
		return typeShort
	case "MEDIUMINT":
		return typeInt24
	case "INT", "INTEGER":
		return typeLong
	case "BIGINT", "UNSIGNED BIGINT":
		return typeLongLong
	case "FLOAT":
		return typeFloat
	case "DOUBLE", "REAL":
		return typeDouble
	case "DECIMAL", "NUMERIC":
		return typeNewDec
	case "NULL":
		return typeNull
	case "TIMESTAMP":
		return typeTimestamp
	case "DATE":
		return typeDate
	case "TIME":
		return typeTime
	case "DATETIME":
		return typeDateTime
	case "YEAR":
		return typeYear
	case "BIT":
		return typeBit
	case "JSON":
		return typeJSON
	case "ENUM":
		return typeEnum
	case "SET":
		return typeSet
	case "TINYTEXT", "TINYBLOB":
		return typeTinyBlob
	case "MEDIUMTEXT", "MEDIUMBLOB":
		return typeMedBlob
	case "LONGTEXT", "LONGBLOB":
		return typeLongBlob
	case "TEXT", "BLOB":
		return typeBlob
	case "VARCHAR", "VARBINARY":
		return typeVarString
	case "CHAR", "BINARY":
		return typeString
	case "GEOMETRY", "POINT", "LINESTRING", "POLYGON",
		"MULTIPOINT", "MULTILINESTRING", "MULTIPOLYGON",
		"GEOMETRYCOLLECTION", "GEOMCOLLECTION":
		return typeGeometry
	default:
		return typeUnknown
	}
}

// rowReturningVerbs lists statements that can produce a result set. They must
// go through QueryContext; everything else goes through ExecContext so that
// LastInsertId/RowsAffected are available.
var rowReturningVerbs = map[string]bool{
	"SELECT":   true,
	"WITH":     true, // CTE; the outer statement decides, but treat as rows
	"SHOW":     true,
	"DESC":     true,
	"DESCRIBE": true,
	"EXPLAIN":  true,
	"TABLE":    true, // MySQL 8 TABLE t
	"VALUES":   true,
	"ANALYZE":  true,
	"CALL":     true, // may or may not return rows; Query handles both
	"CHECK":    true,
	"CHECKSUM": true,
	"HELP":     true,
	"HANDLER":  true,
}

// firstKeyword returns the leading SQL keyword with comments and whitespace
// stripped. Returns "" for empty/comment-only input.
func firstKeyword(query string) string {
	i := 0
	n := len(query)
	for i < n {
		switch {
		case query[i] == ' ' || query[i] == '\t' || query[i] == '\n' ||
			query[i] == '\r' || query[i] == '\f' || query[i] == '\v':
			i++
		case query[i] == '/' && i+1 < n && query[i+1] == '*':
			end := strings.Index(query[i+2:], "*/")
			if end < 0 {
				return ""
			}
			i += 2 + end + 2
		case query[i] == '-' && i+1 < n && query[i+1] == '-':
			// MySQL requires "-- " (or end of input) to start a comment,
			// but being lenient here only affects dispatch, never execution.
			end := strings.IndexByte(query[i:], '\n')
			if end < 0 {
				return ""
			}
			i += end + 1
		case query[i] == '#':
			end := strings.IndexByte(query[i:], '\n')
			if end < 0 {
				return ""
			}
			i += end + 1
		default:
			j := i
			for j < n && (isAlphaNum(query[j]) || query[j] == '_') {
				j++
			}
			return strings.ToUpper(query[i:j])
		}
	}
	return ""
}

func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isRowReturning(query string) bool {
	return rowReturningVerbs[firstKeyword(query)]
}
