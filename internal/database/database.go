// Package database opens the Vaultwarden database from a URL in the
// Vaultwarden DATABASE_URL format and hides the differences between the
// supported engines (PostgreSQL, MySQL/MariaDB, SQLite).
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib" // PostgreSQL driver (pgx)
	_ "modernc.org/sqlite"             // SQLite driver, pure Go (no CGO)
)

// Dialect identifies the database engine
type Dialect int

// Supported engines
const (
	Postgres Dialect = iota
	MySQL
	SQLite
)

func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgresql"
	case MySQL:
		return "mysql"
	default:
		return "sqlite"
	}
}

// sqliteTimeLayout is how Diesel stores timestamps in SQLite (TEXT columns)
const sqliteTimeLayout = "2006-01-02 15:04:05.999999"

// DB is a database handle that knows its dialect
type DB struct {
	*sql.DB
	Dialect Dialect
}

// Open opens the database (lazily: no connection is made before the first
// query) with at most maxOpen connections
func Open(rawURL string, maxOpen int) (*DB, error) {
	driver, dsn, dialect, err := parseURL(rawURL)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dialect, err)
	}
	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxOpen)
	db.SetConnMaxIdleTime(5 * time.Minute)
	return &DB{DB: db, Dialect: dialect}, nil
}

// parseURL converts a Vaultwarden DATABASE_URL into a driver name and DSN
func parseURL(raw string) (driver, dsn string, dialect Dialect, err error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return "", "", 0, errors.New("empty database URL")
	case strings.HasPrefix(raw, "postgres://"), strings.HasPrefix(raw, "postgresql://"):
		return "pgx", raw, Postgres, nil
	case strings.HasPrefix(raw, "mysql://"):
		dsn, err := mysqlDSN(raw)
		return "mysql", dsn, MySQL, err
	case strings.HasPrefix(raw, "sqlite://"):
		return "sqlite", sqliteDSN(strings.TrimPrefix(raw, "sqlite://")), SQLite, nil
	case strings.Contains(raw, "://"):
		return "", "", 0, fmt.Errorf("unsupported database URL scheme in %q (postgresql://, mysql://, sqlite:// or a sqlite file path)",
			strings.SplitN(raw, "://", 2)[0]+"://")
	default:
		// A bare path is a SQLite file, as in Vaultwarden
		return "sqlite", sqliteDSN(raw), SQLite, nil
	}
}

// mysqlDSN converts mysql://user:pass@host:port/db?params to a go-sql-driver
// DSN. Timestamps are read and written in UTC, like Vaultwarden stores them.
func mysqlDSN(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid MySQL URL: %w", err)
	}
	cfg := mysql.NewConfig()
	if u.User != nil {
		cfg.User = u.User.Username()
		cfg.Passwd, _ = u.User.Password()
	}
	cfg.Net = "tcp"
	host := u.Host
	if u.Port() == "" {
		host += ":3306"
	}
	cfg.Addr = host
	cfg.DBName = strings.TrimPrefix(u.Path, "/")
	if cfg.DBName == "" {
		return "", errors.New("invalid MySQL URL: missing database name")
	}
	cfg.ParseTime = true
	cfg.Loc = time.UTC
	cfg.Params = map[string]string{"time_zone": "'+00:00'"}
	// Diesel / Vaultwarden URL option: ssl_mode=required|verify_identity...
	switch strings.ToLower(u.Query().Get("ssl_mode")) {
	case "required", "require", "preferred":
		cfg.TLSConfig = "skip-verify"
	case "verify_ca", "verify_identity":
		cfg.TLSConfig = "true"
	}
	return cfg.FormatDSN(), nil
}

// sqliteDSN opens a SQLite file read-only, waiting on locks instead of failing
func sqliteDSN(path string) string {
	return "file:" + path + "?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)"
}

// Rebind converts ? placeholders to $1, $2... for PostgreSQL
func (d *DB) Rebind(query string) string {
	if d.Dialect != Postgres {
		return query
	}
	var b strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			b.WriteString("$" + strconv.Itoa(n))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Quote quotes an identifier for the dialect (e.g. groups, reserved in MySQL 8)
func (d *DB) Quote(ident string) string {
	if d.Dialect == MySQL {
		return "`" + ident + "`"
	}
	return `"` + ident + `"`
}

// TimeArg returns a timestamp query argument in the storage format of the dialect
func (d *DB) TimeArg(t time.Time) any {
	t = t.UTC()
	if d.Dialect == SQLite {
		return t.Format(sqliteTimeLayout)
	}
	return t
}

// ParseTime converts a scanned timestamp column to a UTC time
func ParseTime(v any) (time.Time, error) {
	switch x := v.(type) {
	case time.Time:
		// TIMESTAMP WITHOUT TIME ZONE: the stored value is UTC
		return time.Date(x.Year(), x.Month(), x.Day(), x.Hour(), x.Minute(), x.Second(), x.Nanosecond(), time.UTC), nil
	case string:
		return parseTimeString(x)
	case []byte:
		return parseTimeString(string(x))
	default:
		return time.Time{}, fmt.Errorf("unexpected timestamp type %T", v)
	}
}

func parseTimeString(s string) (time.Time, error) {
	for _, layout := range []string{sqliteTimeLayout, "2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05.999999999"} {
		if t, err := time.ParseInLocation(layout, s, time.UTC); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unparsable timestamp %q", s)
}

// Ping checks the database is reachable within timeout
func (d *DB) Ping(ctx context.Context, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.PingContext(ctx)
}
