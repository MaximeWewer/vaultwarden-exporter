package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURL(t *testing.T) {
	cases := []struct {
		url     string
		driver  string
		dialect Dialect
		dsn     string
	}{
		{"postgresql://u:p@db:5432/vw?sslmode=require", "pgx", Postgres, "postgresql://u:p@db:5432/vw?sslmode=require"},
		{"postgres://u@db/vw", "pgx", Postgres, "postgres://u@db/vw"},
		{"sqlite:///data/db.sqlite3", "sqlite", SQLite, "file:/data/db.sqlite3?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)"},
		{"data/db.sqlite3", "sqlite", SQLite, "file:data/db.sqlite3?mode=ro&_pragma=busy_timeout(5000)&_pragma=query_only(1)"},
	}
	for _, c := range cases {
		driver, dsn, dialect, err := parseURL(c.url)
		require.NoError(t, err, c.url)
		assert.Equal(t, c.driver, driver, c.url)
		assert.Equal(t, c.dialect, dialect, c.url)
		assert.Equal(t, c.dsn, dsn, c.url)
	}

	for _, bad := range []string{"", "redis://x", "mysql://u:p@db"} {
		_, _, _, err := parseURL(bad)
		assert.Error(t, err, bad)
	}
}

func TestMySQLDSN(t *testing.T) {
	dsn, err := mysqlDSN("mysql://vw:s%40cret@mariadb/vaultwarden?ssl_mode=required")
	require.NoError(t, err)
	assert.Contains(t, dsn, "vw:s@cret@tcp(mariadb:3306)/vaultwarden")
	assert.Contains(t, dsn, "parseTime=true")
	assert.Contains(t, dsn, "tls=skip-verify")
	assert.Contains(t, dsn, "time_zone=%27%2B00%3A00%27")

	dsn, err = mysqlDSN("mysql://vw@mariadb:3307/vw?ssl_mode=verify_identity")
	require.NoError(t, err)
	assert.Contains(t, dsn, "tcp(mariadb:3307)")
	assert.Contains(t, dsn, "tls=true")
}

func TestDialectHelpers(t *testing.T) {
	pg := &DB{Dialect: Postgres}
	assert.Equal(t, "SELECT a FROM t WHERE x = $1 AND y > $2", pg.Rebind("SELECT a FROM t WHERE x = ? AND y > ?"))
	my := &DB{Dialect: MySQL}
	assert.Equal(t, "x = ?", my.Rebind("x = ?"))
	assert.Equal(t, "`groups`", my.Quote("groups"))
	assert.Equal(t, `"groups"`, pg.Quote("groups"))
	assert.Equal(t, "postgresql", Postgres.String())
	assert.Equal(t, "mysql", MySQL.String())
	assert.Equal(t, "sqlite", SQLite.String())

	ts := time.Date(2026, 11, 5, 12, 30, 9, 471627000, time.FixedZone("CET", 3600))
	assert.Equal(t, "2026-11-05 11:30:09.471627", (&DB{Dialect: SQLite}).TimeArg(ts))
	assert.Equal(t, ts.UTC(), pg.TimeArg(ts))
}

func TestParseTime(t *testing.T) {
	want := time.Date(2026, 11, 5, 12, 30, 9, 471627000, time.UTC)
	for _, v := range []any{
		"2026-11-05 12:30:09.471627",
		[]byte("2026-11-05 12:30:09.471627"),
		"2026-11-05T12:30:09.471627Z",
		time.Date(2026, 11, 5, 12, 30, 9, 471627000, time.Local),
	} {
		got, err := ParseTime(v)
		require.NoError(t, err, v)
		assert.True(t, want.Equal(got), "%v -> %v", v, got)
	}
	_, err := ParseTime(42)
	assert.Error(t, err)
	_, err = ParseTime("yesterday")
	assert.Error(t, err)
}

func TestOpenSQLiteReadOnly(t *testing.T) {
	db, err := Open(t.TempDir()+"/missing.sqlite3", 1)
	require.NoError(t, err, "open is lazy")
	defer db.Close()
	assert.Equal(t, SQLite, db.Dialect)
	assert.Error(t, db.Ping(context.Background(), time.Second), "read-only open of a missing file fails")

	_, err = Open("redis://x", 1)
	assert.Error(t, err)
}
