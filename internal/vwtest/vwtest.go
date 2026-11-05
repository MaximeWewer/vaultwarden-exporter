// Package vwtest builds SQLite databases with the Vaultwarden schema (the
// tables and columns the exporter reads, types as in the SQLite migrations)
// for the unit tests. The data is written through a separate read-write
// connection; the exporter opens the file read-only, as in production.
package vwtest

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/database"
	_ "modernc.org/sqlite" // SQLite driver
)

// Schema is the subset of the Vaultwarden schema read by the exporter
const Schema = `
CREATE TABLE users (
  uuid TEXT NOT NULL PRIMARY KEY, enabled BOOLEAN NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, verified_at DATETIME,
  email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash BLOB NOT NULL DEFAULT x'00');
CREATE TABLE organizations (uuid TEXT NOT NULL PRIMARY KEY, name TEXT NOT NULL, billing_email TEXT NOT NULL DEFAULT '');
CREATE TABLE users_organizations (
  uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT NOT NULL, org_uuid TEXT NOT NULL,
  access_all BOOLEAN NOT NULL DEFAULT 0, akey TEXT NOT NULL DEFAULT '', status INTEGER NOT NULL, atype INTEGER NOT NULL);
CREATE TABLE ciphers (
  uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT, organization_uuid TEXT, atype INTEGER NOT NULL,
  name TEXT NOT NULL DEFAULT '', data TEXT NOT NULL DEFAULT '', deleted_at DATETIME);
CREATE TABLE attachments (id TEXT NOT NULL PRIMARY KEY, cipher_uuid TEXT NOT NULL, file_name TEXT NOT NULL DEFAULT '', file_size BIGINT NOT NULL);
CREATE TABLE sends (uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT, atype INTEGER NOT NULL, data TEXT NOT NULL DEFAULT '');
CREATE TABLE devices (uuid TEXT NOT NULL, user_uuid TEXT NOT NULL, name TEXT NOT NULL DEFAULT '', atype INTEGER NOT NULL, PRIMARY KEY (uuid, user_uuid));
CREATE TABLE twofactor (uuid TEXT NOT NULL PRIMARY KEY, user_uuid TEXT NOT NULL, atype INTEGER NOT NULL, enabled BOOLEAN NOT NULL, data TEXT NOT NULL DEFAULT '');
CREATE TABLE twofactor_incomplete (user_uuid TEXT NOT NULL, device_uuid TEXT NOT NULL, device_name TEXT NOT NULL DEFAULT '', login_time DATETIME NOT NULL, ip_address TEXT NOT NULL DEFAULT '', PRIMARY KEY (user_uuid, device_uuid));
CREATE TABLE emergency_access (uuid TEXT NOT NULL PRIMARY KEY, grantor_uuid TEXT, grantee_uuid TEXT, atype INTEGER NOT NULL, status INTEGER NOT NULL);
CREATE TABLE collections (uuid TEXT NOT NULL PRIMARY KEY, org_uuid TEXT NOT NULL, name TEXT NOT NULL DEFAULT '');
CREATE TABLE groups (uuid TEXT NOT NULL PRIMARY KEY, organizations_uuid TEXT NOT NULL, name TEXT NOT NULL DEFAULT '');
CREATE TABLE event (
  uuid CHAR(36) NOT NULL PRIMARY KEY, event_type INTEGER NOT NULL, user_uuid CHAR(36), org_uuid CHAR(36),
  cipher_uuid CHAR(36), collection_uuid CHAR(36), group_uuid CHAR(36), org_user_uuid CHAR(36), act_user_uuid CHAR(36),
  device_type INTEGER, ip_address TEXT, event_date DATETIME NOT NULL, policy_uuid CHAR(36),
  provider_uuid CHAR(36), provider_user_uuid CHAR(36), provider_org_uuid CHAR(36));
`

// TimeLayout is the Diesel SQLite timestamp format
const TimeLayout = "2006-01-02 15:04:05.999999"

// DB is a test database: W writes, RO is the exporter read-only handle
type DB struct {
	W  *sql.DB
	RO *database.DB
}

// New creates a database with the Vaultwarden schema in a temporary directory
func New(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "db.sqlite3")
	w, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	w.SetMaxOpenConns(1)
	if _, err := w.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	ro, err := database.Open("sqlite://"+path, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ro.Close()
		_ = w.Close()
	})
	return &DB{W: w, RO: ro}
}

// Exec runs a statement on the writable handle
func (d *DB) Exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := d.W.Exec(query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// Event is a row of the event table for the tests
type Event struct {
	UUID, User, Org, Actor, Member, IP string
	Type, Device                       int
	Date                               time.Time
}

// InsertEvent stores an event (empty strings are NULL)
func (d *DB) InsertEvent(t *testing.T, e Event) {
	t.Helper()
	d.Exec(t, `INSERT INTO event (uuid, event_type, user_uuid, org_uuid, act_user_uuid, org_user_uuid, device_type, ip_address, event_date)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.UUID, e.Type, null(e.User), null(e.Org), null(e.Actor), null(e.Member), e.Device, null(e.IP), e.Date.UTC().Format(TimeLayout))
}

// UUID returns a deterministic uuid-shaped identifier
func UUID(n int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", n, n)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}
