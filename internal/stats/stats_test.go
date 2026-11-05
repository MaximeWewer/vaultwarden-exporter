package stats

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/vwtest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seed(t *testing.T, db *vwtest.DB) {
	t.Helper()
	// 3 users: alice (enabled, verified, totp + webauthn), bob (enabled, no 2FA),
	// carol (disabled, unverified)
	db.Exec(t, `INSERT INTO users (uuid, enabled, verified_at, email, name) VALUES
		('u1', 1, '2026-01-01 00:00:00', 'alice@example.com', 'Alice'),
		('u2', 1, '2026-01-01 00:00:00', 'bob@example.com', 'Bob'),
		('u3', 0, NULL, 'carol@example.com', 'Carol')`)
	db.Exec(t, `INSERT INTO twofactor (uuid, user_uuid, atype, enabled) VALUES
		('t1', 'u1', 0, 1), ('t2', 'u1', 7, 1), ('t3', 'u2', 0, 0), ('t4', 'u2', 5, 1)`)
	db.Exec(t, `INSERT INTO twofactor_incomplete (user_uuid, device_uuid, login_time) VALUES ('u2', 'd9', '2026-11-05 10:00:00')`)
	db.Exec(t, `INSERT INTO organizations (uuid, name) VALUES ('o1', 'Acme')`)
	db.Exec(t, `INSERT INTO users_organizations (uuid, user_uuid, org_uuid, status, atype) VALUES
		('m1', 'u1', 'o1', 2, 0), ('m2', 'u2', 'o1', 0, 2), ('m3', 'u3', 'o1', -1, 2)`)
	db.Exec(t, `INSERT INTO collections (uuid, org_uuid) VALUES ('c1', 'o1'), ('c2', 'o1')`)
	db.Exec(t, `INSERT INTO groups (uuid, organizations_uuid) VALUES ('g1', 'o1')`)
	db.Exec(t, `INSERT INTO ciphers (uuid, user_uuid, atype, deleted_at) VALUES
		('x1', 'u1', 1, NULL), ('x2', 'u1', 1, NULL), ('x3', 'u2', 3, '2026-11-01 00:00:00'), ('x4', 'u2', 9, NULL)`)
	db.Exec(t, `INSERT INTO attachments (id, cipher_uuid, file_size) VALUES ('a1', 'x1', 1000), ('a2', 'x2', 2500)`)
	db.Exec(t, `INSERT INTO sends (uuid, user_uuid, atype) VALUES ('s1', 'u1', 1)`)
	db.Exec(t, `INSERT INTO devices (uuid, user_uuid, atype) VALUES ('d1', 'u1', 9), ('d2', 'u2', 9), ('d3', 'u2', 0)`)
	db.Exec(t, `INSERT INTO emergency_access (uuid, grantor_uuid, atype, status) VALUES ('e1', 'u1', 0, 2)`)
}

func newCollector(t *testing.T) (*Collector, *vwtest.DB, *prometheus.Registry) {
	t.Helper()
	db := vwtest.New(t)
	reg := prometheus.NewRegistry()
	c, err := New(db.RO, 5*time.Second, reg)
	require.NoError(t, err)
	require.NoError(t, reg.Register(c))
	return c, db, reg
}

func TestRefreshProducesMetrics(t *testing.T) {
	c, db, reg := newCollector(t)
	seed(t, db)
	assert.False(t, c.Ready())
	require.NoError(t, c.Refresh(context.Background()))
	assert.True(t, c.Ready())

	expected := `
# HELP vaultwarden_users Vaultwarden user accounts.
# TYPE vaultwarden_users gauge
vaultwarden_users{email_verified="false",enabled="false"} 1
vaultwarden_users{email_verified="false",enabled="true"} 0
vaultwarden_users{email_verified="true",enabled="false"} 0
vaultwarden_users{email_verified="true",enabled="true"} 2
# HELP vaultwarden_users_without_two_factor Enabled users without any two-factor method.
# TYPE vaultwarden_users_without_two_factor gauge
vaultwarden_users_without_two_factor 1
# HELP vaultwarden_two_factor_incomplete_logins Logins that passed the password but not the second factor yet.
# TYPE vaultwarden_two_factor_incomplete_logins gauge
vaultwarden_two_factor_incomplete_logins 1
# HELP vaultwarden_organizations Organizations.
# TYPE vaultwarden_organizations gauge
vaultwarden_organizations 1
# HELP vaultwarden_collections Organization collections.
# TYPE vaultwarden_collections gauge
vaultwarden_collections 2
# HELP vaultwarden_groups Organization groups.
# TYPE vaultwarden_groups gauge
vaultwarden_groups 1
# HELP vaultwarden_attachments Vault item attachments.
# TYPE vaultwarden_attachments gauge
vaultwarden_attachments 2
# HELP vaultwarden_attachments_size_bytes Total size of the attachments.
# TYPE vaultwarden_attachments_size_bytes gauge
vaultwarden_attachments_size_bytes 3500
# HELP vaultwarden_exporter_up 1 if the last metrics refresh succeeded for every query.
# TYPE vaultwarden_exporter_up gauge
vaultwarden_exporter_up 1
`
	require.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(expected),
		"vaultwarden_users", "vaultwarden_users_without_two_factor", "vaultwarden_two_factor_incomplete_logins",
		"vaultwarden_organizations", "vaultwarden_collections", "vaultwarden_groups", "vaultwarden_attachments",
		"vaultwarden_attachments_size_bytes", "vaultwarden_exporter_up"))

	mfs, err := reg.Gather()
	require.NoError(t, err)
	values := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			key := mf.GetName()
			for _, l := range m.GetLabel() {
				key += "," + l.GetName() + "=" + l.GetValue()
			}
			values[key] = m.GetGauge().GetValue()
		}
	}
	assert.Equal(t, 1.0, values["vaultwarden_users_two_factor,method=authenticator"], "disabled totp of bob not counted")
	assert.Equal(t, 1.0, values["vaultwarden_users_two_factor,method=webauthn"])
	assert.Equal(t, 0.0, values["vaultwarden_users_two_factor,method=yubikey"], "zero-filled")
	assert.Equal(t, 1.0, values["vaultwarden_organization_members,role=owner,status=confirmed"])
	assert.Equal(t, 1.0, values["vaultwarden_organization_members,role=user,status=invited"])
	assert.Equal(t, 1.0, values["vaultwarden_organization_members,role=user,status=revoked"])
	assert.Equal(t, 2.0, values["vaultwarden_ciphers,state=active,type=login"])
	assert.Equal(t, 1.0, values["vaultwarden_ciphers,state=trashed,type=card"])
	assert.Equal(t, 1.0, values["vaultwarden_ciphers,state=active,type=unknown_9"])
	assert.Equal(t, 1.0, values["vaultwarden_sends,type=file"])
	assert.Equal(t, 0.0, values["vaultwarden_sends,type=text"])
	assert.Equal(t, 2.0, values["vaultwarden_devices,type=ChromeBrowser"])
	assert.Equal(t, 1.0, values["vaultwarden_devices,type=Android"])
	assert.Equal(t, 1.0, values["vaultwarden_emergency_access,status=confirmed"])
}

func TestFailedQueryKeepsPreviousValuesAndMarksDown(t *testing.T) {
	c, db, reg := newCollector(t)
	seed(t, db)
	require.NoError(t, c.Refresh(context.Background()))

	db.Exec(t, "DROP TABLE sends")
	err := c.Refresh(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sends")

	assert.Equal(t, 0.0, testutil.ToFloat64(c.up))
	assert.Equal(t, 1.0, testutil.ToFloat64(c.errors.WithLabelValues("sends")))
	n, err := testutil.GatherAndCount(reg, "vaultwarden_sends")
	require.NoError(t, err)
	assert.Equal(t, 2, n, "previous sends values are kept")
}

func TestRunStopsWithContext(t *testing.T) {
	c, db, _ := newCollector(t)
	seed(t, db)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- c.Run(ctx, 10*time.Millisecond) }()
	require.Eventually(t, c.Ready, time.Second, 5*time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestDescribeAndHelpers(t *testing.T) {
	c, _, _ := newCollector(t)
	ch := make(chan *prometheus.Desc, 32)
	c.Describe(ch)
	close(ch)
	assert.Len(t, ch, 14)

	assert.True(t, toBool(true))
	assert.True(t, toBool(int64(1)))
	assert.False(t, toBool(int64(0)))
	assert.True(t, toBool([]byte("1")))
	assert.False(t, toBool("false"))
	assert.False(t, toBool(3.5))
	assert.Equal(t, "0,1,2,3,4,6,7", methodCodes())
}
