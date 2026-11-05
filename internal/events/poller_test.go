package events

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/maximewewer/vaultwarden-exporter/internal/state"
	"github.com/maximewewer/vaultwarden-exporter/internal/vwtest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func baseConfig() config.EventsConfig {
	return config.EventsConfig{Enabled: true, PollInterval: time.Second, BatchSize: 100, LateWindow: time.Hour,
		StartFrom: config.StartBeginning, Filter: config.EventFilter{OrgCopies: "all"}}
}

type env struct {
	db    *vwtest.DB
	out   *bytes.Buffer
	store *state.Memory
	p     *Poller
}

func newEnv(t *testing.T, cfg config.EventsConfig) *env {
	t.Helper()
	db := vwtest.New(t)
	db.Exec(t, `INSERT INTO users (uuid, email, name) VALUES ('u1', 'alice@example.com', 'Alice'), ('u2', 'bob@example.com', 'Bob')`)
	db.Exec(t, `INSERT INTO organizations (uuid, name) VALUES ('o1', 'Acme')`)
	e := &env{db: db, out: &bytes.Buffer{}, store: &state.Memory{}}
	e.p = e.newPoller(t, cfg)
	return e
}

func (e *env) newPoller(t *testing.T, cfg config.EventsConfig) *Poller {
	t.Helper()
	p, err := NewPoller(e.db.RO, cfg, 5*time.Second, e.store, NewWriter(e.out), prometheus.NewRegistry())
	require.NoError(t, err)
	p.now = func() time.Time { return now }
	require.NoError(t, p.Init(context.Background()))
	return p
}

func (e *env) lines(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(e.out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		require.NoError(t, json.Unmarshal([]byte(l), &m))
		out = append(out, m)
	}
	return out
}

func ev(n, typ int, user, org string, at time.Time) vwtest.Event {
	return vwtest.Event{UUID: vwtest.UUID(n), Type: typ, User: user, Actor: user, Org: org, Device: 9, IP: "203.0.113.7", Date: at}
}

func TestExportEnrichedEvents(t *testing.T) {
	e := newEnv(t, baseConfig())
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-10*time.Minute)))
	e.db.InsertEvent(t, ev(2, 1005, "u2", "o1", now.Add(-5*time.Minute)))

	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	lines := e.lines(t)
	require.Len(t, lines, 2)
	assert.Equal(t, "UserLoggedIn", lines[0]["event_name"])
	assert.Equal(t, "alice@example.com", lines[0]["user_email"])
	assert.Equal(t, "Alice", lines[0]["actor_name"])
	assert.Equal(t, "ChromeBrowser", lines[0]["device_name"])
	assert.Equal(t, "203.0.113.7", lines[0]["ip"])
	assert.Equal(t, "audit_event", lines[0]["kind"])
	assert.NotContains(t, lines[0], "org_id", "empty fields are omitted")
	assert.Equal(t, "2026-11-05T11:50:00.000000Z", lines[0]["timestamp"])
	assert.Equal(t, "UserFailedLogIn", lines[1]["event_name"])
	assert.Equal(t, "Acme", lines[1]["org_name"])

	assert.Equal(t, 1.0, testutil.ToFloat64(e.p.metrics.events.WithLabelValues("UserFailedLogIn")))
	assert.Equal(t, 0.0, testutil.ToFloat64(e.p.metrics.events.WithLabelValues("UserClientExportedVault")),
		"known event names are initialized at 0")
	assert.True(t, e.p.Ready())
}

func TestMemberEnrichment(t *testing.T) {
	e := newEnv(t, baseConfig())
	e.db.Exec(t, `INSERT INTO users_organizations (uuid, user_uuid, org_uuid, status, atype) VALUES ('m2', 'u2', 'o1', 0, 2)`)
	// Alice invites Bob; then a removed membership (row deleted) keeps only the id
	invited := ev(1, 1500, "", "o1", now.Add(-2*time.Minute))
	invited.Actor, invited.Member = "u1", "m2"
	e.db.InsertEvent(t, invited)
	removed := ev(2, 1503, "", "o1", now.Add(-time.Minute))
	removed.Actor, removed.Member = "u1", "m-gone"
	e.db.InsertEvent(t, removed)

	_, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	lines := e.lines(t)
	require.Len(t, lines, 2)
	assert.Equal(t, "OrganizationUserInvited", lines[0]["event_name"])
	assert.Equal(t, "alice@example.com", lines[0]["actor_email"])
	assert.Equal(t, "m2", lines[0]["member_id"])
	assert.Equal(t, "bob@example.com", lines[0]["member_email"])
	assert.Equal(t, "Bob", lines[0]["member_name"])
	assert.Equal(t, "m-gone", lines[1]["member_id"])
	assert.NotContains(t, lines[1], "member_email", "membership deleted: no email")
}

func TestNoReplayAfterRestartAndNewEventOnce(t *testing.T) {
	e := newEnv(t, baseConfig())
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-10*time.Minute)))
	_, err := e.p.Poll(context.Background())
	require.NoError(t, err)

	// Restart: a new poller loads the saved state
	e.out.Reset()
	p2 := e.newPoller(t, baseConfig())
	n, err := p2.Poll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "nothing replayed")

	e.db.InsertEvent(t, ev(2, 1005, "u1", "", now.Add(-time.Minute)))
	n, err = p2.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	n, err = p2.Poll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "exported once")
}

func TestLateEventInsideWindowIsExported(t *testing.T) {
	e := newEnv(t, baseConfig())
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-time.Minute)))
	_, err := e.p.Poll(context.Background())
	require.NoError(t, err)

	// A client uploads an event that happened 30 minutes ago (inside the 1h window)
	e.db.InsertEvent(t, ev(2, 1107, "u1", "", now.Add(-30*time.Minute)))
	// and one from 3 hours ago (outside the window: missed by design)
	e.db.InsertEvent(t, ev(3, 1107, "u1", "", now.Add(-3*time.Hour)))
	e.out.Reset()
	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
	assert.Equal(t, vwtest.UUID(2), e.lines(t)[0]["event_id"])
}

func TestPaginationAndPruning(t *testing.T) {
	cfg := baseConfig()
	cfg.BatchSize = 3
	cfg.LateWindow = 10 * time.Minute
	e := newEnv(t, cfg)
	for i := 0; i < 10; i++ {
		// Same timestamp for several events: the uuid breaks the tie
		e.db.InsertEvent(t, ev(i, 1000, "u1", "", now.Add(-time.Hour).Add(time.Duration(i/2)*time.Minute)))
	}
	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 10, n)
	assert.Len(t, e.lines(t), 10)

	st, found, err := e.store.Load(context.Background())
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, st.Cursor.Equal(now.Add(-time.Hour).Add(4*time.Minute)))
	assert.Len(t, st.Seen, 10, "all inside the 10 min window of the cursor")

	e.db.InsertEvent(t, ev(20, 1000, "u1", "", now))
	_, err = e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Len(t, e.p.st.Seen, 1, "events older than cursor-window are pruned")
}

func TestFiltersOrgCopiesAndLabels(t *testing.T) {
	cfg := baseConfig()
	cfg.Filter.Exclude = []string{"CipherClientViewed"}
	cfg.Filter.OrgCopies = "none"
	cfg.Labels = config.LabelsConfig{"cluster": "prod"}
	e := newEnv(t, cfg)
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-3*time.Minute)))   // login, no org: kept
	e.db.InsertEvent(t, ev(2, 1000, "u1", "o1", now.Add(-3*time.Minute))) // per-org copy: dropped
	e.db.InsertEvent(t, ev(3, 1107, "u1", "o1", now.Add(-2*time.Minute))) // excluded type
	e.db.InsertEvent(t, ev(4, 1500, "u2", "o1", now.Add(-time.Minute)))   // org event: kept

	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	lines := e.lines(t)
	assert.Equal(t, "UserLoggedIn", lines[0]["event_name"])
	assert.Equal(t, "OrganizationUserInvited", lines[1]["event_name"])
	assert.Equal(t, map[string]any{"cluster": "prod"}, lines[0]["labels"])

	// Filtered-out events are remembered too: not evaluated again
	assert.True(t, e.p.st.IsSeen(vwtest.UUID(3)))

	inc := baseConfig()
	inc.Filter.Include = []string{"UserFailedLogIn"}
	e2 := newEnv(t, inc)
	e2.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-time.Minute)))
	e2.db.InsertEvent(t, ev(2, 1005, "u1", "", now.Add(-time.Minute)))
	n, err = e2.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	bad := baseConfig()
	bad.Filter.Include = []string{"NoSuchEvent"}
	_, err = NewPoller(e.db.RO, bad, time.Second, &state.Memory{}, NewWriter(&bytes.Buffer{}), prometheus.NewRegistry())
	assert.ErrorContains(t, err, "NoSuchEvent")
}

type failingSink struct{ fail bool }

func (f *failingSink) Write([][]byte) error {
	if f.fail {
		return errors.New("disk full")
	}
	return nil
}
func (f *failingSink) Name() string { return "failing" }

func TestSinkFailureIsRetried(t *testing.T) {
	e := newEnv(t, baseConfig())
	sink := &failingSink{fail: true}
	p, err := NewPoller(e.db.RO, baseConfig(), time.Second, &state.Memory{}, sink, prometheus.NewRegistry())
	require.NoError(t, err)
	p.now = func() time.Time { return now }
	require.NoError(t, p.Init(context.Background()))
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-time.Minute)))

	_, err = p.Poll(context.Background())
	require.ErrorContains(t, err, "disk full")
	assert.False(t, p.st.IsSeen(vwtest.UUID(1)), "not marked as exported")
	assert.Equal(t, 1.0, testutil.ToFloat64(p.metrics.errors.WithLabelValues("sink")))

	sink.fail = false
	n, err := p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "retried at the next poll")
}

func TestBeginningIsClampedToEpoch(t *testing.T) {
	e := newEnv(t, baseConfig())
	assert.True(t, e.p.st.Cursor.IsZero())
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", time.Unix(10, 0)))
	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestStartFromNowAndQueryError(t *testing.T) {
	cfg := baseConfig()
	cfg.StartFrom = config.StartNow
	cfg.LateWindow = 0
	e := newEnv(t, cfg)
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", now.Add(-time.Minute)))
	n, err := e.p.Poll(context.Background())
	require.NoError(t, err)
	assert.Zero(t, n, "history before start is not exported")

	e.db.Exec(t, "DROP TABLE event")
	_, err = e.p.Poll(context.Background())
	assert.ErrorContains(t, err, "query events")
}

func TestRunAndFileSink(t *testing.T) {
	e := newEnv(t, baseConfig())
	path := filepath.Join(t.TempDir(), "events.jsonl")
	p, err := NewPoller(e.db.RO, baseConfig(), time.Second, &state.Memory{}, &File{Path: path}, prometheus.NewRegistry())
	require.NoError(t, err)
	e.db.InsertEvent(t, ev(1, 1000, "u1", "", time.Now().Add(-time.Minute)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- p.Run(ctx) }()
	require.Eventually(t, func() bool {
		data, _ := os.ReadFile(path)
		return strings.Contains(string(data), "UserLoggedIn")
	}, 3*time.Second, 10*time.Millisecond)
	cancel()
	require.NoError(t, <-done)
	assert.Equal(t, "file:"+path, p.sink.Name())

	bad := &File{Path: filepath.Join(t.TempDir(), "missing", "x.jsonl")}
	assert.Error(t, bad.Write([][]byte{[]byte("{}")}))
}

type failingStore struct{ state.Memory }

func (f *failingStore) Load(context.Context) (*state.State, bool, error) {
	return nil, false, errors.New("forbidden")
}

func TestInitFailure(t *testing.T) {
	e := newEnv(t, baseConfig())
	p, err := NewPoller(e.db.RO, baseConfig(), time.Second, &failingStore{}, NewWriter(&bytes.Buffer{}), prometheus.NewRegistry())
	require.NoError(t, err)
	assert.ErrorContains(t, p.Run(context.Background()), "forbidden")
	assert.False(t, p.Ready())
}
