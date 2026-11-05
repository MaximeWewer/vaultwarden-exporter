// Package stats computes the Prometheus metrics of a Vaultwarden instance from
// its database. The queries run every refresh interval and fill a snapshot;
// scrapes only read the snapshot, so the database load does not depend on the
// number of Prometheus servers or on their scrape interval.
//
// Every query is portable (PostgreSQL, MySQL/MariaDB, SQLite) and only reads
// non-sensitive columns (types, statuses, flags, sizes): a read-only role with
// column-level grants is enough (see the README).
package stats

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/database"
	"github.com/maximewewer/vaultwarden-exporter/internal/logger"
	"github.com/maximewewer/vaultwarden-exporter/internal/vaultwarden"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "vaultwarden"

// sample is one value of a metric with its label values
type sample struct {
	desc   *prometheus.Desc
	value  float64
	labels []string
}

// query computes the samples of one metric family
type query struct {
	name string
	run  func(ctx context.Context, c *Collector) ([]sample, error)
}

// Collector is a prometheus.Collector serving the last snapshot
type Collector struct {
	db      *database.DB
	timeout time.Duration
	queries []query

	mu       sync.RWMutex
	snapshot map[string][]sample // per query, the last successful result
	ready    bool

	up          prometheus.Gauge
	lastRefresh prometheus.Gauge
	duration    prometheus.Gauge
	errors      *prometheus.CounterVec
}

var (
	descUsers = prometheus.NewDesc(namespace+"_users", "Vaultwarden user accounts.",
		[]string{"enabled", "email_verified"}, nil)
	descUsers2FA = prometheus.NewDesc(namespace+"_users_two_factor", "Users with this two-factor method enabled.",
		[]string{"method"}, nil)
	descUsersNo2FA = prometheus.NewDesc(namespace+"_users_without_two_factor", "Enabled users without any two-factor method.",
		nil, nil)
	descIncomplete2FA = prometheus.NewDesc(namespace+"_two_factor_incomplete_logins",
		"Logins that passed the password but not the second factor yet.", nil, nil)
	descOrgs    = prometheus.NewDesc(namespace+"_organizations", "Organizations.", nil, nil)
	descMembers = prometheus.NewDesc(namespace+"_organization_members", "Organization memberships.",
		[]string{"status", "role"}, nil)
	descCollections = prometheus.NewDesc(namespace+"_collections", "Organization collections.", nil, nil)
	descGroups      = prometheus.NewDesc(namespace+"_groups", "Organization groups.", nil, nil)
	descCiphers     = prometheus.NewDesc(namespace+"_ciphers", "Vault items.", []string{"type", "state"}, nil)
	descAttachments = prometheus.NewDesc(namespace+"_attachments", "Vault item attachments.", nil, nil)
	descAttachBytes = prometheus.NewDesc(namespace+"_attachments_size_bytes", "Total size of the attachments.", nil, nil)
	descSends       = prometheus.NewDesc(namespace+"_sends", "Sends.", []string{"type"}, nil)
	descDevices     = prometheus.NewDesc(namespace+"_devices", "Registered client devices.", []string{"type"}, nil)
	descEmergency   = prometheus.NewDesc(namespace+"_emergency_access", "Emergency access grants.", []string{"status"}, nil)
)

// New creates the collector and registers its own health metrics in reg
func New(db *database.DB, timeout time.Duration, reg prometheus.Registerer) (*Collector, error) {
	c := &Collector{
		db:       db,
		timeout:  timeout,
		snapshot: make(map[string][]sample),
		up: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "exporter", Name: "up",
			Help: "1 if the last metrics refresh succeeded for every query."}),
		lastRefresh: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "exporter",
			Name: "last_refresh_timestamp_seconds", Help: "Time of the last metrics refresh."}),
		duration: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Subsystem: "exporter",
			Name: "refresh_duration_seconds", Help: "Duration of the last metrics refresh."}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: namespace, Subsystem: "exporter",
			Name: "query_errors_total", Help: "Failed metrics queries."}, []string{"query"}),
	}
	c.queries = []query{
		{"users", queryUsers},
		{"users_two_factor", queryTwoFactor},
		{"users_without_two_factor", queryWithoutTwoFactor},
		{"two_factor_incomplete", countQuery(descIncomplete2FA, "SELECT COUNT(*) FROM twofactor_incomplete")},
		{"organizations", countQuery(descOrgs, "SELECT COUNT(*) FROM organizations")},
		{"organization_members", queryMembers},
		{"collections", countQuery(descCollections, "SELECT COUNT(*) FROM collections")},
		{"groups", countQuery(descGroups, "SELECT COUNT(*) FROM "+db.Quote("groups"))},
		{"ciphers", queryCiphers},
		{"attachments", queryAttachments},
		{"sends", enumQuery(descSends, vaultwarden.SendTypes, "SELECT atype, COUNT(*) FROM sends GROUP BY atype", true)},
		{"devices", enumQuery(descDevices, vaultwarden.DeviceTypes, "SELECT atype, COUNT(*) FROM devices GROUP BY atype", false)},
		{"emergency_access", enumQuery(descEmergency, vaultwarden.EmergencyAccessStatuses,
			"SELECT status, COUNT(*) FROM emergency_access GROUP BY status", true)},
	}
	for _, m := range []prometheus.Collector{c.up, c.lastRefresh, c.duration, c.errors} {
		if err := reg.Register(m); err != nil {
			return nil, err
		}
	}
	for _, q := range c.queries {
		c.errors.WithLabelValues(q.name)
	}
	return c, nil
}

// Describe implements prometheus.Collector
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{descUsers, descUsers2FA, descUsersNo2FA, descIncomplete2FA, descOrgs,
		descMembers, descCollections, descGroups, descCiphers, descAttachments, descAttachBytes, descSends,
		descDevices, descEmergency} {
		ch <- d
	}
}

// Collect implements prometheus.Collector: it serves the last snapshot
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, q := range c.queries {
		for _, s := range c.snapshot[q.name] {
			ch <- prometheus.MustNewConstMetric(s.desc, prometheus.GaugeValue, s.value, s.labels...)
		}
	}
}

// Ready reports whether a first refresh has completed
func (c *Collector) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

// Refresh runs every query and replaces the snapshot. A failed query keeps
// its previous values (a transient error does not drop the series) and marks
// the exporter down until the next successful refresh.
func (c *Collector) Refresh(ctx context.Context) error {
	start := time.Now()
	results := make(map[string][]sample, len(c.queries))
	var failed []string
	for _, q := range c.queries {
		qctx, cancel := context.WithTimeout(ctx, c.timeout)
		samples, err := q.run(qctx, c)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.errors.WithLabelValues(q.name).Inc()
			logger.Error("stats", "Metrics query failed", err, "query", q.name)
			failed = append(failed, q.name)
			continue
		}
		results[q.name] = samples
	}

	c.mu.Lock()
	for name, samples := range results {
		c.snapshot[name] = samples
	}
	c.ready = true
	c.mu.Unlock()

	elapsed := time.Since(start)
	c.duration.Set(elapsed.Seconds())
	c.lastRefresh.SetToCurrentTime()
	if len(failed) > 0 {
		c.up.Set(0)
		return fmt.Errorf("%d metrics queries failed: %v", len(failed), failed)
	}
	c.up.Set(1)
	logger.Debug("stats", "Metrics refreshed", "duration", elapsed.Round(time.Millisecond).String())
	return nil
}

// Run refreshes the snapshot every interval until ctx is cancelled
func (c *Collector) Run(ctx context.Context, interval time.Duration) error {
	_ = c.Refresh(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = c.Refresh(ctx)
		}
	}
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

func countQuery(desc *prometheus.Desc, sqlText string) func(context.Context, *Collector) ([]sample, error) {
	return func(ctx context.Context, c *Collector) ([]sample, error) {
		var n int64
		if err := c.db.QueryRowContext(ctx, sqlText).Scan(&n); err != nil {
			return nil, err
		}
		return []sample{{desc: desc, value: float64(n)}}, nil
	}
}

// enumQuery maps "SELECT code, COUNT(*) ... GROUP BY code" to one series per
// code name. With zeroFill every known code has a series, 0 when absent.
func enumQuery(desc *prometheus.Desc, names map[int]string, sqlText string, zeroFill bool) func(context.Context, *Collector) ([]sample, error) {
	return func(ctx context.Context, c *Collector) ([]sample, error) {
		counts := map[string]float64{}
		if zeroFill {
			for _, name := range names {
				counts[name] = 0
			}
		}
		err := scanRows(ctx, c.db, sqlText, nil, func(scan func(...any) error) error {
			var code, n int64
			if err := scan(&code, &n); err != nil {
				return err
			}
			counts[vaultwarden.Name(names, int(code))] += float64(n)
			return nil
		})
		if err != nil {
			return nil, err
		}
		out := make([]sample, 0, len(counts))
		for name, n := range counts {
			out = append(out, sample{desc: desc, value: n, labels: []string{name}})
		}
		return out, nil
	}
}

func queryUsers(ctx context.Context, c *Collector) ([]sample, error) {
	counts := map[[2]string]float64{}
	for _, e := range []string{"true", "false"} {
		for _, v := range []string{"true", "false"} {
			counts[[2]string{e, v}] = 0
		}
	}
	err := scanRows(ctx, c.db, `SELECT enabled, CASE WHEN verified_at IS NULL THEN 0 ELSE 1 END AS verified, COUNT(*)
		FROM users GROUP BY enabled, CASE WHEN verified_at IS NULL THEN 0 ELSE 1 END`, nil,
		func(scan func(...any) error) error {
			var enabled any
			var verified, n int64
			if err := scan(&enabled, &verified, &n); err != nil {
				return err
			}
			counts[[2]string{boolLabel(toBool(enabled)), boolLabel(verified == 1)}] += float64(n)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]sample, 0, len(counts))
	for k, n := range counts {
		out = append(out, sample{desc: descUsers, value: n, labels: []string{k[0], k[1]}})
	}
	return out, nil
}

// methodCodes is the SQL list of the two-factor method codes
func methodCodes() string {
	codes := make([]int, 0, len(vaultwarden.TwoFactorTypes))
	for code := range vaultwarden.TwoFactorTypes {
		codes = append(codes, code)
	}
	slices.Sort(codes)
	parts := make([]string, len(codes))
	for i, code := range codes {
		parts[i] = strconv.Itoa(code)
	}
	return strings.Join(parts, ",")
}

func queryTwoFactor(ctx context.Context, c *Collector) ([]sample, error) {
	counts := map[string]float64{}
	for _, name := range vaultwarden.TwoFactorTypes {
		counts[name] = 0
	}
	err := scanRows(ctx, c.db, `SELECT atype, COUNT(DISTINCT user_uuid) FROM twofactor
		WHERE enabled = ? AND atype IN (`+methodCodes()+`) GROUP BY atype`, []any{true},
		func(scan func(...any) error) error {
			var code, n int64
			if err := scan(&code, &n); err != nil {
				return err
			}
			counts[vaultwarden.Name(vaultwarden.TwoFactorTypes, int(code))] += float64(n)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]sample, 0, len(counts))
	for name, n := range counts {
		out = append(out, sample{desc: descUsers2FA, value: n, labels: []string{name}})
	}
	return out, nil
}

func queryWithoutTwoFactor(ctx context.Context, c *Collector) ([]sample, error) {
	var n int64
	err := c.db.QueryRowContext(ctx, c.db.Rebind(`SELECT COUNT(*) FROM users u WHERE u.enabled = ? AND NOT EXISTS (
		SELECT 1 FROM twofactor t WHERE t.user_uuid = u.uuid AND t.enabled = ? AND t.atype IN (`+methodCodes()+`))`),
		true, true).Scan(&n)
	if err != nil {
		return nil, err
	}
	return []sample{{desc: descUsersNo2FA, value: float64(n)}}, nil
}

func queryMembers(ctx context.Context, c *Collector) ([]sample, error) {
	counts := map[[2]string]float64{}
	for _, s := range vaultwarden.MembershipStatuses {
		for _, r := range vaultwarden.MembershipTypes {
			counts[[2]string{s, r}] = 0
		}
	}
	err := scanRows(ctx, c.db, "SELECT status, atype, COUNT(*) FROM users_organizations GROUP BY status, atype", nil,
		func(scan func(...any) error) error {
			var status, role, n int64
			if err := scan(&status, &role, &n); err != nil {
				return err
			}
			key := [2]string{vaultwarden.Name(vaultwarden.MembershipStatuses, int(status)),
				vaultwarden.Name(vaultwarden.MembershipTypes, int(role))}
			counts[key] += float64(n)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]sample, 0, len(counts))
	for k, n := range counts {
		out = append(out, sample{desc: descMembers, value: n, labels: []string{k[0], k[1]}})
	}
	return out, nil
}

func queryCiphers(ctx context.Context, c *Collector) ([]sample, error) {
	counts := map[[2]string]float64{}
	for _, t := range vaultwarden.CipherTypes {
		counts[[2]string{t, "active"}] = 0
		counts[[2]string{t, "trashed"}] = 0
	}
	err := scanRows(ctx, c.db, `SELECT atype, CASE WHEN deleted_at IS NULL THEN 0 ELSE 1 END AS trashed, COUNT(*)
		FROM ciphers GROUP BY atype, CASE WHEN deleted_at IS NULL THEN 0 ELSE 1 END`, nil,
		func(scan func(...any) error) error {
			var code, trashed, n int64
			if err := scan(&code, &trashed, &n); err != nil {
				return err
			}
			state := "active"
			if trashed == 1 {
				state = "trashed"
			}
			counts[[2]string{vaultwarden.Name(vaultwarden.CipherTypes, int(code)), state}] += float64(n)
			return nil
		})
	if err != nil {
		return nil, err
	}
	out := make([]sample, 0, len(counts))
	for k, n := range counts {
		out = append(out, sample{desc: descCiphers, value: n, labels: []string{k[0], k[1]}})
	}
	return out, nil
}

func queryAttachments(ctx context.Context, c *Collector) ([]sample, error) {
	var n, size int64
	if err := c.db.QueryRowContext(ctx, "SELECT COUNT(*), COALESCE(SUM(file_size), 0) FROM attachments").Scan(&n, &size); err != nil {
		return nil, err
	}
	return []sample{{desc: descAttachments, value: float64(n)}, {desc: descAttachBytes, value: float64(size)}}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// scanRows runs a query and calls fn for every row
func scanRows(ctx context.Context, db *database.DB, sqlText string, args []any, fn func(scan func(...any) error) error) error {
	rows, err := db.QueryContext(ctx, db.Rebind(sqlText), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows.Scan); err != nil {
			return err
		}
	}
	return rows.Err()
}

// toBool normalizes a boolean column: PostgreSQL bool, MySQL/SQLite integers
func toBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case []byte:
		return len(x) > 0 && x[0] != '0'
	case string:
		return x != "" && x != "0" && x != "false"
	default:
		return false
	}
}

func boolLabel(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
