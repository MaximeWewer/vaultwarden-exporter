package events

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/maximewewer/vaultwarden-exporter/internal/database"
	"github.com/maximewewer/vaultwarden-exporter/internal/logger"
	"github.com/maximewewer/vaultwarden-exporter/internal/state"
	"github.com/maximewewer/vaultwarden-exporter/internal/vaultwarden"
	"github.com/prometheus/client_golang/prometheus"
)

// Poller reads the new events of the database and writes them to a sink.
//
// Ordering by date alone would miss events stored late: clients upload some
// events afterwards with their own timestamp (item viewed, password copied).
// Each poll therefore re-reads the late-arrival window [cursor - window, now],
// page by page in (event_date, uuid) order, and skips the events already
// exported (kept in the state). Delivery is at least once: the state is saved
// after each page written, a crash in between re-emits that page.
type Poller struct {
	db      *database.DB
	cfg     config.EventsConfig
	timeout time.Duration
	store   state.Store
	sink    Sink
	now     func() time.Time

	include map[int]bool
	exclude map[int]bool

	st      *state.State
	ready   atomic.Bool
	metrics *pollerMetrics
}

type pollerMetrics struct {
	events     *prometheus.CounterVec
	errors     *prometheus.CounterVec
	cursor     prometheus.Gauge
	lastPoll   prometheus.Gauge
	seen       prometheus.Gauge
	pollLength prometheus.Gauge
}

func newPollerMetrics(reg prometheus.Registerer) (*pollerMetrics, error) {
	m := &pollerMetrics{
		events: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "vaultwarden", Name: "audit_events_total",
			Help: "Audit events exported since the exporter started, by event name."}, []string{"event_name"}),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{Namespace: "vaultwarden", Subsystem: "exporter",
			Name: "events_errors_total", Help: "Event stream errors, by stage (query, sink, state)."}, []string{"stage"}),
		cursor: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "vaultwarden", Subsystem: "exporter",
			Name: "events_cursor_timestamp_seconds", Help: "Date of the newest exported event."}),
		lastPoll: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "vaultwarden", Subsystem: "exporter",
			Name: "events_last_poll_timestamp_seconds", Help: "Time of the last successful poll."}),
		seen: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "vaultwarden", Subsystem: "exporter",
			Name: "events_window_size", Help: "Exported events remembered in the late-arrival window."}),
		pollLength: prometheus.NewGauge(prometheus.GaugeOpts{Namespace: "vaultwarden", Subsystem: "exporter",
			Name: "events_poll_duration_seconds", Help: "Duration of the last poll."}),
	}
	for _, c := range []prometheus.Collector{m.events, m.errors, m.cursor, m.lastPoll, m.seen, m.pollLength} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	for _, stage := range []string{"query", "sink", "state"} {
		m.errors.WithLabelValues(stage)
	}
	// Every known event name starts at 0: a counter that first appears with
	// value 1 is invisible to increase() and rate(), so a single rare event
	// (a vault export) would never show in a dashboard or fire an alert.
	for _, name := range vaultwarden.EventTypes {
		m.events.WithLabelValues(name)
	}
	return m, nil
}

// NewPoller creates a poller; Init must be called before Poll
func NewPoller(db *database.DB, cfg config.EventsConfig, timeout time.Duration, store state.Store, sink Sink,
	reg prometheus.Registerer) (*Poller, error) {
	m, err := newPollerMetrics(reg)
	if err != nil {
		return nil, err
	}
	p := &Poller{db: db, cfg: cfg, timeout: timeout, store: store, sink: sink, now: time.Now, metrics: m}
	p.include, err = eventCodes(cfg.Filter.Include)
	if err != nil {
		return nil, fmt.Errorf("events.filter.include: %w", err)
	}
	p.exclude, err = eventCodes(cfg.Filter.Exclude)
	if err != nil {
		return nil, fmt.Errorf("events.filter.exclude: %w", err)
	}
	return p, nil
}

// eventCodes converts event names to codes; an unknown name is an error
func eventCodes(names []string) (map[int]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	codes := make(map[int]bool, len(names))
	for _, n := range names {
		code, ok := vaultwarden.EventCode(n)
		if !ok {
			return nil, fmt.Errorf("unknown event name %q", n)
		}
		codes[code] = true
	}
	return codes, nil
}

// Init loads the saved state, or starts from events.start_from
func (p *Poller) Init(ctx context.Context) error {
	st, found, err := p.store.Load(ctx)
	if err != nil {
		return fmt.Errorf("load event state from %s: %w", p.store.Name(), err)
	}
	if found {
		p.st = st
		logger.Info("events", "Event state loaded", "store", p.store.Name(), "cursor", st.Cursor, "window_size", len(st.Seen))
	} else {
		start := p.now().UTC()
		if p.cfg.StartFrom == config.StartBeginning {
			start = time.Time{}
		}
		p.st = state.New(start)
		logger.Info("events", "No event state yet", "store", p.store.Name(), "start_from", p.cfg.StartFrom)
	}
	p.metrics.cursor.Set(unix(p.st.Cursor))
	p.metrics.seen.Set(float64(len(p.st.Seen)))
	p.ready.Store(true)
	return nil
}

// Poll exports the events stored since the last poll. It returns the number
// of events written.
func (p *Poller) Poll(ctx context.Context) (int, error) {
	start := time.Now()
	since := p.st.Cursor.Add(-p.cfg.LateWindow)
	// start_from=beginning: the zero time minus the window is year 0, which
	// MySQL rejects. No Vaultwarden event predates the Unix epoch.
	if since.Before(epoch) {
		since = epoch
	}
	lastDate, lastID := since, ""
	written := 0

	for {
		page, err := p.page(ctx, since, lastDate, lastID)
		if err != nil {
			p.metrics.errors.WithLabelValues("query").Inc()
			return written, fmt.Errorf("query events: %w", err)
		}
		if len(page) == 0 {
			break
		}

		lines, exported := p.encode(page)
		if len(lines) > 0 {
			if err := p.sink.Write(lines); err != nil {
				p.metrics.errors.WithLabelValues("sink").Inc()
				return written, fmt.Errorf("write events to %s: %w", p.sink.Name(), err)
			}
		}
		// The page is written: remember it (filtered-out events too, so that
		// they are not evaluated again) and move the cursor
		for _, e := range page {
			if !p.st.IsSeen(e.EventID) {
				p.st.MarkSeen(e.EventID, e.date)
			}
			if e.date.After(p.st.Cursor) {
				p.st.Cursor = e.date
			}
		}
		for _, e := range exported {
			p.metrics.events.WithLabelValues(e.EventName).Inc()
		}
		written += len(lines)
		p.st.Prune(p.st.Cursor.Add(-p.cfg.LateWindow))
		if len(lines) > 0 {
			p.save(ctx)
		}

		last := page[len(page)-1]
		lastDate, lastID = last.date, last.EventID
		if len(page) < p.cfg.BatchSize {
			break
		}
	}

	p.metrics.cursor.Set(unix(p.st.Cursor))
	p.metrics.seen.Set(float64(len(p.st.Seen)))
	p.metrics.lastPoll.SetToCurrentTime()
	p.metrics.pollLength.Set(time.Since(start).Seconds())
	return written, nil
}

// page reads up to batch events after (lastDate, lastID) and not before since
func (p *Poller) page(ctx context.Context, since, lastDate time.Time, lastID string) ([]*Event, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	q := p.db.Rebind(`SELECT ` + columns + ` ` + fromClause + `
WHERE e.event_date >= ? AND (e.event_date > ? OR (e.event_date = ? AND e.uuid > ?))
ORDER BY e.event_date, e.uuid
LIMIT ?`)
	rows, err := p.db.QueryContext(ctx, q, p.db.TimeArg(since), p.db.TimeArg(lastDate), p.db.TimeArg(lastDate), lastID, p.cfg.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Event
	for rows.Next() {
		e, err := scanEvent(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// encode returns the JSON lines of the new events that pass the filters
func (p *Poller) encode(page []*Event) ([][]byte, []*Event) {
	var lines [][]byte
	var exported []*Event
	for _, e := range page {
		if p.st.IsSeen(e.EventID) || !p.keep(e) {
			continue
		}
		if len(p.cfg.Labels) > 0 {
			e.Labels = p.cfg.Labels
		}
		line, err := json.Marshal(e)
		if err != nil {
			logger.Error("events", "Cannot encode event", err, "event_id", e.EventID)
			continue
		}
		lines = append(lines, line)
		exported = append(exported, e)
	}
	return lines, exported
}

// keep applies the event filters
func (p *Poller) keep(e *Event) bool {
	if p.include != nil && !p.include[e.EventType] {
		return false
	}
	if p.exclude != nil && p.exclude[e.EventType] {
		return false
	}
	if p.cfg.Filter.OrgCopies == "none" && e.OrgID != "" && isUserEvent(e.EventType) {
		return false
	}
	return true
}

// save persists the state; a failure is logged and retried at the next page
func (p *Poller) save(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	if err := p.store.Save(ctx, p.st); err != nil {
		p.metrics.errors.WithLabelValues("state").Inc()
		logger.Error("events", "Cannot save event state", err, "store", p.store.Name())
	}
}

// Run polls every interval until ctx is cancelled. A full poll is not delayed:
// the next one starts right away when the last page was full.
func (p *Poller) Run(ctx context.Context) error {
	if err := p.Init(ctx); err != nil {
		return err
	}
	logger.Info("events", "Event stream started", "sink", p.sink.Name(), "poll_interval", p.cfg.PollInterval,
		"late_window", p.cfg.LateWindow, "batch_size", p.cfg.BatchSize)
	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()
	for {
		n, err := p.Poll(ctx)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			logger.Error("events", "Event poll failed", err)
		} else if n > 0 {
			logger.Debug("events", "Events exported", "count", n, "cursor", p.st.Cursor)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// Ready reports whether the state is loaded
func (p *Poller) Ready() bool {
	return p.ready.Load()
}

// epoch is the lower bound of the event dates read
var epoch = time.Unix(0, 0).UTC()

func unix(t time.Time) float64 {
	if t.IsZero() {
		return 0
	}
	return float64(t.UnixMicro()) / 1e6
}
