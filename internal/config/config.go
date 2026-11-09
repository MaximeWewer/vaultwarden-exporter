// Package config loads the exporter configuration.
// Priority: environment variables > YAML file > defaults.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

// Event output types
const (
	OutputStdout = "stdout"
	OutputFile   = "file"
	OutputSyslog = "syslog"
)

// Syslog message formats
const (
	SyslogRFC3164 = "rfc3164"
	SyslogRFC5424 = "rfc5424"
)

// Event state backends
const (
	StateFile       = "file"
	StateKubernetes = "kubernetes"
	StateMemory     = "memory"
)

// Event start positions, used when no state was saved yet
const (
	StartNow       = "now"
	StartBeginning = "beginning"
)

// Config is the exporter configuration
type Config struct {
	Database DatabaseConfig `yaml:"database" json:"database"`
	Server   ServerConfig   `yaml:"server" json:"server"`
	Logging  LoggingConfig  `yaml:"logging" json:"logging"`
	Metrics  MetricsConfig  `yaml:"metrics" json:"metrics"`
	Events   EventsConfig   `yaml:"events" json:"events"`
}

// DatabaseConfig is the connection to the Vaultwarden database
type DatabaseConfig struct {
	// URL in the Vaultwarden DATABASE_URL format: postgresql://, mysql://,
	// sqlite:// or a sqlite file path. Use a read-only account.
	URL string `yaml:"url" json:"url"`
	// URLFile reads the URL from a file (mounted secret), used when URL is empty
	URLFile string `yaml:"url_file" json:"url_file"`
	// MaxOpenConns bounds the connections the exporter keeps to the database
	MaxOpenConns int `yaml:"max_open_conns" json:"max_open_conns"`
	// QueryTimeout bounds each query
	QueryTimeout time.Duration `yaml:"query_timeout" json:"query_timeout"`
}

// ServerConfig is the HTTP server exposing /metrics, /healthz and /readyz
type ServerConfig struct {
	Address       string        `yaml:"address" json:"address"`
	Port          int           `yaml:"port" json:"port"`
	ReadTimeout   time.Duration `yaml:"read_timeout" json:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout" json:"write_timeout"`
	WebConfigFile string        `yaml:"web_config_file" json:"web_config_file"`
}

// LoggingConfig configures the diagnostic logs (stderr)
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

// MetricsConfig configures the Prometheus metrics computed from the database
type MetricsConfig struct {
	// Enabled is a pointer so that an explicit false in YAML is kept (default true)
	Enabled *bool `yaml:"enabled" json:"enabled"`
	// RefreshInterval is the period of the database queries. Scrapes read the
	// last snapshot: the database load does not depend on the scrape rate.
	RefreshInterval time.Duration `yaml:"refresh_interval" json:"refresh_interval"`
}

// EventsConfig configures the audit event stream
type EventsConfig struct {
	Enabled      bool          `yaml:"enabled" json:"enabled"`
	PollInterval time.Duration `yaml:"poll_interval" json:"poll_interval"`
	BatchSize    int           `yaml:"batch_size" json:"batch_size"`
	// LateWindow is how far back each poll looks for events stored late with an
	// older timestamp (clients upload some events afterwards, e.g. item viewed)
	LateWindow time.Duration `yaml:"late_window" json:"late_window"`
	// StartFrom is used on the first start, before any state was saved
	StartFrom string       `yaml:"start_from" json:"start_from"`
	Output    OutputConfig `yaml:"output" json:"output"`
	State     StateConfig  `yaml:"state" json:"state"`
	Labels    LabelsConfig `yaml:"labels" json:"labels"`
	Filter    EventFilter  `yaml:"filter" json:"filter"`
}

// OutputConfig is where the event JSON lines are written
type OutputConfig struct {
	Type   string       `yaml:"type" json:"type"` // stdout, file, syslog
	Path   string       `yaml:"path" json:"path"` // file output
	Syslog SyslogConfig `yaml:"syslog" json:"syslog"`
}

// SyslogConfig configures remote syslog output with the event JSON as MSG.
type SyslogConfig struct {
	Address  string        `yaml:"address" json:"address"`     // host:port
	Protocol string        `yaml:"protocol" json:"protocol"`   // tcp, udp or tls
	Format   string        `yaml:"format" json:"format"`       // rfc3164 or rfc5424
	Timeout  time.Duration `yaml:"timeout" json:"timeout"`     // per batch, including dialing
	CAFile   string        `yaml:"ca_file" json:"ca_file"`     // TLS PEM trust bundle; empty uses system roots
	CertFile string        `yaml:"cert_file" json:"cert_file"` // TLS client certificate (mutual TLS)
	KeyFile  string        `yaml:"key_file" json:"key_file"`   // TLS client private key (mutual TLS)
}

// StateConfig is where the cursor is persisted between restarts
type StateConfig struct {
	Backend   string `yaml:"backend" json:"backend"` // file, kubernetes, memory
	Path      string `yaml:"path" json:"path"`
	ConfigMap string `yaml:"configmap" json:"configmap"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

// LabelsConfig adds static fields to every event (e.g. cluster, environment)
type LabelsConfig map[string]string

// EventFilter selects the exported events by name (Vaultwarden EventType)
type EventFilter struct {
	Include []string `yaml:"include" json:"include"`
	Exclude []string `yaml:"exclude" json:"exclude"`
	// OrgCopies controls the per-organization copies of user events (a login
	// is stored once without organization and once per organization of the
	// user): "all" keeps every copy, "none" keeps only the copy without
	// organization.
	OrgCopies string `yaml:"org_copies" json:"org_copies"`
}

// MetricsEnabled reports whether the metrics are computed (default true)
func (c *Config) MetricsEnabled() bool {
	return c.Metrics.Enabled == nil || *c.Metrics.Enabled
}

// Redacted returns a copy safe to log: the database password is masked
func (c *Config) Redacted() Config {
	out := *c
	out.Database.URL = RedactURL(c.Database.URL)
	return out
}

// RedactURL masks the password of a database URL
func RedactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	if _, ok := u.User.Password(); ok {
		u.User = url.UserPassword(u.User.Username(), "xxxxx")
	}
	return u.String()
}

// LoadFromYamlWithEnvOverrides loads base config from YAML, then overrides with environment variables.
// Any error (missing file, invalid YAML, unknown key, invalid env value) is fatal.
func LoadFromYamlWithEnvOverrides(path string) (*Config, error) {
	cfg, err := readYamlFile(path)
	if err != nil {
		return nil, err
	}
	return finish(cfg)
}

// LoadFromEnvVarsOnly loads configuration from environment variables only (no YAML file)
func LoadFromEnvVarsOnly() (*Config, error) {
	return finish(&Config{})
}

func finish(cfg *Config) (*Config, error) {
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}
	ApplyDefaults(cfg)
	if err := resolveURLFile(cfg); err != nil {
		return nil, err
	}
	if err := Validate(cfg); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	return cfg, nil
}

// readYamlFile parses a YAML file strictly: unknown keys are rejected
func readYamlFile(path string) (*Config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator-provided -config flag
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.UnmarshalWithOptions(data, cfg, yaml.DisallowUnknownField()); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config file %s: %w", path, err)
	}
	return cfg, nil
}

// resolveURLFile reads the database URL from database.url_file when database.url is empty
func resolveURLFile(cfg *Config) error {
	if cfg.Database.URL != "" || cfg.Database.URLFile == "" {
		return nil
	}
	data, err := os.ReadFile(cfg.Database.URLFile) //nolint:gosec // operator-provided secret path
	if err != nil {
		return fmt.Errorf("failed to read database.url_file: %w", err)
	}
	cfg.Database.URL = strings.TrimSpace(string(data))
	return nil
}

// envPrefix prefixes every environment variable of the exporter
const envPrefix = "VAULTWARDEN_EXPORTER_"

// applyEnvOverrides reads the VAULTWARDEN_EXPORTER_* variables. DATABASE_URL
// (the Vaultwarden variable) is accepted as a fallback for the database URL.
func applyEnvOverrides(cfg *Config) error {
	e := &envReader{}
	if v, ok := os.LookupEnv("DATABASE_URL"); ok && v != "" {
		cfg.Database.URL = v
	}
	e.string("DATABASE_URL", &cfg.Database.URL)
	e.string("DATABASE_URL_FILE", &cfg.Database.URLFile)
	e.int("DATABASE_MAX_OPEN_CONNS", &cfg.Database.MaxOpenConns)
	e.duration("DATABASE_QUERY_TIMEOUT", &cfg.Database.QueryTimeout)

	e.string("ADDRESS", &cfg.Server.Address)
	e.int("PORT", &cfg.Server.Port)
	e.duration("READ_TIMEOUT", &cfg.Server.ReadTimeout)
	e.duration("WRITE_TIMEOUT", &cfg.Server.WriteTimeout)
	e.string("WEB_CONFIG_FILE", &cfg.Server.WebConfigFile)

	e.string("LOG_LEVEL", &cfg.Logging.Level)
	e.string("LOG_FORMAT", &cfg.Logging.Format)

	e.boolPtr("METRICS_ENABLED", &cfg.Metrics.Enabled)
	e.duration("METRICS_REFRESH_INTERVAL", &cfg.Metrics.RefreshInterval)

	e.bool("EVENTS_ENABLED", &cfg.Events.Enabled)
	e.duration("EVENTS_POLL_INTERVAL", &cfg.Events.PollInterval)
	e.int("EVENTS_BATCH_SIZE", &cfg.Events.BatchSize)
	e.duration("EVENTS_LATE_WINDOW", &cfg.Events.LateWindow)
	e.string("EVENTS_START_FROM", &cfg.Events.StartFrom)
	e.string("EVENTS_OUTPUT", &cfg.Events.Output.Type)
	e.string("EVENTS_OUTPUT_PATH", &cfg.Events.Output.Path)
	e.string("EVENTS_SYSLOG_ADDRESS", &cfg.Events.Output.Syslog.Address)
	e.string("EVENTS_SYSLOG_PROTOCOL", &cfg.Events.Output.Syslog.Protocol)
	e.string("EVENTS_SYSLOG_FORMAT", &cfg.Events.Output.Syslog.Format)
	e.duration("EVENTS_SYSLOG_TIMEOUT", &cfg.Events.Output.Syslog.Timeout)
	e.string("EVENTS_SYSLOG_CA_FILE", &cfg.Events.Output.Syslog.CAFile)
	e.string("EVENTS_SYSLOG_CERT_FILE", &cfg.Events.Output.Syslog.CertFile)
	e.string("EVENTS_SYSLOG_KEY_FILE", &cfg.Events.Output.Syslog.KeyFile)
	e.string("EVENTS_STATE_BACKEND", &cfg.Events.State.Backend)
	e.string("EVENTS_STATE_PATH", &cfg.Events.State.Path)
	e.string("EVENTS_STATE_CONFIGMAP", &cfg.Events.State.ConfigMap)
	e.string("EVENTS_STATE_NAMESPACE", &cfg.Events.State.Namespace)
	e.labels("EVENTS_LABELS", &cfg.Events.Labels)
	e.list("EVENTS_INCLUDE", &cfg.Events.Filter.Include)
	e.list("EVENTS_EXCLUDE", &cfg.Events.Filter.Exclude)
	e.string("EVENTS_ORG_COPIES", &cfg.Events.Filter.OrgCopies)

	if len(e.errs) > 0 {
		return fmt.Errorf("invalid environment configuration: %w", errors.Join(e.errs...))
	}
	return nil
}

// envReader reads typed environment variables and accumulates parse errors
type envReader struct {
	errs []error
}

func (e *envReader) lookup(name string) (string, string, bool) {
	full := envPrefix + name
	if v, ok := os.LookupEnv(full); ok && v != "" {
		return v, full, true
	}
	return "", full, false
}

func (e *envReader) fail(name, value string, err error) {
	e.errs = append(e.errs, fmt.Errorf("invalid value %q for %s: %w", value, name, err))
}

func (e *envReader) string(name string, dst *string) {
	if v, _, ok := e.lookup(name); ok {
		*dst = v
	}
}

func (e *envReader) list(name string, dst *[]string) {
	if v, _, ok := e.lookup(name); ok {
		*dst = parseCommaSeparated(v)
	}
}

func (e *envReader) int(name string, dst *int) {
	if v, full, ok := e.lookup(name); ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			e.fail(full, v, err)
			return
		}
		*dst = n
	}
}

func (e *envReader) bool(name string, dst *bool) {
	if v, full, ok := e.lookup(name); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			e.fail(full, v, err)
			return
		}
		*dst = b
	}
}

func (e *envReader) boolPtr(name string, dst **bool) {
	if v, full, ok := e.lookup(name); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			e.fail(full, v, err)
			return
		}
		*dst = &b
	}
}

func (e *envReader) duration(name string, dst *time.Duration) {
	if v, full, ok := e.lookup(name); ok {
		d, err := time.ParseDuration(v)
		if err != nil {
			e.fail(full, v, err)
			return
		}
		*dst = d
	}
}

func (e *envReader) labels(name string, dst *LabelsConfig) {
	v, full, ok := e.lookup(name)
	if !ok {
		return
	}
	labels := make(LabelsConfig)
	for _, item := range parseCommaSeparated(v) {
		key, value, found := strings.Cut(item, "=")
		if !found || strings.TrimSpace(key) == "" {
			e.fail(full, v, fmt.Errorf("label %q must be key=value", item))
			return
		}
		labels[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	*dst = labels
}

// parseCommaSeparated splits a comma separated list, trimming and dropping empty items
func parseCommaSeparated(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
