package config

import "time"

// Default values
const (
	DefaultPort            = 9776
	DefaultMaxOpenConns    = 2
	DefaultQueryTimeout    = 15 * time.Second
	DefaultReadTimeout     = 10 * time.Second
	DefaultWriteTimeout    = 10 * time.Second
	DefaultRefreshInterval = 60 * time.Second
	DefaultPollInterval    = 30 * time.Second
	DefaultBatchSize       = 500
	DefaultLateWindow      = time.Hour
	DefaultStatePath       = "/var/lib/vaultwarden-exporter/state.json"
	DefaultConfigMap       = "vaultwarden-exporter-state"
	DefaultOrgCopies       = "all"
)

// ApplyDefaults fills every unset field
func ApplyDefaults(cfg *Config) {
	if cfg.Database.MaxOpenConns == 0 {
		cfg.Database.MaxOpenConns = DefaultMaxOpenConns
	}
	if cfg.Database.QueryTimeout == 0 {
		cfg.Database.QueryTimeout = DefaultQueryTimeout
	}

	if cfg.Server.Address == "" {
		cfg.Server.Address = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = DefaultPort
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = DefaultReadTimeout
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = DefaultWriteTimeout
	}

	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "json"
	}

	if cfg.Metrics.RefreshInterval == 0 {
		cfg.Metrics.RefreshInterval = DefaultRefreshInterval
	}

	ev := &cfg.Events
	if ev.PollInterval == 0 {
		ev.PollInterval = DefaultPollInterval
	}
	if ev.BatchSize == 0 {
		ev.BatchSize = DefaultBatchSize
	}
	if ev.LateWindow == 0 {
		ev.LateWindow = DefaultLateWindow
	}
	if ev.StartFrom == "" {
		ev.StartFrom = StartNow
	}
	if ev.Output.Type == "" {
		ev.Output.Type = OutputStdout
	}
	if ev.Output.Syslog.Protocol == "" {
		ev.Output.Syslog.Protocol = "tcp"
	}
	if ev.Output.Syslog.Format == "" {
		ev.Output.Syslog.Format = SyslogRFC3164
	}
	if ev.Output.Syslog.Timeout == 0 {
		ev.Output.Syslog.Timeout = 5 * time.Second
	}
	if ev.State.Backend == "" {
		ev.State.Backend = StateFile
	}
	if ev.State.Backend == StateFile && ev.State.Path == "" {
		ev.State.Path = DefaultStatePath
	}
	if ev.State.Backend == StateKubernetes && ev.State.ConfigMap == "" {
		ev.State.ConfigMap = DefaultConfigMap
	}
	if ev.Filter.OrgCopies == "" {
		ev.Filter.OrgCopies = DefaultOrgCopies
	}
}
