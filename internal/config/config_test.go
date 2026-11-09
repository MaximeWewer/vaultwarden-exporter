package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestLoadFromEnvVarsOnlyDefaults(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://vw:secret@db:5432/vaultwarden")
	cfg, err := LoadFromEnvVarsOnly()
	require.NoError(t, err)

	assert.Equal(t, DefaultPort, cfg.Server.Port)
	assert.True(t, cfg.MetricsEnabled())
	assert.False(t, cfg.Events.Enabled)
	assert.Equal(t, DefaultRefreshInterval, cfg.Metrics.RefreshInterval)
	assert.Equal(t, StateFile, cfg.Events.State.Backend)
	assert.Equal(t, DefaultStatePath, cfg.Events.State.Path)
}

func TestPrefixedVariableWinsOverDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://a@db/x")
	t.Setenv("VAULTWARDEN_EXPORTER_DATABASE_URL", "postgresql://b@db/x")
	cfg, err := LoadFromEnvVarsOnly()
	require.NoError(t, err)
	assert.Equal(t, "postgresql://b@db/x", cfg.Database.URL)
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("VAULTWARDEN_EXPORTER_DATABASE_URL", "sqlite:///data/db.sqlite3")
	t.Setenv("VAULTWARDEN_EXPORTER_PORT", "9100")
	t.Setenv("VAULTWARDEN_EXPORTER_METRICS_ENABLED", "false")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_ENABLED", "true")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_POLL_INTERVAL", "5s")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_STATE_BACKEND", "kubernetes")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_LABELS", "cluster=prod, env = eu")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_INCLUDE", "UserLoggedIn,UserFailedLogIn")
	cfg, err := LoadFromEnvVarsOnly()
	require.NoError(t, err)

	assert.Equal(t, 9100, cfg.Server.Port)
	assert.False(t, cfg.MetricsEnabled())
	assert.True(t, cfg.Events.Enabled)
	assert.Equal(t, 5*time.Second, cfg.Events.PollInterval)
	assert.Equal(t, DefaultConfigMap, cfg.Events.State.ConfigMap)
	assert.Equal(t, LabelsConfig{"cluster": "prod", "env": "eu"}, cfg.Events.Labels)
	assert.Equal(t, []string{"UserLoggedIn", "UserFailedLogIn"}, cfg.Events.Filter.Include)
}

func TestInvalidEnvValuesAreAllReported(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://db/x")
	t.Setenv("VAULTWARDEN_EXPORTER_PORT", "abc")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_ENABLED", "maybe")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_POLL_INTERVAL", "soon")
	t.Setenv("VAULTWARDEN_EXPORTER_METRICS_ENABLED", "x")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_LABELS", "novalue")
	_, err := LoadFromEnvVarsOnly()
	require.Error(t, err)
	for _, name := range []string{"PORT", "EVENTS_ENABLED", "EVENTS_POLL_INTERVAL", "METRICS_ENABLED", "EVENTS_LABELS"} {
		assert.Contains(t, err.Error(), "VAULTWARDEN_EXPORTER_"+name)
	}
}

func TestYamlFileWithEnvOverride(t *testing.T) {
	p := writeFile(t, `
database:
  url: postgresql://vw_events:pw@db:5432/vaultwarden
metrics:
  enabled: false
events:
  enabled: true
  late_window: 30m
  output:
    type: file
    path: /var/log/vw/events.jsonl
  state:
    backend: memory
  labels:
    cluster: prod
`)
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_BATCH_SIZE", "50")
	cfg, err := LoadFromYamlWithEnvOverrides(p)
	require.NoError(t, err)
	assert.False(t, cfg.MetricsEnabled())
	assert.Equal(t, 30*time.Minute, cfg.Events.LateWindow)
	assert.Equal(t, OutputFile, cfg.Events.Output.Type)
	assert.Equal(t, 50, cfg.Events.BatchSize)
	assert.Equal(t, "prod", cfg.Events.Labels["cluster"])
	assert.Len(t, Warnings(cfg), 1, "memory backend warning")
}

func TestYamlUnknownKeyIsRejected(t *testing.T) {
	p := writeFile(t, "database:\n  url: x\n  passwrod: y\n")
	_, err := LoadFromYamlWithEnvOverrides(p)
	require.Error(t, err)
	_, err = LoadFromYamlWithEnvOverrides(filepath.Join(t.TempDir(), "missing.yaml"))
	require.Error(t, err)
}

func TestURLFile(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "url")
	require.NoError(t, os.WriteFile(secret, []byte("postgresql://u:p@db/vw\n"), 0o600))
	t.Setenv("VAULTWARDEN_EXPORTER_DATABASE_URL_FILE", secret)
	cfg, err := LoadFromEnvVarsOnly()
	require.NoError(t, err)
	assert.Equal(t, "postgresql://u:p@db/vw", cfg.Database.URL)

	t.Setenv("VAULTWARDEN_EXPORTER_DATABASE_URL_FILE", secret+".missing")
	_, err = LoadFromEnvVarsOnly()
	require.Error(t, err)
}

func TestValidationErrors(t *testing.T) {
	cfg := &Config{}
	f := false
	cfg.Metrics.Enabled = &f
	ApplyDefaults(cfg)
	cfg.Events.Enabled = true
	cfg.Events.BatchSize = 0
	cfg.Events.StartFrom = "yesterday"
	cfg.Events.Output.Type = OutputFile
	cfg.Events.State.Backend = "redis"
	cfg.Events.Filter = EventFilter{Include: []string{"a"}, Exclude: []string{"b"}, OrgCopies: "some"}
	cfg.Logging.Format = "xml"
	cfg.Server.Port = 70000
	err := Validate(cfg)
	require.Error(t, err)
	for _, want := range []string{"database.url", "batch_size", "start_from", "output.path", "state.backend",
		"mutually exclusive", "org_copies", "logging.format", "server.port"} {
		assert.Contains(t, err.Error(), want)
	}

	nothing := &Config{Database: DatabaseConfig{URL: "x"}}
	nothing.Metrics.Enabled = &f
	ApplyDefaults(nothing)
	assert.ErrorContains(t, Validate(nothing), "nothing to do")
}

func TestRedactURL(t *testing.T) {
	assert.Equal(t, "postgresql://vw:xxxxx@db:5432/vw", RedactURL("postgresql://vw:secret@db:5432/vw"))
	assert.Equal(t, "postgresql://vw@db/vw", RedactURL("postgresql://vw@db/vw"))
	assert.Equal(t, "/data/db.sqlite3", RedactURL("/data/db.sqlite3"))
	cfg := Config{Database: DatabaseConfig{URL: "mysql://u:p@db/vw"}}
	assert.NotContains(t, cfg.Redacted().Database.URL, ":p@")
	assert.Equal(t, "mysql://u:p@db/vw", cfg.Database.URL, "the original is untouched")
}

func TestSyslogConfiguration(t *testing.T) {
	p := writeFile(t, `
database:
  url: postgresql://vw@db/vw
events:
  enabled: true
  output:
    type: syslog
    syslog:
      address: siem.example.com:514
`)
	cfg, err := LoadFromYamlWithEnvOverrides(p)
	require.NoError(t, err)
	assert.Equal(t, OutputSyslog, cfg.Events.Output.Type)
	assert.Equal(t, SyslogConfig{Address: "siem.example.com:514", Protocol: "tcp", Format: SyslogRFC3164, Timeout: 5 * time.Second}, cfg.Events.Output.Syslog)

	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_ADDRESS", "[::1]:5514")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_PROTOCOL", "udp")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_TIMEOUT", "2s")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_FORMAT", "rfc5424")
	cfg, err = LoadFromYamlWithEnvOverrides(p)
	require.NoError(t, err)
	assert.Equal(t, SyslogConfig{Address: "[::1]:5514", Protocol: "udp", Format: SyslogRFC5424, Timeout: 2 * time.Second}, cfg.Events.Output.Syslog)
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_PROTOCOL", "tls")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_CA_FILE", "/etc/syslog/ca.pem")
	cfg, err = LoadFromYamlWithEnvOverrides(p)
	require.NoError(t, err)
	assert.Equal(t, "tls", cfg.Events.Output.Syslog.Protocol)
	assert.Equal(t, "/etc/syslog/ca.pem", cfg.Events.Output.Syslog.CAFile)
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_CERT_FILE", "/etc/syslog/tls.crt")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_KEY_FILE", "/etc/syslog/tls.key")
	cfg, err = LoadFromYamlWithEnvOverrides(p)
	require.NoError(t, err)
	assert.Equal(t, "/etc/syslog/tls.crt", cfg.Events.Output.Syslog.CertFile)
	assert.Equal(t, "/etc/syslog/tls.key", cfg.Events.Output.Syslog.KeyFile)
}

func TestSyslogValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  SyslogConfig
		want string
	}{
		{"missing address", SyslogConfig{Protocol: "tcp", Timeout: time.Second}, "address"},
		{"missing port", SyslogConfig{Address: "siem", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"empty host", SyslogConfig{Address: ":514", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"invalid port", SyslogConfig{Address: "siem:65536", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"zero port", SyslogConfig{Address: "siem:0", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"named port", SyslogConfig{Address: "siem:syslog", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"invalid host", SyslogConfig{Address: "bad\nhost:514", Protocol: "tcp", Timeout: time.Second}, "address"},
		{"invalid protocol", SyslogConfig{Address: "siem:514", Protocol: "http", Timeout: time.Second}, "protocol"},
		{"negative timeout", SyslogConfig{Address: "siem:514", Protocol: "tcp", Timeout: -time.Second}, "timeout"},
		{"CA without TLS", SyslogConfig{Address: "siem:514", Protocol: "tcp", Timeout: time.Second, CAFile: "ca.pem"}, "ca_file"},
		{"invalid format", SyslogConfig{Address: "siem:514", Protocol: "tcp", Format: "rfc5425", Timeout: time.Second}, "format"},
		{"certificate without key", SyslogConfig{Address: "siem:514", Protocol: "tls", Timeout: time.Second, CertFile: "tls.crt"}, "cert_file and key_file"},
		{"key without certificate", SyslogConfig{Address: "siem:514", Protocol: "tls", Timeout: time.Second, KeyFile: "tls.key"}, "cert_file and key_file"},
		{"client certificate without TLS", SyslogConfig{Address: "siem:514", Protocol: "tcp", Timeout: time.Second, CertFile: "tls.crt", KeyFile: "tls.key"}, "cert_file requires"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{Database: DatabaseConfig{URL: "postgresql://db/vw"}}
			ApplyDefaults(cfg)
			cfg.Events.Enabled = true
			cfg.Events.Output = OutputConfig{Type: OutputSyslog, Syslog: tc.cfg}
			assert.ErrorContains(t, Validate(cfg), "events.output.syslog."+tc.want)
		})
	}
}
