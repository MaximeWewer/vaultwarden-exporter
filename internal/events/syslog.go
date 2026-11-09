package events

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
)

const syslogAppName = "vaultwarden-exporter"

// rfc5424Time is RFC3339 with the 6-digit TIME-SECFRAC limit of RFC5424
const rfc5424Time = "2006-01-02T15:04:05.000000Z07:00"

// Syslog sends the event JSON as the MSG of a user.info message, formatted
// as RFC3164 or RFC5424. A connection is opened per batch so that a failed
// poll can reconnect. TLS files are re-read for every batch, so rotated
// certificates are picked up without a restart.
type Syslog struct {
	cfg      config.SyslogConfig
	hostname string
	procID   string
}

func NewSyslog(cfg config.SyslogConfig) (*Syslog, error) {
	s := &Syslog{cfg: cfg, hostname: syslogHostname(), procID: strconv.Itoa(os.Getpid())}
	// Fail fast at startup on unreadable or invalid TLS files
	if _, err := s.tlsConfig(); err != nil {
		return nil, err
	}
	return s, nil
}

// syslogHostname returns the host name if it is valid in both formats:
// 1 to 255 printable US-ASCII characters without spaces.
func syslogHostname() string {
	hostname, _ := os.Hostname()
	if hostname == "" || len(hostname) > 255 {
		return "localhost"
	}
	for i := range len(hostname) {
		if hostname[i] < 33 || hostname[i] > 126 {
			return "localhost"
		}
	}
	return hostname
}

// tlsConfig builds the client TLS configuration, nil for tcp and udp
func (s *Syslog) tlsConfig() (*tls.Config, error) {
	if s.cfg.Protocol != "tls" {
		return nil, nil
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.cfg.CAFile != "" {
		pem, err := os.ReadFile(s.cfg.CAFile) //nolint:gosec // operator-provided CA bundle
		if err != nil {
			return nil, fmt.Errorf("read syslog CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("syslog CA file contains no certificates")
		}
		tlsConfig.RootCAs = pool
	}
	if s.cfg.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load syslog client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

func (s *Syslog) Write(lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	tlsConfig, err := s.tlsConfig()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(s.cfg.Timeout)
	dialer := net.Dialer{Deadline: deadline}
	var conn net.Conn
	if tlsConfig != nil {
		conn, err = tls.DialWithDialer(&dialer, "tcp", s.cfg.Address, tlsConfig)
	} else {
		conn, err = dialer.Dial(s.cfg.Protocol, s.cfg.Address)
	}
	if err != nil {
		return fmt.Errorf("connect to %s: %w", s.Name(), err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set syslog write deadline: %w", err)
	}
	for _, line := range lines {
		message := s.format(time.Now(), line)
		switch s.cfg.Protocol {
		case "tls":
			message = fmt.Sprintf("%d %s", len(message), message)
		case "tcp":
			message += "\n"
		}
		n, err := io.WriteString(conn, message)
		if err != nil {
			return fmt.Errorf("write to %s: %w", s.Name(), err)
		}
		if n != len(message) {
			return fmt.Errorf("write to %s: %w", s.Name(), io.ErrShortWrite)
		}
	}
	return nil
}

// format builds a user.info (PRI 14) message carrying the event JSON
func (s *Syslog) format(now time.Time, line []byte) string {
	if s.cfg.Format == config.SyslogRFC5424 {
		// VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
		return fmt.Sprintf("<14>1 %s %s %s %s - - %s",
			now.UTC().Format(rfc5424Time), s.hostname, syslogAppName, s.procID, line)
	}
	return fmt.Sprintf("<14>%s %s %s: %s", now.Format(time.Stamp), s.hostname, syslogAppName, line)
}

func (s *Syslog) Name() string {
	return "syslog:" + s.cfg.Protocol + "://" + s.cfg.Address
}
