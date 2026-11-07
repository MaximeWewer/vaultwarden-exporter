package events

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
)

// Syslog sends the event JSON as the MSG of an RFC3164 user.info message.
// A connection is opened per batch so that a failed poll can reconnect.
type Syslog struct {
	cfg       config.SyslogConfig
	hostname  string
	tlsConfig *tls.Config
}

func NewSyslog(cfg config.SyslogConfig) (*Syslog, error) {
	hostname, _ := os.Hostname()
	if hostname == "" || strings.ContainsAny(hostname, " \t\r\n") {
		hostname = "localhost"
	}
	s := &Syslog{cfg: cfg, hostname: hostname}
	if cfg.Protocol == "tls" {
		s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.CAFile != "" {
			pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // operator-provided CA bundle
			if err != nil {
				return nil, fmt.Errorf("read syslog CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("syslog CA file contains no certificates")
			}
			s.tlsConfig.RootCAs = pool
		}
	}
	return s, nil
}

func (s *Syslog) Write(lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	deadline := time.Now().Add(s.cfg.Timeout)
	dialer := net.Dialer{Deadline: deadline}
	var conn net.Conn
	var err error
	if s.cfg.Protocol == "tls" {
		conn, err = tls.DialWithDialer(&dialer, "tcp", s.cfg.Address, s.tlsConfig)
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
		message := fmt.Sprintf("<14>%s %s vaultwarden-exporter: %s", time.Now().Format(time.Stamp), s.hostname, line)
		// TLS uses octet counting; plain TCP keeps newline framing.
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

func (s *Syslog) Name() string {
	return "syslog:" + s.cfg.Protocol + "://" + s.cfg.Address
}
