package events

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/maximewewer/vaultwarden-exporter/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyslogTCP(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(3*time.Second)))
	sink, err := NewSyslog(config.SyslogConfig{Address: listener.Addr().String(), Protocol: "tcp", Timeout: time.Second})
	require.NoError(t, err)
	lines := [][]byte{[]byte(`{"event_id":"one","actor_name":"Alice\nBob"}`), []byte(`{"event_id":"two"}`)}
	done := make(chan error, 1)
	go func() { done <- sink.Write(lines) }()
	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	scanner := bufio.NewScanner(conn)
	for _, line := range lines {
		require.True(t, scanner.Scan(), "missing event")
		assertSyslogMessage(t, scanner.Text(), line)
	}
	assert.False(t, scanner.Scan(), "connection closes after the batch")
	require.NoError(t, scanner.Err())
	require.NoError(t, <-done)
	assert.Equal(t, "syslog:tcp://"+listener.Addr().String(), sink.Name())
}

func assertSyslogMessage(t *testing.T, message string, line []byte) {
	t.Helper()
	assert.Regexp(t, `^<14>[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ vaultwarden-exporter: `, message)
	_, payload, found := strings.Cut(message, "vaultwarden-exporter: ")
	require.True(t, found)
	assert.Equal(t, string(line), payload, "event JSON is preserved")
	assert.True(t, json.Valid([]byte(payload)))
}

func TestSyslogUDP(t *testing.T) {
	t.Parallel()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	require.NoError(t, listener.SetReadDeadline(time.Now().Add(3*time.Second)))
	sink, err := NewSyslog(config.SyslogConfig{Address: listener.LocalAddr().String(), Protocol: "udp", Timeout: time.Second})
	require.NoError(t, err)
	lines := [][]byte{[]byte(`{"event_id":"one"}`), []byte(`{"event_id":"two"}`)}
	require.NoError(t, sink.Write(lines))
	for _, line := range lines {
		buf := make([]byte, 4096)
		n, _, err := listener.ReadFrom(buf)
		require.NoError(t, err)
		assertSyslogMessage(t, string(buf[:n]), line)
	}
}

func TestSyslogFailureAndRetry(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	sink, err := NewSyslog(config.SyslogConfig{Address: address, Protocol: "tcp", Timeout: time.Second})
	require.NoError(t, err)
	require.NoError(t, sink.Write(nil), "empty batches need no connection")
	lines := [][]byte{[]byte(`{"event_id":"retry"}`)}
	require.ErrorContains(t, sink.Write(lines), "connect to syslog:tcp://")

	tcpListener, err := net.Listen("tcp", address)
	require.NoError(t, err)
	defer tcpListener.Close()
	require.NoError(t, tcpListener.(*net.TCPListener).SetDeadline(time.Now().Add(3*time.Second)))
	require.NoError(t, sink.Write(lines))
	conn, err := tcpListener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	scanner := bufio.NewScanner(conn)
	require.True(t, scanner.Scan())
	assertSyslogMessage(t, scanner.Text(), lines[0])
}

func TestSyslogWriteDeadline(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	require.NoError(t, listener.(*net.TCPListener).SetDeadline(time.Now().Add(3*time.Second)))
	sink, err := NewSyslog(config.SyslogConfig{Address: listener.Addr().String(), Protocol: "tcp", Timeout: 100 * time.Millisecond})
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- sink.Write([][]byte{[]byte(strings.Repeat("x", 32<<20))}) }()
	conn, err := listener.Accept()
	require.NoError(t, err)
	defer conn.Close()
	// The receiver accepts but never reads, so a blocked write must time out.
	select {
	case err := <-done:
		var netErr net.Error
		require.ErrorAs(t, err, &netErr)
		assert.True(t, netErr.Timeout())
	case <-time.After(3 * time.Second):
		t.Fatal("syslog write did not respect its deadline")
	}
}

func TestSyslogOversizedDatagramFails(t *testing.T) {
	t.Parallel()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	sink, err := NewSyslog(config.SyslogConfig{Address: listener.LocalAddr().String(), Protocol: "udp", Timeout: time.Second})
	require.NoError(t, err)
	assert.ErrorContains(t, sink.Write([][]byte{[]byte(strings.Repeat("x", 65536))}), "write to syslog:udp://")
}

func TestSyslogTLS(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		host    string
		trust   bool
		expired bool
		wantErr string
	}{
		{name: "trusted", host: "127.0.0.1", trust: true},
		{name: "untrusted", host: "127.0.0.1", wantErr: "unknown authority"},
		{name: "wrong hostname", host: "other.example.com", trust: true, wantErr: "IP SAN"},
		{name: "expired", host: "127.0.0.1", trust: true, expired: true, wantErr: "expired"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cert, caFile := syslogTLSCertificate(t, tc.host, tc.expired)
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12,
			})
			require.NoError(t, err)
			defer listener.Close()
			type received struct {
				data []byte
				err  error
			}
			done := make(chan received, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- received{err: err}
					return
				}
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
					done <- received{err: err}
					return
				}
				data, err := io.ReadAll(conn)
				done <- received{data: data, err: err}
			}()
			cfg := config.SyslogConfig{Address: listener.Addr().String(), Protocol: "tls", Timeout: 5 * time.Second}
			if tc.trust {
				cfg.CAFile = caFile
			}
			sink, err := NewSyslog(cfg)
			require.NoError(t, err)
			lines := [][]byte{[]byte(`{"actor_name":"Алиса"}`), []byte(`{"event_id":"two"}`)}
			err = sink.Write(lines)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				var verificationError *tls.CertificateVerificationError
				assert.ErrorAs(t, err, &verificationError)
			} else {
				require.NoError(t, err)
			}
			select {
			case result := <-done:
				if tc.wantErr != "" {
					assert.Empty(t, result.data, "no events sent to an unverified receiver")
					return
				}
				require.NoError(t, result.err)
				reader := bufio.NewReader(strings.NewReader(string(result.data)))
				for _, line := range lines {
					prefix, err := reader.ReadString(' ')
					require.NoError(t, err)
					size, err := strconv.Atoi(strings.TrimSpace(prefix))
					require.NoError(t, err)
					require.Positive(t, size)
					require.Less(t, size, 4096)
					message := make([]byte, size)
					_, err = io.ReadFull(reader, message)
					require.NoError(t, err)
					assertSyslogMessage(t, string(message), line)
				}
				_, err := reader.ReadByte()
				assert.ErrorIs(t, err, io.EOF, "no extra delimiters between octet-counted messages")
			case <-time.After(10 * time.Second):
				t.Fatal("TLS receiver did not stop")
			}
		})
	}
}

func syslogTLSCertificate(t *testing.T, host string, expired bool) (tls.Certificate, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if expired {
		template.NotAfter = time.Now().Add(-time.Minute)
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	require.NoError(t, err)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, caFile
}

func TestSyslogInvalidCA(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ca.pem")
	cfg := config.SyslogConfig{Protocol: "tls", CAFile: path}
	_, err := NewSyslog(cfg)
	assert.ErrorContains(t, err, "read syslog CA file")
	require.NoError(t, os.WriteFile(path, []byte("not a certificate"), 0o600))
	_, err = NewSyslog(cfg)
	assert.ErrorContains(t, err, "contains no certificates")
}

func TestSyslogTLSHandshakeDeadline(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	sink, err := NewSyslog(config.SyslogConfig{Address: listener.Addr().String(), Protocol: "tls", Timeout: 100 * time.Millisecond})
	require.NoError(t, err)
	// A plain listener never completes the TLS handshake.
	err = sink.Write([][]byte{[]byte(`{}`)})
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout())
}
