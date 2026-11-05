//go:build integration

// Integration test against a real Vaultwarden: its migrations create the
// schema, its API produces the events, the exporter reads them back.
// Run by .github/scripts/integration.sh, which starts Vaultwarden on each
// database engine and sets:
//
//	IT_VAULTWARDEN_URL  base URL of the Vaultwarden instance
//	IT_DATABASE_URL     the same database, as the exporter sees it
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	itEmail    = "it@example.com"
	itPassword = "integration-hash"
	// Any EncString-shaped value: the server does not decrypt client data
	encString = "2.QUFBQUFBQUFBQUFBQUFBQQ==|QUFBQUFBQUFBQUFBQUFBQQ==|QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
)

func vwPost(t *testing.T, base, path, contentType string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(base+path, contentType, bytes.NewReader(body)) //nolint:gosec,noctx // test
	require.NoError(t, err)
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func login(t *testing.T, base, password string) int {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "username": {itEmail}, "password": {password},
		"scope": {"api offline_access"}, "client_id": {"web"}, "deviceType": {"10"},
		"deviceIdentifier": {"5f5b8b3e-0000-4000-8000-000000000001"}, "deviceName": {"integration"}}
	code, _ := vwPost(t, base, "/identity/connect/token", "application/x-www-form-urlencoded", []byte(form.Encode()))
	return code
}

// register creates the account through the email verification flow (with
// SMTP disabled, Vaultwarden returns the verification token directly)
func register(t *testing.T, base string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"email": itEmail, "name": "it", "receiveMarketingEmails": false})
	code, token := vwPost(t, base, "/identity/accounts/register/send-verification-email", "application/json", body)
	require.Equal(t, http.StatusOK, code, string(token))
	body, _ = json.Marshal(map[string]any{
		"emailVerificationToken": strings.Trim(strings.TrimSpace(string(token)), `"`),
		"email":                  itEmail, "masterPasswordHash": itPassword, "masterPasswordHint": nil,
		"key": encString, "kdf": 0, "kdfIterations": 600000,
		"keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString([]byte("pub")), "encryptedPrivateKey": encString},
	})
	code, resp := vwPost(t, base, "/identity/accounts/register/finish", "application/json", body)
	require.Equal(t, http.StatusOK, code, string(resp))
}

func TestIntegrationRealVaultwarden(t *testing.T) {
	base, dbURL := os.Getenv("IT_VAULTWARDEN_URL"), os.Getenv("IT_DATABASE_URL")
	if base == "" || dbURL == "" {
		t.Skip("IT_VAULTWARDEN_URL / IT_DATABASE_URL not set")
	}

	register(t, base)
	require.Equal(t, http.StatusOK, login(t, base, itPassword))
	require.Equal(t, http.StatusBadRequest, login(t, base, "wrong"))

	port := freePort(t)
	t.Setenv("DATABASE_URL", dbURL)
	t.Setenv("VAULTWARDEN_EXPORTER_ADDRESS", "127.0.0.1")
	t.Setenv("VAULTWARDEN_EXPORTER_PORT", strconv.Itoa(port))
	t.Setenv("VAULTWARDEN_EXPORTER_METRICS_REFRESH_INTERVAL", "1s")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_ENABLED", "true")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_POLL_INTERVAL", "500ms")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_START_FROM", "beginning")
	t.Setenv("VAULTWARDEN_EXPORTER_EVENTS_STATE_BACKEND", "memory")

	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	signals := make(chan os.Signal, 1)
	done := make(chan int)
	go func() { done <- run(nil, signals, stdout, stderr) }()

	exporter := "http://127.0.0.1:" + strconv.Itoa(port)
	require.Eventually(t, func() bool { return status(exporter+"/readyz") == http.StatusOK },
		30*time.Second, 200*time.Millisecond, "stderr: %s", stderr.String())
	require.Eventually(t, func() bool {
		out := stdout.String()
		return strings.Contains(out, `"event_name":"UserLoggedIn"`) && strings.Contains(out, `"event_name":"UserFailedLogIn"`)
	}, 30*time.Second, 200*time.Millisecond, "stdout: %s\nstderr: %s", stdout.String(), stderr.String())
	require.Contains(t, stdout.String(), `"user_email":"`+itEmail+`"`)

	metrics := fetch(t, exporter+"/metrics")
	// SIGNUPS_VERIFY=false: Vaultwarden leaves verified_at empty
	require.Contains(t, metrics, `vaultwarden_users{email_verified="false",enabled="true"} 1`, metrics)
	require.Contains(t, metrics, `vaultwarden_users_without_two_factor 1`)
	require.Contains(t, metrics, `vaultwarden_exporter_up 1`)
	require.NotContains(t, stderr.String(), `"level":"ERROR"`, stderr.String())

	signals <- os.Interrupt
	require.Equal(t, 0, <-done)
	t.Logf("events exported:\n%s", stdout.String())
}
