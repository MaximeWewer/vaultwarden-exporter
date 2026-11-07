# Vaultwarden Exporter

A Prometheus exporter and audit event stream for
[Vaultwarden](https://github.com/dani-garcia/vaultwarden): it reads the
Vaultwarden database (read-only) and

- exposes **Prometheus metrics**: accounts, two-factor adoption, organizations
  and memberships, vault items, attachments, Sends, devices, emergency access;
- streams the **audit events** (logins, failed logins, vault exports, items
  viewed or copied, membership and policy changes...) as **JSON lines** on
  stdout, to a file, or directly to a remote syslog receiver, for your SIEM.

Vaultwarden has no metrics endpoint, and only exposes its events per
organization to an organization admin, never the events outside an
organization.

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
- [Database access](#database-access)
- [Audit event stream](#audit-event-stream)
- [Configuration](#configuration)
- [Metrics reference](#metrics-reference)
- [Alerting](#alerting)
- [Grafana dashboard](#grafana-dashboard)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

## Features

- **PostgreSQL, MySQL/MariaDB and SQLite**, with the Vaultwarden
  `DATABASE_URL` format. Pure Go drivers: one static binary, no CGO.
- **Least privilege**: every query reads non-sensitive columns only (types,
  statuses, flags, sizes, emails for the events). A read-only role with
  column-level grants is enough: never password hashes, keys or vault data.
- **Database-friendly metrics**: the queries run every `refresh_interval`
  (60 s) into a snapshot; scrapes never hit the database.
- **Reliable event stream**: cursor + late-arrival window + deduplication by
  event id, persisted in a file or a Kubernetes ConfigMap. No event replayed
  after a restart, late client uploads caught, at-least-once delivery.
- Readable events: event and device type names, user / actor emails,
  organization names, static labels, include / exclude filters.
- Distroless non-root image, `--healthcheck` for container health checks,
  Prometheus web configuration (TLS, basic auth) through exporter-toolkit.

## Quick start

### Docker Compose (SQLite)

[`deployments/docker/docker-compose.yml`](deployments/docker/docker-compose.yml)
runs Vaultwarden and the exporter side by side:

```bash
docker compose -f deployments/docker/docker-compose.yml up -d
curl localhost:9776/metrics
docker compose -f deployments/docker/docker-compose.yml logs -f exporter   # audit events
```

### Docker

```bash
docker run -d -p 9776:9776 \
  -e DATABASE_URL='postgresql://vw_exporter:secret@db:5432/vaultwarden' \
  -e VAULTWARDEN_EXPORTER_EVENTS_ENABLED=true \
  -v vw-exporter-state:/var/lib/vaultwarden-exporter \
  ghcr.io/maximewewer/vaultwarden-exporter:latest
```

### Kubernetes

- With the [vaultwarden-helm](https://github.com/MaximeWewer/vaultwarden-helm)
  chart, which also creates the read-only PostgreSQL role and its grants.
- Or with the plain manifests of
  [`deployments/kubernetes/`](deployments/kubernetes/vaultwarden-exporter.yaml)
  (ServiceAccount, RBAC for the cursor ConfigMap, Deployment, Service,
  ServiceMonitor).

### Binary

Download a binary from the [releases](https://github.com/MaximeWewer/vaultwarden-exporter/releases):

```bash
DATABASE_URL=sqlite:///opt/vaultwarden/data/db.sqlite3 ./vaultwarden-exporter
```

## Database access

Use a dedicated read-only account. PostgreSQL
([`deployments/sql/postgresql-readonly.sql`](deployments/sql/postgresql-readonly.sql),
run as the owner of the tables once Vaultwarden has created them; the
integration tests run the exporter with exactly this role):

```sql
-- Column-level grants only: never password hashes, keys or vault data.
-- (COUNT(*) needs SELECT on at least one column of the table.)
CREATE ROLE vw_exporter LOGIN PASSWORD :password;
GRANT USAGE ON SCHEMA public TO vw_exporter;
-- metrics
GRANT SELECT (uuid, enabled, verified_at, email, name) ON users TO vw_exporter;
GRANT SELECT (user_uuid, atype, enabled) ON twofactor TO vw_exporter;
GRANT SELECT (user_uuid) ON twofactor_incomplete TO vw_exporter;
GRANT SELECT (uuid, name) ON organizations TO vw_exporter;
GRANT SELECT (uuid, user_uuid, status, atype) ON users_organizations TO vw_exporter;
GRANT SELECT (uuid) ON collections, groups TO vw_exporter;
GRANT SELECT (atype, deleted_at) ON ciphers TO vw_exporter;
GRANT SELECT (file_size) ON attachments TO vw_exporter;
GRANT SELECT (atype) ON sends, devices TO vw_exporter;
GRANT SELECT (status) ON emergency_access TO vw_exporter;
-- events
GRANT SELECT ON event TO vw_exporter;
```

MySQL / MariaDB accept the same column-level `GRANT SELECT (...) ON db.table`
statements (quote `` `groups` ``, a reserved word in MySQL 8).

**SQLite**: Vaultwarden runs it in WAL mode, so the reader needs access to
`db.sqlite3-shm` next to the database: run the exporter with the uid of
Vaultwarden on the same volume. The database is opened read-only
(`mode=ro`, `query_only`).

Supported URLs (as Vaultwarden `DATABASE_URL`):

| Engine | URL |
|--------|-----|
| PostgreSQL | `postgresql://user:pass@host:5432/vaultwarden?sslmode=require` |
| MySQL / MariaDB | `mysql://user:pass@host:3306/vaultwarden` (`?ssl_mode=required` / `verify_identity`) |
| SQLite | `sqlite:///data/db.sqlite3` or a bare path |

## Audit event stream

Vaultwarden records events only with **`ORG_EVENTS_ENABLED=true`** (and keeps
them `EVENTS_DAYS_RETAIN` days). With `events.enabled`, the exporter prints one
JSON document per event:

```json
{"source":"vaultwarden","kind":"audit_event","timestamp":"2026-11-05T13:16:26.113563Z",
 "event_id":"1ded621b-e428-4cbd-aced-f1b621503fe2","event_type":1005,"event_name":"UserFailedLogIn",
 "user_id":"837c8b37-...","user_email":"alice@example.com","actor_id":"837c8b37-...",
 "actor_email":"alice@example.com","actor_name":"Alice","device_type":10,"device_name":"FirefoxBrowser",
 "ip":"203.0.113.7","labels":{"cluster":"prod"}}
```

(one line per event; wrapped here). Empty fields are omitted.

Organization events about a member (invited, confirmed, removed, revoked, role
or groups changed...) carry `member_id` and, while the membership exists,
`member_email` / `member_name` of the user concerned; `actor_*` is who did it.
A deleted membership (`OrganizationUserRemoved`, `OrganizationUserDeleted`)
keeps `member_id` only.

- **stdout is reserved for the events**, the exporter logs go to stderr: a
  log pipeline (fluent-bit, Vector, Alloy, Promtail...) can tell them apart, or
  filter on `"kind":"audit_event"`.
- **How it works**: ordering by date alone would miss events stored late:
  clients upload some events afterwards with their own timestamp (item viewed,
  password copied). Each poll re-reads the window `[cursor - late_window, now]`
  page by page in `(event_date, event_id)` order and skips the events already
  exported. The cursor and the ids of the window are saved after each page.
- **Delivery is at least once**: a crash between writing a page and saving the
  state re-emits that page. Deduplicate on `event_id` downstream.
- **One reader**: run a single instance with events enabled, or every event is
  printed once per instance.
- **User events** (login, failed login...) are stored once without
  organization and once per organization of the user; `filter.org_copies: none`
  keeps only the copy without organization.
- **No index on `event_date`** in the Vaultwarden schema: on large event tables,
  add one (`CREATE INDEX event_date_idx ON event (event_date)`) or keep
  `EVENTS_DAYS_RETAIN` low.
- **State backends**: `file` (default, atomic writes), `kubernetes` (a
  ConfigMap created by the exporter; RBAC: `create` configmaps, `get`/`patch` on
  that name; it is not part of a Helm release, so upgrades and GitOps syncs
  never reset it), `memory` (tests).

### Direct syslog output

No log-forwarding sidecar is needed when your SIEM accepts syslog:

```yaml
events:
  enabled: true
  output:
    type: syslog
    syslog:
      address: siem.example.com:6514
      protocol: tls             # tcp (default), udp or tls
      # ca_file: /etc/syslog/ca.pem  # optional PEM trust bundle; otherwise system roots
      timeout: 5s               # total dial + TLS handshake + write deadline per batch
```

Each message uses RFC3164, facility `user`, severity `info`, and the tag
`vaultwarden-exporter`; the message body is the original event JSON. TCP uses
newline-delimited framing (RFC6587 non-transparent framing); TLS uses
octet-counted frames (`<byte-length> <message>`); UDP sends one datagram per
event. Messages are not truncated: configure the receiver to
accept the largest event JSON, including its syslog header.

The exporter opens a connection for each batch. A connection or write error
leaves that batch uncommitted so the next poll retries it. Partially sent
batches can be replayed; deduplicate on `event_id` at the receiver. A successful
socket write does not acknowledge storage in the SIEM, and UDP can lose
messages without reporting an error. State must remain on persistent storage.

TLS requires TLS 1.2 or newer and verifies the receiver's certificate chain,
validity period and hostname/IP against `address`. There is no insecure mode
or fallback to plaintext. When `ca_file` is set, its certificates replace the
system trust roots. The file is loaded at startup; restart after changing it.
An unreadable file or a PEM bundle with no certificates prevents startup.
Client certificates (mutual TLS) are not supported.

Plain TCP and UDP remain unencrypted and unauthenticated; use them only over
a trusted private network or a secured tunnel.

For Wazuh, use a syslog listener with restricted `allowed-ips`, not the agent
protocol. For TLS, point the exporter at a TLS-capable syslog receiver/relay
(such as rsyslog or syslog-ng) in front of Wazuh. Verify rules for the JSON
body with `wazuh-logtest`.

## Configuration

Priority: environment variables > YAML file (`--config`) > defaults. The YAML
file is strict: an unknown key is an error.

```yaml
database:
  url: postgresql://vw_exporter:secret@db:5432/vaultwarden
  # url_file: /etc/vaultwarden-exporter/db/url   # read from a mounted secret
  max_open_conns: 2
  query_timeout: 15s
server:
  address: 0.0.0.0
  port: 9776
  web_config_file: ""          # Prometheus web config: TLS, basic auth
logging:
  level: info                  # debug, info, warn, error
  format: json                 # json, console
metrics:
  enabled: true
  refresh_interval: 60s
events:
  enabled: true
  poll_interval: 30s
  batch_size: 500
  late_window: 1h
  start_from: now              # first start only: now or beginning
  output:
    type: stdout               # stdout, file or syslog
    path: ""                   # file: appended, reopened for every batch (logrotate friendly)
    syslog:
      address: ""              # required for syslog, host:port (IPv6: [host]:port)
      protocol: tcp            # tcp, udp or tls
      timeout: 5s              # dial + TLS handshake + write deadline per batch
      ca_file: ""              # TLS PEM trust bundle; empty uses system roots
  state:
    backend: file              # file, kubernetes or memory
    path: /var/lib/vaultwarden-exporter/state.json
    configmap: vaultwarden-exporter-state
    namespace: ""              # default: the pod namespace
  labels:
    cluster: prod
  filter:
    include: []                # event names, e.g. [UserLoggedIn, UserFailedLogIn]
    exclude: []                # mutually exclusive with include
    org_copies: all            # all or none
```

| Environment variable | YAML key |
|----------------------|----------|
| `VAULTWARDEN_EXPORTER_DATABASE_URL` (or `DATABASE_URL`) | `database.url` |
| `VAULTWARDEN_EXPORTER_DATABASE_URL_FILE` | `database.url_file` |
| `VAULTWARDEN_EXPORTER_DATABASE_MAX_OPEN_CONNS` | `database.max_open_conns` |
| `VAULTWARDEN_EXPORTER_DATABASE_QUERY_TIMEOUT` | `database.query_timeout` |
| `VAULTWARDEN_EXPORTER_ADDRESS` / `_PORT` | `server.address` / `server.port` |
| `VAULTWARDEN_EXPORTER_READ_TIMEOUT` / `_WRITE_TIMEOUT` | `server.read_timeout` / `server.write_timeout` |
| `VAULTWARDEN_EXPORTER_WEB_CONFIG_FILE` | `server.web_config_file` |
| `VAULTWARDEN_EXPORTER_LOG_LEVEL` / `_LOG_FORMAT` | `logging.level` / `logging.format` |
| `VAULTWARDEN_EXPORTER_METRICS_ENABLED` | `metrics.enabled` |
| `VAULTWARDEN_EXPORTER_METRICS_REFRESH_INTERVAL` | `metrics.refresh_interval` |
| `VAULTWARDEN_EXPORTER_EVENTS_ENABLED` | `events.enabled` |
| `VAULTWARDEN_EXPORTER_EVENTS_POLL_INTERVAL` | `events.poll_interval` |
| `VAULTWARDEN_EXPORTER_EVENTS_BATCH_SIZE` | `events.batch_size` |
| `VAULTWARDEN_EXPORTER_EVENTS_LATE_WINDOW` | `events.late_window` |
| `VAULTWARDEN_EXPORTER_EVENTS_START_FROM` | `events.start_from` |
| `VAULTWARDEN_EXPORTER_EVENTS_OUTPUT` / `_OUTPUT_PATH` | `events.output.type` / `events.output.path` |
| `VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_ADDRESS` | `events.output.syslog.address` |
| `VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_PROTOCOL` | `events.output.syslog.protocol` |
| `VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_TIMEOUT` | `events.output.syslog.timeout` |
| `VAULTWARDEN_EXPORTER_EVENTS_SYSLOG_CA_FILE` | `events.output.syslog.ca_file` |
| `VAULTWARDEN_EXPORTER_EVENTS_STATE_BACKEND` | `events.state.backend` |
| `VAULTWARDEN_EXPORTER_EVENTS_STATE_PATH` | `events.state.path` |
| `VAULTWARDEN_EXPORTER_EVENTS_STATE_CONFIGMAP` / `_STATE_NAMESPACE` | `events.state.configmap` / `events.state.namespace` |
| `VAULTWARDEN_EXPORTER_EVENTS_LABELS` (`k=v,k2=v2`) | `events.labels` |
| `VAULTWARDEN_EXPORTER_EVENTS_INCLUDE` / `_EXCLUDE` (comma separated) | `events.filter.include` / `exclude` |
| `VAULTWARDEN_EXPORTER_EVENTS_ORG_COPIES` | `events.filter.org_copies` |

Flags: `--config`, `--web.config.file`, `--web.listen-address` (override the
file and the environment), `--version`, `--healthcheck`.

Endpoints: `/metrics`, `/healthz` (liveness), `/readyz` (first refresh done,
event state loaded).

## Metrics reference

| Metric | Labels | Description |
|--------|--------|-------------|
| `vaultwarden_users` | `enabled`, `email_verified` | User accounts |
| `vaultwarden_users_two_factor` | `method` (authenticator, email, duo, yubikey, u2f, organization_duo, webauthn) | Users with this method enabled |
| `vaultwarden_users_without_two_factor` | | Enabled users without any method |
| `vaultwarden_two_factor_incomplete_logins` | | Master password accepted, second factor pending |
| `vaultwarden_organizations` | | Organizations |
| `vaultwarden_organization_members` | `status` (invited, accepted, confirmed, revoked), `role` (owner, admin, user, manager) | Memberships |
| `vaultwarden_collections`, `vaultwarden_groups` | | Organization collections and groups |
| `vaultwarden_ciphers` | `type` (login, secure_note, card, identity, ssh_key), `state` (active, trashed) | Vault items |
| `vaultwarden_attachments`, `vaultwarden_attachments_size_bytes` | | Attachments and their total size |
| `vaultwarden_sends` | `type` (text, file) | Sends |
| `vaultwarden_devices` | `type` (Android, ChromeBrowser, LinuxDesktop...) | Registered client devices |
| `vaultwarden_emergency_access` | `status` | Emergency access grants |
| `vaultwarden_audit_events_total` | `event_name` | Events exported since start (counter, `rate()` it). Every known event name starts at 0, so a single rare event (a vault export) shows in `increase()` / `rate()` |
| `vaultwarden_exporter_up` | | 1 if the last refresh succeeded for every query |
| `vaultwarden_exporter_last_refresh_timestamp_seconds` / `_refresh_duration_seconds` | | Metrics refresh |
| `vaultwarden_exporter_query_errors_total` | `query` | Failed metrics queries |
| `vaultwarden_exporter_events_last_poll_timestamp_seconds` / `_events_poll_duration_seconds` | | Event polls |
| `vaultwarden_exporter_events_cursor_timestamp_seconds` | | Date of the newest exported event |
| `vaultwarden_exporter_events_window_size` | | Event ids remembered in the window |
| `vaultwarden_exporter_events_errors_total` | `stage` (query, sink, state) | Event stream errors |
| `vaultwarden_exporter_build_info` | `version`, `commit`, `goversion`, `database` | Build information |

Known enum values always have a series (0 when absent), so alerts on a missing
value work. A failed query keeps its previous values and sets
`vaultwarden_exporter_up` to 0.

## Alerting

[`deployments/prometheus/vaultwarden-alerts.yml`](deployments/prometheus/vaultwarden-alerts.yml)
(unit-tested with `promtool test rules`):

| Alert | Severity | Fires when |
|-------|----------|------------|
| `VaultwardenEventStreamStalled` | critical | No event poll for 15 min: events no longer reach the SIEM |
| `VaultwardenFailedLoginsSpike` | warning | More than 20 failed logins in 10 min |
| `VaultwardenFailedTwoFactor` | warning | More than 3 wrong two-factor codes in 15 min (master password accepted) |
| `VaultwardenIncompleteTwoFactorLogins` | warning | More than 10 logins stuck at the second factor for 30 min |
| `VaultwardenExporterQueriesFailing` | warning | Metrics queries failing for 10 min (grant, schema change) |
| `VaultwardenMetricsStale` | warning | No metrics refresh for 15 min |
| `VaultwardenEventStreamErrors` | warning | Event query, output or state errors |
| `VaultwardenVaultExported` | info | A user or organization vault was exported |
| `VaultwardenUsersWithoutTwoFactor` | info | Enabled users without 2FA for 7 days |

## Grafana dashboard

[`grafana/vaultwarden.json`](grafana/vaultwarden.json): overview, security
(logins, failed logins and wrong two-factor codes, events by type, vault
exports, membership and policy changes), inventory (2FA methods, item types, devices, members), exporter
health.

## Security

- Read-only database access, column-level grants (see above); SQLite opened
  read-only.
- The database password never appears in the logs (redacted at startup).
- Distroless `nonroot` image, read-only root filesystem friendly, no shell.
- The Kubernetes state backend needs only `create` configmaps and
  `get`/`patch` on one name.
- Event fields come from the database and are JSON-escaped: an email or an
  organization name cannot forge a log line.

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `vaultwarden_exporter_up 0`, `permission denied for table` | Missing grant (see [Database access](#database-access)) |
| No events at all | `ORG_EVENTS_ENABLED` is off in Vaultwarden |
| SQLite `unable to open database file` | The exporter cannot read the volume, or cannot access `db.sqlite3-shm` (run with the Vaultwarden uid) |
| Every event printed twice | Two instances with events enabled |
| Events replayed after a restart | `events.state.backend: memory`, or the state path is not persistent |

## Development

```bash
go test -race ./...                                   # unit tests (SQLite schema of Vaultwarden)
.github/scripts/integration.sh postgresql mysql sqlite  # real Vaultwarden on each engine (docker)
.github/scripts/check-deployments.sh                  # rules, manifests, compose, dashboard, metric names
.github/scripts/check-enums.sh 1.37.5                 # event / device type names vs the Vaultwarden sources
golangci-lint run
```

Releases follow `YEAR.MONTH.INDEX` (e.g. `2026.11.1`), built by the
*Build and Release* workflow: multi-arch image signed with cosign, SBOM,
binaries for Linux, macOS and Windows.
