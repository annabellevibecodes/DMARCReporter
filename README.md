# DMARC Reporter

> This web application is vibe coded. Use at your own risk.

A web application for parsing, storing, and visualising DMARC aggregate reports. Reports can be uploaded manually or fetched automatically from IMAP mailboxes — including **Gmail** and **Office 365** via OAuth2.

## Features

- Parse DMARC aggregate report XML files (`.xml`, `.xml.gz`, `.gz`, `.zip`), raw email files (`.eml`), and SMTP TLS reports (RFC 8460, `.json` / `.json.gz`)
- SMTP TLS reports are stored in full: every policy entry, its `mx-host` patterns and each `failure-details` row, with the DKIM signature of the carrying mail verified per RFC 8460 §3 (see `TLSRPT_REQUIRE_DKIM`). Reports that describe the same sessions under two policy entries (an MTA-STS policy and a TLSA record) are counted once, not twice
- Published TLS records are snapshotted with history — one row per observed state, not per check — so a policy or key change is a dated entry, and reports can be compared against what the domain publishes now (T8 drift)
- TLS analytics (T1–T15): success rate and volume with period-over-period deltas, policy-type mix and MTA-STS enforcement readiness, failures grouped by result type, receiving host, receiving node, sending network and reason code, DANE and policy-host health, reporter coverage, hygiene, address-family split, and multi-day incidents
- Fetch reports from multiple mailboxes managed under **Accounts**: generic IMAP (password), **Gmail / Google Workspace** (app password or OAuth2), and **Office 365** via IMAP or the **Microsoft Graph API** (both OAuth2 client credentials — required, since Microsoft disabled basic auth)
- Background fetching: manual trigger or scheduled via `FETCH_INTERVAL`; a two-phase BODYSTRUCTURE fetch downloads only messages that carry report attachments, and report-free messages are cached by UID so they are never downloaded twice
- Processed emails are moved to a subfolder; the folder name adapts to the server's hierarchy delimiter (`INBOX.Processed` on Dovecot, `INBOX/Processed` on Gmail/O365) unless overridden
- Account credentials are encrypted at rest (AES-256-GCM) with `SECRETS_KEY` or an auto-generated key file next to the database
- Dashboard with pass/fail statistics, failure modes, top failing sources, policy-override ("forgiven failures") breakdown, and an adaptive trend chart (daily buckets for short periods, weekly beyond ~3 months, gaps filled)
- Known-sender classification: source IPs are labelled with their provider (Google, Microsoft 365, SendGrid, …) from cached reverse DNS
- Enrich page for bulk-refreshing reverse DNS/WHOIS (source IPs), DMARC/BIMI/MTA-STS domain checks, SPF record expansion (include / redirect / a / mx / ip4 / ip6, capped at 10 lookups per RFC 7208, cached 24h) and the published TLS records of each domain (`_smtp._tls` TLS-RPT record, the MTA-STS policy file, and TLSA records per MX host) in the background, with live progress via Server-Sent Events; a run keeps going even if the browser tab is closed
- Analytics: authentication matrix (both / DKIM-only / SPF-only / neither), disposition and enforcement effectiveness, unexplained policy overrides, deltas versus the preceding period, and a 0–100 health score per domain
- Source intelligence: per-IP matrix, raw DKIM/SPF results, first/last seen, reporters, behaviour pattern (healthy / forwarder / broken signing / spoof suspect / mixed) with user labels, classifications and notes; spoof volume split by SPF membership
- Authentication and policy analysis per domain: selector inventory with expected flags, signing alignment (exact / relaxed / third-party via the Public Suffix List), alignment gap, envelope-from alignment, DNS error rate per reporter, published-record consistency across reporters, change log with before/after pass rates, subdomain traffic, pct sampling, enforcement readiness
- Reporters page: inventory, coverage strips and silent reporters, report latency, hygiene (duplicates, parse errors, odd window lengths), schema versions (RFC 7489 and DMARCbis `dmarc-2.0`), unmanaged domains, managed-domain list
- Nineteen persisted, acknowledgeable alert rules evaluated after every import and on a timer, delivered via webhook and/or SMTP email. DMARC (X1–X11): new failing source, pass-rate drop per domain, known-good source degraded, new / missing selector, silent reporter, policy changed / inconsistent, DNS error spike, override spike, spoof spike. SMTP TLS (X12–X19): TLS rate drop, STARTTLS stripping, expired certificate, inconsistent or drifted policy, MTA-STS policy-host errors, DANE validation failure, silent TLS reporter, newly failing receiving node
- DMARCbis (RFC 9989/9990) fields stored: namespace, `np`, `discovery_method`, `testing`, report version and `<error>` entries; absent `sp`/`pct`/`fo` distinguishable from explicit values
- Ingest log: one row per processed attachment (imported / duplicate / parse error / rejected) and the mail `Date` header as `received_at`
- Three UI themes — **Goth** (terminal), **Pink** (Y2K glam), **Blue** (newspaper) — switchable at any time, persisted via cookie
- DKIM selector statistics (weighted by message volume) on domain and report detail pages
- Management report export in CSV, XLSX, PDF, and DOCX, scoped to the selected reporting period and domain
- Browse reports, domains, and source IPs with sortable column headers
- Filter reports by domain and date range; filter sources by IP, envelope-from, disposition, and minimum message count (slider)
- Reporting period selector on all list pages — All Time, 2 Years, 1 Year, 6/3 Months, Last Month, 30/14/7/3/2 Days, Last 24 Hours
- JSON API (`/api/*`) honouring the same `period`, `ef`, and `domain` filters as the UI
- HTTP Basic Auth with configurable username and password
- Rate limiting on upload, fetch, and account-management endpoints
- SQLite storage — no external database required

## Requirements

- Go 1.26 or later

No C compiler is required. The SQLite driver (`modernc.org/sqlite`) is pure Go.

## Build

```bash
git clone <repository-url>
cd DMARCReporter
go build -o dmarcreporter .
```

The resulting `dmarcreporter` binary is self-contained and has no runtime dependencies.

## Run

### Without IMAP (file upload only)

```bash
./dmarcreporter
```

The server starts on `http://localhost:8080` by default.

### With mail fetching

Mailboxes are managed on the **Accounts** page. Alternatively, a single IMAP account can be configured via environment variables (it is mirrored into the Accounts page on startup):

```bash
IMAP_HOST=mail.example.com \
IMAP_USER=dmarc@example.com \
IMAP_PASS=secret \
./dmarcreporter
```

When at least one account is configured, a **Fetch** button appears in the navigation bar. Fetching runs in the background: it scans message structures, downloads only messages carrying report attachments, imports DMARC and TLS-RPT reports, and moves processed emails to the processed subfolder. Set `FETCH_INTERVAL` (e.g. `30m`, `4h`) to fetch on a schedule.

### Gmail

Two options:

1. **App password** (simplest): enable 2-step verification on the Google account, create an app password, and add a Gmail account with that password on the Accounts page.
2. **OAuth2**: create an OAuth client (type *Web application*) in Google Cloud Console with the redirect URI `<BASE_URL>/oauth/google/callback`, enter its client ID and secret when adding the account (leave the password blank), and complete the Google consent screen you are redirected to. The refresh token is stored encrypted; access tokens are renewed automatically.

### Office 365 / Exchange Online

Microsoft has disabled basic authentication for IMAP, so OAuth2 is required:

1. Register an application in Entra ID (Azure AD).
2. Add the **API permission** `Office 365 Exchange Online → IMAP.AccessAsApp` (application permission) and grant admin consent.
3. Grant the app's service principal access to the mailbox in Exchange Online PowerShell:
   ```powershell
   New-ServicePrincipal -AppId <client-id> -ObjectId <sp-object-id>
   Add-MailboxPermission -Identity dmarc@example.com -User <sp-object-id> -AccessRights FullAccess
   ```
4. Add an Office 365 account on the Accounts page with the tenant ID, client ID, and client secret.

Use **Test** on the Accounts page to verify connectivity before the first fetch.

### Office 365 (Microsoft Graph API)

An alternative to the IMAP option above that talks to the mailbox over the Graph REST API instead of IMAP — useful when IMAP is disabled for the tenant:

1. Register an application in Entra ID (Azure AD).
2. Add the **API permission** `Microsoft Graph → Mail.ReadWrite` (application permission) and grant admin consent. Application permissions apply tenant-wide by default; scope access to a specific mailbox with an [application access policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access) if needed.
3. Add an **Office 365 (Microsoft Graph API)** account on the Accounts page with the tenant ID, client ID, client secret, and the mailbox's email address as the username. "Mailbox" accepts a well-known folder name (`inbox`, the default) or an explicit Graph folder ID.

Use **Test** on the Accounts page to verify connectivity before the first fetch.

## Configuration

All configuration is via environment variables. Every variable has a sensible default.

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP port to listen on |
| `DB_PATH` | `dmarc.db` | Path to the SQLite database file |
| `SECURE_COOKIES` | `false` | Set to `true` when serving over HTTPS to enable the `Secure` flag on cookies and HSTS |
| `DEBUG` | `false` | Set to `true` to emit verbose debug logs to stdout and syslog |
| `AUTH_USER` | `admin` | HTTP Basic Auth username |
| `AUTH_PASSWORD` | _(required)_ | HTTP Basic Auth password. The application refuses to start unless this is set. |
| `AUTH_DISABLED` | `false` | Set to `true` to run without authentication. **Development only — never use in production.** |
| `AUTH_FAIL_MAX` | `10` | Failed login attempts per IP before that IP is locked out for `AUTH_FAIL_WINDOW` (0 to disable) |
| `AUTH_FAIL_WINDOW` | `15m` | Lockout window for `AUTH_FAIL_MAX` (Go duration) |
| `HSTS_ENABLED` | `false` | Set to `true` to send `Strict-Transport-Security` headers. Enable whenever the application is served over HTTPS. |
| `UPLOAD_RATE_MAX` | `20` | Maximum file uploads per minute per IP (0 to disable) |
| `FETCH_RATE_MAX` | `3` | Maximum fetch requests per 5 minutes per IP (0 to disable) |
| `BASE_URL` | `http://localhost:<PORT>` | External base URL of the app; used to build the Google OAuth redirect URI |
| `SECRETS_KEY` | _(unset)_ | Key for encrypting account credentials at rest: a 64-char hex string is used as the raw key; any other value is treated as a passphrase and stretched with argon2id (secrets saved by older versions, which used plain SHA-256, remain readable and are migrated on their next save). When unset a random key is generated in `<DB_PATH>.key` (mode 0600). |
| `FETCH_INTERVAL` | _(unset)_ | Background fetch interval (Go duration, e.g. `30m`, `4h`). Unset = manual fetch only. |
| `IMAP_HOST` | _(unset)_ | Legacy single-account config: IMAP server hostname. Mirrored into the Accounts page on startup. |
| `IMAP_PORT` | `993` | IMAP server port |
| `IMAP_USER` | _(unset)_ | IMAP username |
| `IMAP_PASS` | _(unset)_ | IMAP password |
| `IMAP_MAILBOX` | `INBOX` | Mailbox to fetch reports from |
| `IMAP_PROCESSED_MAILBOX` | _(auto)_ | Mailbox to move processed emails to. When unset, derived from the server's hierarchy delimiter (`INBOX.Processed`, `INBOX/Processed`, …). |
| `IMAP_TLS` | `true` | Use TLS. Set to `false` only for local testing. |
| `ALERT_WEBHOOK_URL` | _(unset)_ | POST target for JSON alert notifications |
| `ALERT_PASS_RATE_DROP` | `5.0` | X2: alert when a domain's 7-day pass rate drops by more than this many percentage points week-over-week |
| `ALERT_EVAL_INTERVAL` | `24h` | How often alert rules run on the timer (they also run after every import) |
| `ALERT_NEW_SOURCE_MIN` | `10` | X1: minimum messages before a new failing source alerts |
| `ALERT_MIN_WINDOW_MESSAGES` | `50` | X2/X3: minimum messages in both windows for rate comparisons |
| `ALERT_KNOWN_DROP` | `20` | X3: pass-rate drop (points) of a `known_good` source versus its 7-day baseline |
| `ALERT_NEW_SELECTOR_HOURS` | `48` | X4: a selector first seen within this many hours is "new" |
| `ALERT_SELECTOR_MISSING_DAYS` | `7` | X5: an expected selector unseen for this many days is "missing" |
| `ALERT_REPORTER_GAP_DAYS` | `3` | X6: a reporter active in the last 14 days with no report window in this many days is "silent" |
| `ALERT_DNS_ERROR_PCT` | `5` | X9: DNS temp/perm error share of a reporter's raw results |
| `ALERT_OVERRIDE_SPIKE_FACTOR` | `3` | X10: policy-override volume above this multiple of the 7-day daily mean |
| `ALERT_SPOOF_SPIKE_FACTOR` / `ALERT_SPOOF_ABS` | `3` / `50` | X11: not-in-SPF volume above this multiple of the daily mean, or above the absolute count |
| `ALERT_TLS_RATE_DROP` / `ALERT_TLS_MIN_WINDOW_SESSIONS` | `5.0` / `100` | X12: week-over-week fall in a domain's TLS success rate, with a session floor in both windows |
| `ALERT_TLS_STRIP_MIN_SESSIONS` | `5` | X13: sessions reporting `starttls-not-supported` on a host that previously negotiated TLS |
| `ALERT_TLS_POLICY_HOST_ERR_PCT` | `5` | X16: MTA-STS policy fetch and WebPKI failures as a percentage of a domain's sessions |
| `ALERT_TLS_REPORTER_GAP_DAYS` | `3` | X18: a TLS reporter active in the last 14 days with no report window in this many days |
| `ALERT_TLS_NEW_FAILING_IP_MIN` | `10` | X19: sessions from a receiving node that was not failing before |
| `ALERT_RECENT_HOURS` | `48` | Window used by "last 24h" rules (reports for a day arrive the next day) |
| `DNS_SERVER` | _(from `/etc/resolv.conf`)_ | Nameserver for TLSA lookups (`host` or `host:port`). Go's resolver has no API for TLSA records, so those queries are sent directly; every other lookup uses the system resolver. Set this when the container has no usable `/etc/resolv.conf`. |
| `TLSRPT_REQUIRE_DKIM` | `true` | RFC 8460 §3: a TLS report that arrived as mail without a valid DKIM signature is stored and listed with its reason, but left out of the TLS metrics. Set to `false` to count them anyway. Reports uploaded through the web form have no carrying message and are never affected. |
| `HEALTH_W_PASS_RATE` / `HEALTH_W_ENFORCEMENT` / `HEALTH_W_SPOOF` / `HEALTH_W_COVERAGE` / `HEALTH_W_ALERTS` / `HEALTH_W_TLS` | `40` / `25` / `15` / `10` / `10` / `15` | Health score component weights. The DMARC five sum to 100; the TLS component is added on top, and is left out of both the score and its maximum for a domain with no TLS sessions to judge, so absent data never reads as failure |
| `PATTERN_HEALTHY_MIN` / `PATTERN_FORWARDER_MIN` / `PATTERN_BROKEN_SIGNING_MIN` / `PATTERN_SPOOF_MIN` / `PATTERN_SPOOF_MIN_MSGS` | `90` / `60` / `60` / `95` / `5` | Source pattern thresholds (percent of a source's messages; message floor for spoof suspects) |
| `SMTP_HOST` / `SMTP_PORT` | _(unset)_ / `587` | SMTP relay for alert emails (disabled when host is unset) |
| `SMTP_USER` / `SMTP_PASS` | _(unset)_ | SMTP credentials (optional) |
| `SMTP_FROM` / `SMTP_TO` | _(unset)_ | Alert email sender and comma-separated recipients |

## Exposure to Internet

If you wish to make this web application publicly accessible, we recommend using a reverse proxy with pre-authentication to enable secure access via the internet.

## Usage

### Uploading reports manually

Navigate to **Upload** and select one or more report files. Supported formats:

- `.xml` — plain DMARC aggregate report XML
- `.xml.gz` / `.gz` — gzip-compressed XML
- `.xml.zip` / `.zip` — zip-archived XML
- `.eml` — raw email file; DMARC report attachments are extracted automatically

Re-uploading a report that has already been imported is safe — duplicates are detected and silently skipped.

### Fetching from mailboxes

Click **Fetch** in the navigation bar (or configure `FETCH_INTERVAL`). For each enabled account the application will, in the background:

1. Connect over TLS and authenticate (password or OAuth2/XOAUTH2)
2. List all messages in the source mailbox and skip UIDs already examined
3. Fetch message structures and download full bodies only for messages carrying candidate report attachments
4. Parse and import DMARC XML and TLS-RPT JSON reports
5. Move emails that carried reports to the processed subfolder; remember report-free messages so they are never downloaded again

The subfolder is created automatically if it does not exist. Per-account status (last run, imported count, errors) is shown on the Accounts page.

### Viewing data

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Summary stats and weekly pass/fail trend chart |
| Reports | `/reports` | All imported reports, filterable by domain and date |
| Report detail | `/reports/:id` | Individual report with per-IP record breakdown |
| Domains | `/domains` | All domains with aggregate message counts |
| Domain detail | `/domains/:domain` | Per-domain records across all reports |
| Sources | `/sources` | All source IPs with pattern, matrix, labels and first/last seen; filterable by period, envelope-from, IP, pattern, matrix cell, new-only and minimum message count; inline label editing |
| Source detail | `/sources/:ip` | Per-IP matrix, raw results, timeline, selectors, identifiers, reporters, label/classification/notes |
| Reporters | `/reporters` | Reporter inventory, coverage and latency, hygiene, schema versions, managed domains, recipient domains |
| Alerts | `/alerts` | Open / acknowledged alerts with payloads, acknowledge buttons, rule table |
| TLS reports | `/tlsrpt` | The T-series for SMTP TLS reporting (RFC 8460): success rate with period delta, sessions per day, per-domain and per-policy-type breakdown, failures by result type, receiving host, receiving node and sending network, failure reasons, MTA-STS mode and readiness, DANE health, reporter coverage, hygiene and incidents. Drill down by policy domain, MX host or receiving node |
| TLS report detail | `/tlsrpt/:id` | One report as its reporter sent it: every policy entry with its parsed MTA-STS body and mx list, the full failure-detail table, and the DKIM verdict on the carrying mail |
| TLS report list | `/reports/tlsrpt` | The raw TLS report list, counterpart of `/reports/dmarc` |
| Accounts | `/accounts` | Manage fetch mailboxes (IMAP / Gmail / Office 365) and view fetch status |
| Enrich | `/enrich` | Bulk-refresh reverse DNS/WHOIS and domain DNS checks in the background, with live progress |
| Export | `/export` | Management report download (CSV, XLSX, PDF, DOCX); optional `?domain=` and `?period=` filters |

### JSON API

All endpoints honour `period` (same values as the UI selector), `domain`, `ef` (envelope-from) and `compare=1` (also return the preceding window of equal length). The `/api/tls*` endpoints report `window.require_dkim`, which says whether reports failing the RFC 8460 §3 signature requirement were excluded from the figures, so a filtered period is never mistaken for a quiet one. Mutating endpoints take form-encoded bodies with the `_csrf` token of the page and accept a `redirect` field for use from HTML forms.

| Endpoint | Content |
|----------|---------|
| `GET /api/stats`, `/api/failure-modes`, `/api/domain-trend`, `/api/top-failing-sources` | Original endpoints (failure-modes now includes `both_pass` and `total`) |
| `GET /api/overview` | C1–C8, new-source count, health score, open alert count, previous window and deltas |
| `GET /api/auth-matrix` | The 2×2 matrix with shares |
| `GET /api/sources` (`sort`, `dir`, `pattern`, `matrix`, `new=1`, `min`, `q`, `limit`, `page`), `GET /api/sources/:ip`, `GET /api/new-sources`, `GET /api/spoof` | Source inventory, detail with timeline, new sources, spoof volume by SPF membership |
| `GET /api/auth`, `GET /api/policy` | A1–A8 and P1–P6 in one payload each |
| `GET /api/reporters`, `GET/POST/DELETE /api/managed-domains` | R1–R8; managed-domain list management |
| `GET /api/alerts?state=open\|ack\|all`, `POST /api/alerts/:id/ack`, `POST /api/alerts/evaluate` | Persisted alerts, acknowledgement, on-demand evaluation |
| `GET /api/tls` | T1–T15 in one payload, with the previous window when `compare=1` |
| `GET /api/tls/failures` (`result_type`, `mx`, `receiving_ip`, `sending_ip`) | Failure detail: by result type, receiver, sender, reason code, plus policy-host and DANE health, address family and incidents |
| `GET /api/tls/policies` | Policy-type mix, MTA-STS mode and enforcement readiness, same-day policy divergence |
| `GET /api/tls/reporters` | TLS reporter volume and share, coverage and latency, report hygiene |
| `GET /api/health`, `GET /api/health/:domain` | Health score with components |
| `POST /api/labels/:ip` (`label`, `classification`, `notes`), `POST /api/selectors/expected` (`domain`, `selector`, `expected`) | Source labels; selector expectations |

### Exporting a management report

Navigate to **Export** in the navigation bar. Choose a domain (or leave blank for all domains) and a format:

| Format | Description |
|--------|-------------|
| CSV | Flat spreadsheet, one row per DMARC record |
| XLSX | Excel workbook |
| PDF | Formatted report document |
| DOCX | Word-compatible document |

The downloaded file is named `dmarc-report-<domain|all>-<date>.<format>`.

Every format carries the same sections, scoped to the selected period and domain: summary and per-domain breakdown, the authentication matrix and enforcement effectiveness, published policy and its change log, top failing and new sources, open alerts, and an **SMTP TLS Reporting** section — success rate with its period-over-period delta, policy-type mix, failures by result type, the top failing receivers, MTA-STS enforcement readiness, and any open TLS alerts. A period with no TLS reports says so rather than showing a zero rate. Free text that arrives in a report (organisation names, result types, failure reason codes, additional information) is escaped in CSV and XLSX so a spreadsheet cannot evaluate it as a formula.

### Switching themes

Click the theme selector in the navigation bar (Pink / Blue / Goth). The selection is saved in a `ui_theme` cookie and persists across sessions. The default theme is **Goth**.

## Development

Run directly without building:

```bash
go run .
```

Run tests:

```bash
go test ./...
```

The database file is created automatically on first run. To start fresh, delete `dmarc.db`.

## Audit logging

All import events are written to syslog (`facility=DAEMON`, tag `dmarcreporter`). If the local syslog daemon is unavailable the same events are written to stderr.

Logged events:

| Event | Severity | Fields |
|-------|----------|--------|
| Report imported | INFO | `source`, `org`, `domain`, `report_id`, `records` |
| Report duplicate (skipped) | INFO | `source`, `org`, `report_id` |
| Report parse failed | WARNING | `source` (filename only, no internal detail) |
| IMAP fetch started | INFO | `mailbox` |
| IMAP fetch completed | INFO | `mailbox`, `imported` |
| IMAP fetch failed | ERROR | `mailbox` |

On macOS, view live audit events with:

```bash
log stream --predicate 'senderImagePath contains "dmarcreporter"'
```

On Linux (journald):

```bash
journalctl -t dmarcreporter -f
```

On Linux (syslog file):

```bash
grep dmarcreporter /var/log/syslog
```

## Network communications

The table below lists every connection the application makes or accepts. Use it to configure firewall rules for the host running DMARC Reporter.

### Inbound

| Port | Protocol | Direction | Purpose | Required |
|------|----------|-----------|---------|----------|
| `8080` ¹ | TCP | → server | Web UI and API — browser or reverse-proxy to application | Always |

¹ Configurable via the `PORT` environment variable.

### Outbound

| Port | Protocol | Direction | Purpose | Required |
|------|----------|-----------|---------|----------|
| `993` ² | TCP | server → | IMAP over TLS — fetching reports from configured mail accounts | Only when accounts are configured |
| `143` ² | TCP | server → | IMAP with STARTTLS or unencypted — **dev/test only**, never use it unencrypted in production | Only when TLS is disabled on an account or it uses STARTTLS |
| `443` | TCP | server → | OAuth2 token endpoints (`oauth2.googleapis.com`, `login.microsoftonline.com`) | Only for Gmail/O365 OAuth accounts |
| `443` | TCP | server → | Alert webhook delivery | Only when `ALERT_WEBHOOK_URL` is set |
| `587` | TCP | server → | SMTP submission for alert emails | Only when `SMTP_HOST` is set |
| `53` | UDP + TCP | server → | DNS — DMARC (`_dmarc.*`), BIMI (`default._bimi.*`), MTA-STS (`_mta-sts.*`) record lookups, SPF expansion (TXT, A/AAAA, MX for each domain and its includes), and reverse DNS for source IPs; uses the system resolver | When the Enrich or Domain Detail features are used |
| `53` | UDP + TCP | server → | DNS — the published TLS records of each domain: `_smtp._tls.<domain>` and `_mta-sts.<domain>` TXT, MX, and a TLSA query for `_25._tcp.<mx>` per MX host. The TLSA query is sent directly to the nameservers in `/etc/resolv.conf` (or `DNS_SERVER`), because Go's resolver cannot query that record type | When the Enrich feature is used |
| `53` | UDP + TCP | server → | DNS — DKIM key records (`<selector>._domainkey.<reporting-domain>`) while importing a TLS report, to verify the signature RFC 8460 §3 requires and read its `s=tlsrpt` service tag from the same answer; best-effort with a 5s timeout, and a failure records the report as `dkim_status=unknown` rather than delaying the import | Whenever TLS-RPT reports are imported from a mailbox |
| `443` | TCP | server → | HTTPS — MTA-STS policy fetch from `https://mta-sts.<domain>/.well-known/mta-sts.txt` for each managed or reported domain, with certificate verification and no redirects followed (RFC 8461 §3.3) | When the Enrich feature is used |
| `43` | TCP | server → | WHOIS — organisation, country, network, and abuse-contact lookups for source IPs; connections go to the authoritative WHOIS server for each IP block (ARIN, RIPE, APNIC, LACNIC, AFRINIC, etc.) | When the Enrich or Source Detail features are used |

² Configurable via the `IMAP_PORT` environment variable.

> **Note for restrictive egress policies:** WHOIS (port 43) and most DNS (port 53) use is only needed for the enrichment features (Enrich page, Domain detail page, Source detail page). The application is fully functional for report import and display without them — source IPs will simply show without geo/WHOIS data. The one exception is DKIM verification of mailed TLS reports, which looks up the reporter's key record during import: without DNS those reports import with `dkim_status=unknown`, and with `TLSRPT_REQUIRE_DKIM=true` (the default) they are then left out of the TLS metrics.

## Security notes

- `AUTH_PASSWORD` is required at startup; the application refuses to start without it unless `AUTH_DISABLED=true` is explicitly set (development only)
- Repeated failed logins lock the client IP out for `AUTH_FAIL_WINDOW` (see `AUTH_FAIL_MAX`). When running behind a reverse proxy, configure Fiber's trusted-proxy settings or rate-limit at the proxy, since all clients otherwise share the proxy's IP
- CSRF tokens are required on all state-mutating POST requests
- Report content is untrusted (anyone can mail a report to the monitored mailbox): records whose `source_ip` is not a valid IP address are dropped at import, negative counts are clamped, and only reports up to 8 MB have their original XML kept for download (larger ones are still imported)
- Flash messages use `HttpOnly`, `Secure`, and `SameSite=Lax` cookies
- HTTP security headers are set on all responses (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Uploaded and fetched files are limited to 10 MB before decompression; decompressed content is capped at 50 MB to prevent decompression bomb attacks
- XML entity expansion is disabled to prevent XXE attacks
- Report fields (org name, envelope-to, etc.) are sanitized before being written into CSV/XLSX exports, preventing formula/DDE injection when the file is opened in a spreadsheet application
- IMAP plaintext mode (`IMAP_TLS=false`) logs a warning at startup and should only be used for local testing
