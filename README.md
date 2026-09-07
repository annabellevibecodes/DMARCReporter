# DMARC Reporter

> This web application is vibe coded. Use at your own risk.

A web application for parsing, storing, and visualising DMARC aggregate reports. Reports can be uploaded manually or fetched automatically from IMAP mailboxes — including **Gmail** and **Office 365** via OAuth2.

## Features

- Parse DMARC aggregate report XML files (`.xml`, `.xml.gz`, `.gz`, `.zip`), raw email files (`.eml`), and SMTP TLS reports (RFC 8460, `.json` / `.json.gz`)
- Fetch reports from multiple mailboxes managed under **Accounts**: generic IMAP (password), **Gmail / Google Workspace** (app password or OAuth2), and **Office 365** via IMAP or the **Microsoft Graph API** (both OAuth2 client credentials — required, since Microsoft disabled basic auth)
- Background fetching: manual trigger or scheduled via `FETCH_INTERVAL`; a two-phase BODYSTRUCTURE fetch downloads only messages that carry report attachments, and report-free messages are cached by UID so they are never downloaded twice
- Processed emails are moved to a subfolder; the folder name adapts to the server's hierarchy delimiter (`INBOX.Processed` on Dovecot, `INBOX/Processed` on Gmail/O365) unless overridden
- Account credentials are encrypted at rest (AES-256-GCM) with `SECRETS_KEY` or an auto-generated key file next to the database
- Dashboard with pass/fail statistics, failure modes, top failing sources, policy-override ("forgiven failures") breakdown, and an adaptive trend chart (daily buckets for short periods, weekly beyond ~3 months, gaps filled)
- Known-sender classification: source IPs are labelled with their provider (Google, Microsoft 365, SendGrid, …) from cached reverse DNS
- Enrich page for bulk-refreshing reverse DNS/WHOIS (source IPs) and DMARC/BIMI/MTA-STS domain checks in the background, with live progress via Server-Sent Events; a run keeps going even if the browser tab is closed
- Alerts on pass-rate drops and new failing sources, delivered via webhook and/or SMTP email
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
| `HSTS_ENABLED` | `false` | Set to `true` to send `Strict-Transport-Security` headers. Enable whenever the application is served over HTTPS. |
| `UPLOAD_RATE_MAX` | `20` | Maximum file uploads per minute per IP (0 to disable) |
| `FETCH_RATE_MAX` | `3` | Maximum fetch requests per 5 minutes per IP (0 to disable) |
| `BASE_URL` | `http://localhost:<PORT>` | External base URL of the app; used to build the Google OAuth redirect URI |
| `SECRETS_KEY` | _(unset)_ | Key for encrypting account credentials at rest (64-char hex, or any passphrase). When unset a random key is generated in `<DB_PATH>.key` (mode 0600). |
| `FETCH_INTERVAL` | _(unset)_ | Background fetch interval (Go duration, e.g. `30m`, `4h`). Unset = manual fetch only. |
| `IMAP_HOST` | _(unset)_ | Legacy single-account config: IMAP server hostname. Mirrored into the Accounts page on startup. |
| `IMAP_PORT` | `993` | IMAP server port |
| `IMAP_USER` | _(unset)_ | IMAP username |
| `IMAP_PASS` | _(unset)_ | IMAP password |
| `IMAP_MAILBOX` | `INBOX` | Mailbox to fetch reports from |
| `IMAP_PROCESSED_MAILBOX` | _(auto)_ | Mailbox to move processed emails to. When unset, derived from the server's hierarchy delimiter (`INBOX.Processed`, `INBOX/Processed`, …). |
| `IMAP_TLS` | `true` | Use TLS. Set to `false` only for local testing. |
| `ALERT_WEBHOOK_URL` | _(unset)_ | POST target for JSON alert notifications (pass-rate drop, new failing source) |
| `ALERT_PASS_RATE_DROP` | `5.0` | Alert when the 7-day pass rate drops by more than this many percentage points week-over-week |
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
| Sources | `/sources` | All source IPs with provider labels, filterable by period, envelope-from, IP, and minimum message count |
| Source detail | `/sources/:ip` | Per-IP records across all reports |
| TLS reports | `/tlsrpt` | SMTP TLS reports (RFC 8460) with session success/failure counts |
| Accounts | `/accounts` | Manage fetch mailboxes (IMAP / Gmail / Office 365) and view fetch status |
| Enrich | `/enrich` | Bulk-refresh reverse DNS/WHOIS and domain DNS checks in the background, with live progress |
| Export | `/export` | Management report download (CSV, XLSX, PDF, DOCX); optional `?domain=` and `?period=` filters |

A JSON endpoint at `/api/stats?days=90` returns trend data for programmatic use.

### Exporting a management report

Navigate to **Export** in the navigation bar. Choose a domain (or leave blank for all domains) and a format:

| Format | Description |
|--------|-------------|
| CSV | Flat spreadsheet, one row per DMARC record |
| XLSX | Excel workbook |
| PDF | Formatted report document |
| DOCX | Word-compatible document |

The downloaded file is named `dmarc-report-<domain|all>-<date>.<format>`.

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
| `53` | UDP + TCP | server → | DNS — DMARC (`_dmarc.*`), BIMI (`default._bimi.*`), MTA-STS (`_mta-sts.*`) record lookups, and reverse DNS for source IPs; uses the system resolver | When the Enrich or Domain Detail features are used |
| `43` | TCP | server → | WHOIS — organisation, country, network, and abuse-contact lookups for source IPs; connections go to the authoritative WHOIS server for each IP block (ARIN, RIPE, APNIC, LACNIC, AFRINIC, etc.) | When the Enrich or Source Detail features are used |

² Configurable via the `IMAP_PORT` environment variable.

> **Note for restrictive egress policies:** DNS (port 53) and WHOIS (port 43) are only needed if you use the enrichment features (Enrich page, Domain detail page, Source detail page). The application is fully functional for report import and display without them — source IPs will simply show without geo/WHOIS data.

## Security notes

- `AUTH_PASSWORD` is required at startup; the application refuses to start without it unless `AUTH_DISABLED=true` is explicitly set (development only)
- CSRF tokens are required on all state-mutating POST requests
- Flash messages use `HttpOnly`, `Secure`, and `SameSite=Lax` cookies
- HTTP security headers are set on all responses (CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Uploaded and fetched files are limited to 10 MB before decompression; decompressed content is capped at 50 MB to prevent decompression bomb attacks
- XML entity expansion is disabled to prevent XXE attacks
- Report fields (org name, envelope-to, etc.) are sanitized before being written into CSV/XLSX exports, preventing formula/DDE injection when the file is opened in a spreadsheet application
- IMAP plaintext mode (`IMAP_TLS=false`) logs a warning at startup and should only be used for local testing
