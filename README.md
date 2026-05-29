# DMARC Reporter

> This web application is vibe coded. Use at your own risk.

A web application for parsing, storing, and visualising DMARC aggregate reports. Reports can be uploaded manually or fetched automatically from an IMAP mailbox.

## Features

- Parse DMARC aggregate report XML files (`.xml`, `.xml.gz`, `.gz`, `.zip`) and raw email files (`.eml`)
- Fetch reports directly from an IMAP mailbox; processed emails are moved to a configurable subfolder
- Dashboard with pass/fail statistics, failure modes, top failing sources, and a weekly trend chart
- Three UI themes — **Goth** (terminal), **Pink** (Y2K glam), **Blue** (newspaper) — switchable at any time, persisted via cookie
- DKIM selector statistics on domain and report detail pages
- Management report export in CSV, XLSX, PDF, and DOCX
- Browse reports, domains, and source IPs with sortable column headers
- Filter reports by domain and date range; filter sources by IP, envelope-from, disposition, and minimum message count (slider)
- Reporting period selector on all list pages — All Time, 2 Years, 1 Year, 6/3 Months, Last Month, 30/14/7/3/2 Days, Last 24 Hours
- HTTP Basic Auth with configurable username and password
- Rate limiting on upload and IMAP fetch endpoints
- SQLite storage — no external database required

## Requirements

- Go 1.22 or later

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

### With IMAP

```bash
IMAP_HOST=mail.example.com \
IMAP_USER=dmarc@example.com \
IMAP_PASS=secret \
./dmarcreporter
```

When IMAP is configured, a **Fetch IMAP** button appears in the navigation bar. Clicking it fetches all unread messages from the configured mailbox, extracts any DMARC report attachments, imports them, and moves the processed emails to `INBOX.Processed` (configurable).

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
| `FETCH_RATE_MAX` | `3` | Maximum IMAP fetch requests per 5 minutes per IP (0 to disable) |
| `IMAP_HOST` | _(unset)_ | IMAP server hostname. IMAP is disabled when unset. |
| `IMAP_PORT` | `993` | IMAP server port |
| `IMAP_USER` | _(unset)_ | IMAP username |
| `IMAP_PASS` | _(unset)_ | IMAP password |
| `IMAP_MAILBOX` | `INBOX` | Mailbox to fetch reports from |
| `IMAP_PROCESSED_MAILBOX` | `INBOX.Processed` | Mailbox to move processed emails to |
| `IMAP_TLS` | `true` | Use TLS. Set to `false` only for local testing. |

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

### Fetching from IMAP

Click **Fetch IMAP** in the navigation bar. The application will:

1. Connect to the configured IMAP server over TLS
2. Search for unread messages in `IMAP_MAILBOX`
3. Extract any DMARC report attachments
4. Parse and import them into the database
5. Move each processed email to `IMAP_PROCESSED_MAILBOX`

The subfolder is created automatically if it does not exist.

### Viewing data

| Page | URL | Description |
|------|-----|-------------|
| Dashboard | `/` | Summary stats and weekly pass/fail trend chart |
| Reports | `/reports` | All imported reports, filterable by domain and date |
| Report detail | `/reports/:id` | Individual report with per-IP record breakdown |
| Domains | `/domains` | All domains with aggregate message counts |
| Domain detail | `/domains/:domain` | Per-domain records across all reports |
| Sources | `/sources` | All source IPs, filterable by period, envelope-from, IP, and minimum message count |
| Source detail | `/sources/:ip` | Per-IP records across all reports |
| Export | `/export` | Management report download (CSV, XLSX, PDF, DOCX); optional `?domain=` filter |

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
| `993` ² | TCP | server → | IMAP over TLS — fetching DMARC reports from a mailbox | Only when `IMAP_HOST` is set |
| `143` ² | TCP | server → | IMAP without TLS — **dev/test only**, never use in production | Only when `IMAP_TLS=false` |
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
- IMAP plaintext mode (`IMAP_TLS=false`) logs a warning at startup and should only be used for local testing
