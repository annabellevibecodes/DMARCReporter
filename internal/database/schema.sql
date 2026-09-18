PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS reports (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    org_name            TEXT    NOT NULL,
    email               TEXT    NOT NULL DEFAULT '',
    extra_contact_info  TEXT    NOT NULL DEFAULT '',
    report_id           TEXT    NOT NULL,
    date_range_begin    INTEGER NOT NULL,
    date_range_end      INTEGER NOT NULL,
    domain              TEXT    NOT NULL,
    adkim               TEXT    NOT NULL DEFAULT 'r',
    aspf                TEXT    NOT NULL DEFAULT 'r',
    policy              TEXT    NOT NULL DEFAULT 'none',
    subdomain_policy    TEXT    NOT NULL DEFAULT 'none',
    pct                 INTEGER NOT NULL DEFAULT 100,
    failure_options     TEXT    NOT NULL DEFAULT '0',
    imported_at         INTEGER NOT NULL DEFAULT (unixepoch()),
    source_filename     TEXT    NOT NULL DEFAULT '',
    -- Columns below were added by the analytics extension. They are also
    -- listed in db.go (reportColumns) so existing databases gain them via
    -- ALTER TABLE on startup.
    version             TEXT    NOT NULL DEFAULT '',   -- raw <version> text ('1.0', '0.1', '')
    xml_namespace       TEXT    NOT NULL DEFAULT '',   -- '' or 'urn:ietf:params:xml:ns:dmarc-2.0'
    np                  TEXT    NOT NULL DEFAULT '',   -- '' = not present (never defaulted to 'none')
    discovery_method    TEXT    NOT NULL DEFAULT '',
    testing             TEXT    NOT NULL DEFAULT '',
    generator           TEXT    NOT NULL DEFAULT '',
    report_errors       TEXT    NOT NULL DEFAULT '',   -- JSON array of <report_metadata><error>
    received_at         INTEGER NOT NULL DEFAULT 0,    -- mail Date header; 0 for bare uploads
    sp_present          INTEGER NOT NULL DEFAULT 0,    -- 1 when <sp> was in the XML
    pct_present         INTEGER NOT NULL DEFAULT 0,    -- 1 when <pct> was in the XML
    fo_present          INTEGER NOT NULL DEFAULT 0,    -- 1 when <fo> was in the XML
    UNIQUE (org_name, report_id)
);

CREATE INDEX IF NOT EXISTS idx_reports_domain      ON reports(domain);
CREATE INDEX IF NOT EXISTS idx_reports_date_begin  ON reports(date_range_begin);
CREATE INDEX IF NOT EXISTS idx_reports_date_end    ON reports(date_range_end);
CREATE INDEX IF NOT EXISTS idx_reports_imported_at ON reports(imported_at);

CREATE TABLE IF NOT EXISTS record_rows (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id     INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    source_ip     TEXT    NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0,
    disposition   TEXT    NOT NULL DEFAULT 'none',
    eval_dkim     TEXT    NOT NULL DEFAULT 'fail',
    eval_spf      TEXT    NOT NULL DEFAULT 'fail',
    envelope_to   TEXT    NOT NULL DEFAULT '',
    envelope_from TEXT    NOT NULL DEFAULT '',
    header_from   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_record_rows_report_id   ON record_rows(report_id);
CREATE INDEX IF NOT EXISTS idx_record_rows_source_ip   ON record_rows(source_ip);
CREATE INDEX IF NOT EXISTS idx_record_rows_eval_dkim   ON record_rows(eval_dkim);
CREATE INDEX IF NOT EXISTS idx_record_rows_eval_spf    ON record_rows(eval_spf);
CREATE INDEX IF NOT EXISTS idx_record_rows_disposition ON record_rows(disposition);

CREATE TABLE IF NOT EXISTS dkim_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    record_row_id INTEGER NOT NULL REFERENCES record_rows(id) ON DELETE CASCADE,
    domain        TEXT    NOT NULL DEFAULT '',
    selector      TEXT    NOT NULL DEFAULT '',
    result        TEXT    NOT NULL DEFAULT 'none',
    human_result  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_dkim_results_record_row_id ON dkim_results(record_row_id);
CREATE INDEX IF NOT EXISTS idx_dkim_results_domain        ON dkim_results(domain);
CREATE INDEX IF NOT EXISTS idx_dkim_results_result        ON dkim_results(result);

CREATE TABLE IF NOT EXISTS spf_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    record_row_id INTEGER NOT NULL REFERENCES record_rows(id) ON DELETE CASCADE,
    domain        TEXT    NOT NULL DEFAULT '',
    scope         TEXT    NOT NULL DEFAULT 'mfrom',
    result        TEXT    NOT NULL DEFAULT 'none'
);

CREATE INDEX IF NOT EXISTS idx_spf_results_record_row_id ON spf_results(record_row_id);
CREATE INDEX IF NOT EXISTS idx_spf_results_domain        ON spf_results(domain);
CREATE INDEX IF NOT EXISTS idx_spf_results_result        ON spf_results(result);

CREATE TABLE IF NOT EXISTS policy_overrides (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    record_row_id INTEGER NOT NULL REFERENCES record_rows(id) ON DELETE CASCADE,
    type          TEXT    NOT NULL DEFAULT '',
    comment       TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_record_row_id ON policy_overrides(record_row_id);

-- Stores the original decompressed XML for each imported report.
-- Kept in a separate table so queries on reports are not burdened by the blob.
CREATE TABLE IF NOT EXISTS report_xml (
    report_id INTEGER PRIMARY KEY REFERENCES reports(id) ON DELETE CASCADE,
    xml_data  TEXT    NOT NULL DEFAULT ''
);

-- Cache for per-domain DNS checks (DMARC / BIMI / MTA-STS).
-- checked_at = 0 means never checked.
CREATE TABLE IF NOT EXISTS domain_checks (
    domain      TEXT    PRIMARY KEY,
    has_dmarc   INTEGER NOT NULL DEFAULT 0,
    has_bimi    INTEGER NOT NULL DEFAULT 0,
    has_mta_sts INTEGER NOT NULL DEFAULT 0,
    checked_at  INTEGER NOT NULL DEFAULT 0
);

-- Cache for reverse DNS and WHOIS lookups.
-- looked_up_at = 0 means never looked up.
CREATE TABLE IF NOT EXISTS ip_info (
    ip            TEXT    PRIMARY KEY,
    rdns          TEXT    NOT NULL DEFAULT '',
    whois_org     TEXT    NOT NULL DEFAULT '',
    whois_net     TEXT    NOT NULL DEFAULT '',
    whois_country TEXT    NOT NULL DEFAULT '',
    whois_cidr    TEXT    NOT NULL DEFAULT '',
    whois_abuse   TEXT    NOT NULL DEFAULT '',
    looked_up_at  INTEGER NOT NULL DEFAULT 0
);

-- Mail accounts to fetch DMARC reports from. Secrets (passwords, OAuth client
-- secrets, refresh tokens) are stored AES-GCM-encrypted in secret_enc.
CREATE TABLE IF NOT EXISTS accounts (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    name                TEXT    NOT NULL UNIQUE,
    provider            TEXT    NOT NULL DEFAULT 'imap',      -- imap | gmail | o365 | msgraph
    host                TEXT    NOT NULL DEFAULT '',
    port                TEXT    NOT NULL DEFAULT '993',
    username            TEXT    NOT NULL DEFAULT '',
    auth_type           TEXT    NOT NULL DEFAULT 'password',  -- password | oauth-refresh | oauth-client
    secret_enc          TEXT    NOT NULL DEFAULT '',
    mailbox             TEXT    NOT NULL DEFAULT 'INBOX',
    processed_mailbox   TEXT    NOT NULL DEFAULT '',          -- empty = auto (INBOX<delim>Processed)
    tls                 INTEGER NOT NULL DEFAULT 1,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL DEFAULT (unixepoch()),
    last_fetch_at       INTEGER NOT NULL DEFAULT 0,
    last_fetch_status   TEXT    NOT NULL DEFAULT '',          -- '', 'ok', 'error', 'running'
    last_fetch_detail   TEXT    NOT NULL DEFAULT '',
    last_fetch_imported INTEGER NOT NULL DEFAULT 0
);

-- UIDs already examined (and found to carry no report attachments), so
-- subsequent fetches skip them without re-downloading. Scoped by UIDVALIDITY;
-- rows for a stale UIDVALIDITY are purged on the next fetch.
CREATE TABLE IF NOT EXISTS imap_seen (
    account_id  INTEGER NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid         INTEGER NOT NULL,
    seen_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (account_id, uidvalidity, uid)
);

-- Graph message IDs already examined (and found to carry no report
-- attachments), so subsequent fetches skip them without re-downloading.
-- Equivalent to imap_seen but for the Microsoft Graph API provider, whose
-- message IDs are opaque strings rather than UID/UIDVALIDITY pairs.
CREATE TABLE IF NOT EXISTS graph_seen (
    account_id  INTEGER NOT NULL,
    message_id  TEXT    NOT NULL,
    seen_at     INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (account_id, message_id)
);

-- SMTP TLS reports (RFC 8460), delivered as JSON alongside DMARC reports.
CREATE TABLE IF NOT EXISTS tlsrpt_reports (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    org_name         TEXT    NOT NULL,
    report_id        TEXT    NOT NULL,
    contact_info     TEXT    NOT NULL DEFAULT '',
    date_range_begin INTEGER NOT NULL,
    date_range_end   INTEGER NOT NULL,
    policy_domains   TEXT    NOT NULL DEFAULT '', -- comma-separated
    total_success    INTEGER NOT NULL DEFAULT 0,
    total_failure    INTEGER NOT NULL DEFAULT 0,
    raw_json         TEXT    NOT NULL DEFAULT '',
    imported_at      INTEGER NOT NULL DEFAULT (unixepoch()),
    source_filename  TEXT    NOT NULL DEFAULT '',
    UNIQUE (org_name, report_id)
);

CREATE INDEX IF NOT EXISTS idx_tlsrpt_date_begin ON tlsrpt_reports(date_range_begin);

-- Alert deduplication: one row per alert already delivered.
CREATE TABLE IF NOT EXISTS alerts_sent (
    key     TEXT    PRIMARY KEY,
    sent_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Key/value store for one-off migration markers (backfill done, seeds applied).
CREATE TABLE IF NOT EXISTS app_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

-- User-set labels and classification overrides for source IPs.
CREATE TABLE IF NOT EXISTS ip_labels (
    ip             TEXT    PRIMARY KEY,
    label          TEXT    NOT NULL DEFAULT '',
    classification TEXT    NOT NULL DEFAULT '',   -- '' | known_good | forwarder | unknown | suspicious
    notes          TEXT    NOT NULL DEFAULT '',
    updated_at     INTEGER NOT NULL DEFAULT 0
);

-- DKIM selector inventory, maintained on ingest (one row per signing domain +
-- selector). first_seen / last_seen are report date_range_begin values so the
-- table is reproducible from the stored XML. expected: -1 unset, 0 no, 1 yes.
CREATE TABLE IF NOT EXISTS selectors (
    domain     TEXT    NOT NULL,
    selector   TEXT    NOT NULL,
    first_seen INTEGER NOT NULL DEFAULT 0,
    last_seen  INTEGER NOT NULL DEFAULT 0,
    expected   INTEGER NOT NULL DEFAULT -1,
    PRIMARY KEY (domain, selector)
);

-- Domains the operator considers their own. Seeded from reports.domain once.
CREATE TABLE IF NOT EXISTS managed_domains (
    domain   TEXT    PRIMARY KEY,
    added_at INTEGER NOT NULL DEFAULT (unixepoch())
);

-- One row per attachment processed by any ingest path.
CREATE TABLE IF NOT EXISTS ingest_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL DEFAULT (unixepoch()),
    source    TEXT    NOT NULL DEFAULT '',   -- upload | imap | graph
    filename  TEXT    NOT NULL DEFAULT '',
    kind      TEXT    NOT NULL DEFAULT '',   -- dmarc | tlsrpt | unknown
    status    TEXT    NOT NULL DEFAULT '',   -- ok | duplicate | parse_error | rejected
    org_name  TEXT    NOT NULL DEFAULT '',
    report_id TEXT    NOT NULL DEFAULT '',
    error     TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_ingest_events_at     ON ingest_events(at);
CREATE INDEX IF NOT EXISTS idx_ingest_events_status ON ingest_events(status);

-- Persisted, acknowledgeable alerts. alerts_sent stays for delivery dedupe.
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule            TEXT    NOT NULL,
    domain          TEXT    NOT NULL DEFAULT '',
    key             TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL DEFAULT 'info',   -- info | warning | critical
    message         TEXT    NOT NULL DEFAULT '',
    first_fired     INTEGER NOT NULL DEFAULT 0,
    last_fired      INTEGER NOT NULL DEFAULT 0,
    count           INTEGER NOT NULL DEFAULT 1,
    acknowledged_at INTEGER NOT NULL DEFAULT 0,
    payload         TEXT    NOT NULL DEFAULT '',       -- JSON
    UNIQUE (rule, domain, key)
);

CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged_at);

-- Resolved SPF authorisation per domain (all CIDRs the SPF record expands to).
CREATE TABLE IF NOT EXISTS spf_authorized_cache (
    domain     TEXT    PRIMARY KEY,
    cidrs      TEXT    NOT NULL DEFAULT '[]',  -- JSON array of CIDR strings
    lookups    INTEGER NOT NULL DEFAULT 0,
    over_limit INTEGER NOT NULL DEFAULT 0,
    error      TEXT    NOT NULL DEFAULT '',
    checked_at INTEGER NOT NULL DEFAULT 0
);
