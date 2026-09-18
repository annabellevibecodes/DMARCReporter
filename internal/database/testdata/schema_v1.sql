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
