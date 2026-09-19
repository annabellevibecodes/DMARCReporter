package database

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
)

// DomainCheck holds the cached DNS check results for a single domain.
//
// The record text is cached alongside the booleans so the domain page can
// render what a domain publishes without resolving anything: every DNS query
// in this application happens in the Enrich worker or the background
// refresher, never while an HTTP request is waiting on it.
type DomainCheck struct {
	Domain    string `db:"domain"`
	HasDMARC  int    `db:"has_dmarc"` // 1 = record found, 0 = not found
	HasBIMI   int    `db:"has_bimi"`
	HasMTASTS int    `db:"has_mta_sts"`
	CheckedAt int64  `db:"checked_at"` // Unix timestamp; 0 = never checked

	// DMARCRecord and MTASTSRecord are the raw TXT strings as published; the
	// *Error fields hold a lookup failure, which is a different state from a
	// domain that publishes nothing.
	DMARCRecord  string `db:"dmarc_record"`
	DMARCError   string `db:"dmarc_error"`
	MTASTSRecord string `db:"mta_sts_record"`
	MTASTSError  string `db:"mta_sts_error"`
}

// Checked reports whether this domain has ever been looked up.
func (dc DomainCheck) Checked() bool { return dc.CheckedAt > 0 }

// UpsertDomainCheck inserts or updates the DNS check result for a domain.
func UpsertDomainCheck(db *sqlx.DB, dc DomainCheck) error {
	_, err := db.Exec(`
		INSERT INTO domain_checks
			(domain, has_dmarc, has_bimi, has_mta_sts, checked_at,
			 dmarc_record, dmarc_error, mta_sts_record, mta_sts_error)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(domain) DO UPDATE SET
			has_dmarc      = excluded.has_dmarc,
			has_bimi       = excluded.has_bimi,
			has_mta_sts    = excluded.has_mta_sts,
			checked_at     = excluded.checked_at,
			dmarc_record   = excluded.dmarc_record,
			dmarc_error    = excluded.dmarc_error,
			mta_sts_record = excluded.mta_sts_record,
			mta_sts_error  = excluded.mta_sts_error`,
		dc.Domain, dc.HasDMARC, dc.HasBIMI, dc.HasMTASTS, dc.CheckedAt,
		dc.DMARCRecord, dc.DMARCError, dc.MTASTSRecord, dc.MTASTSError)
	return err
}

// GetDomainCheck returns one domain's cached check, or a zero value with
// CheckedAt 0 when it has never been looked up.
func GetDomainCheck(db *sqlx.DB, domain string) (DomainCheck, error) {
	var dc DomainCheck
	err := db.Get(&dc, `SELECT * FROM domain_checks WHERE domain = ?`, domain)
	if err == sql.ErrNoRows {
		return DomainCheck{Domain: domain}, nil
	}
	return dc, err
}

// GetAllDomainChecks returns all cached domain check results keyed by domain name.
func GetAllDomainChecks(db *sqlx.DB) (map[string]DomainCheck, error) {
	var rows []DomainCheck
	if err := db.Select(&rows, `SELECT * FROM domain_checks`); err != nil {
		return nil, err
	}
	m := make(map[string]DomainCheck, len(rows))
	for _, r := range rows {
		m[r.Domain] = r
	}
	return m, nil
}

// ClearDNSCache deletes all cached DNS data: ip_info rows and domain_checks rows.
// This forces a full re-enrichment on the next run.
func ClearDNSCache(db *sqlx.DB) error {
	if _, err := db.Exec(`DELETE FROM ip_info`); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM domain_checks`); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM spf_authorized_cache`)
	return err
}

// ListStaleSourceIPs returns distinct source IPs from record_rows whose
// ip_info cache is missing, never looked up, or older than cutoff (a Unix
// timestamp) — i.e. everything a bulk enrichment run should refresh.
func ListStaleSourceIPs(db *sqlx.DB, cutoff int64) ([]string, error) {
	var ips []string
	err := db.Select(&ips, `
		SELECT DISTINCT rr.source_ip
		FROM record_rows rr
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip
		WHERE ii.ip IS NULL OR ii.looked_up_at = 0 OR ii.looked_up_at < ?`, cutoff)
	return ips, err
}
