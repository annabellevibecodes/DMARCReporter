package database

import (
	"github.com/jmoiron/sqlx"
)

// DomainCheck holds the cached DNS check results for a single domain.
type DomainCheck struct {
	Domain    string `db:"domain"`
	HasDMARC  int    `db:"has_dmarc"`   // 1 = record found, 0 = not found
	HasBIMI   int    `db:"has_bimi"`
	HasMTASTS int    `db:"has_mta_sts"`
	CheckedAt int64  `db:"checked_at"` // Unix timestamp; 0 = never checked
}

// UpsertDomainCheck inserts or updates the DNS check result for a domain.
func UpsertDomainCheck(db *sqlx.DB, dc DomainCheck) error {
	_, err := db.Exec(`
		INSERT INTO domain_checks (domain, has_dmarc, has_bimi, has_mta_sts, checked_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			has_dmarc   = excluded.has_dmarc,
			has_bimi    = excluded.has_bimi,
			has_mta_sts = excluded.has_mta_sts,
			checked_at  = excluded.checked_at`,
		dc.Domain, dc.HasDMARC, dc.HasBIMI, dc.HasMTASTS, dc.CheckedAt)
	return err
}

// GetAllDomainChecks returns all cached domain check results keyed by domain name.
func GetAllDomainChecks(db *sqlx.DB) (map[string]DomainCheck, error) {
	var rows []DomainCheck
	if err := db.Select(&rows, `SELECT domain, has_dmarc, has_bimi, has_mta_sts, checked_at FROM domain_checks`); err != nil {
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
	_, err := db.Exec(`DELETE FROM domain_checks`)
	return err
}

// ListUncachedSourceIPs returns distinct source IPs from record_rows that have
// never been looked up in ip_info (looked_up_at = 0 or missing).
func ListUncachedSourceIPs(db *sqlx.DB) ([]string, error) {
	var ips []string
	err := db.Select(&ips, `
		SELECT DISTINCT rr.source_ip
		FROM record_rows rr
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip
		WHERE ii.ip IS NULL OR ii.looked_up_at = 0`)
	return ips, err
}
