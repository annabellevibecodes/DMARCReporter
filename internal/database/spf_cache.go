package database

import "github.com/jmoiron/sqlx"

// ListStaleSPFDomains returns every domain that should have an SPF expansion
// (managed domains plus every reports.domain) whose cache entry is missing or
// older than cutoff (Unix seconds).
func ListStaleSPFDomains(db *sqlx.DB, cutoff int64) ([]string, error) {
	var out []string
	err := db.Select(&out, `
		SELECT d.domain FROM (
			SELECT domain FROM managed_domains
			UNION
			SELECT DISTINCT domain FROM reports WHERE domain != ''
		) d
		LEFT JOIN spf_authorized_cache c ON c.domain = d.domain
		WHERE c.domain IS NULL OR c.checked_at = 0 OR c.checked_at < ?
		ORDER BY d.domain`, cutoff)
	return out, err
}

// CountSPFDomains returns how many domains are in scope for SPF resolution.
func CountSPFDomains(db *sqlx.DB) (int, error) {
	var n int
	err := db.Get(&n, `
		SELECT COUNT(*) FROM (
			SELECT domain FROM managed_domains
			UNION
			SELECT DISTINCT domain FROM reports WHERE domain != ''
		)`)
	return n, err
}
