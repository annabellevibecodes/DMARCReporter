package database

import "github.com/jmoiron/sqlx"

// CountOverrideMessages returns the message volume carrying a policy override
// for domain ("" = all) in reports whose window begins in [from, to).
func CountOverrideMessages(db *sqlx.DB, domain string, from, to int64) (int64, error) {
	var n int64
	q := `
		SELECT COALESCE(SUM(rr.count), 0)
		FROM policy_overrides po
		JOIN record_rows rr ON rr.id = po.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE r.date_range_begin >= ? AND r.date_range_begin < ?`
	if domain != "" {
		err := db.Get(&n, q+` AND r.domain = ?`, from, to, domain)
		return n, err
	}
	err := db.Get(&n, q, from, to)
	return n, err
}

// CountDistinctReporters returns the number of distinct reporters with a
// report window beginning at or after since, optionally for one domain.
func CountDistinctReporters(db *sqlx.DB, domain string, since int64) (int, error) {
	var n int
	if domain != "" {
		err := db.Get(&n, `SELECT COUNT(DISTINCT org_name) FROM reports WHERE date_range_begin >= ? AND domain = ?`, since, domain)
		return n, err
	}
	err := db.Get(&n, `SELECT COUNT(DISTINCT org_name) FROM reports WHERE date_range_begin >= ?`, since)
	return n, err
}
