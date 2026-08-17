package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
	"github.com/jmoiron/sqlx"
)

// TLSRPTReport is the database representation of one SMTP TLS report.
type TLSRPTReport struct {
	ID             int64  `db:"id"`
	OrgName        string `db:"org_name"`
	ReportID       string `db:"report_id"`
	ContactInfo    string `db:"contact_info"`
	DateRangeBegin int64  `db:"date_range_begin"`
	DateRangeEnd   int64  `db:"date_range_end"`
	PolicyDomains  string `db:"policy_domains"`
	TotalSuccess   int64  `db:"total_success"`
	TotalFailure   int64  `db:"total_failure"`
	RawJSON        string `db:"raw_json"`
	ImportedAt     int64  `db:"imported_at"`
	SourceFilename string `db:"source_filename"`
}

// BeginTime returns DateRangeBegin as a UTC time.Time.
func (r TLSRPTReport) BeginTime() time.Time { return time.Unix(r.DateRangeBegin, 0).UTC() }

// EndTime returns DateRangeEnd as a UTC time.Time.
func (r TLSRPTReport) EndTime() time.Time { return time.Unix(r.DateRangeEnd, 0).UTC() }

// SaveTLSRPT stores a parsed TLS report. Returns ErrDuplicate when the same
// (org, report-id) pair was imported before.
func SaveTLSRPT(db *sqlx.DB, report *parser.TLSReport, filename string, rawJSON []byte) (int64, error) {
	success, failure := report.Totals()
	res, err := db.Exec(`
		INSERT INTO tlsrpt_reports
			(org_name, report_id, contact_info, date_range_begin, date_range_end,
			 policy_domains, total_success, total_failure, raw_json, imported_at, source_filename)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		report.OrganizationName,
		report.ReportID,
		report.ContactInfo,
		report.DateRange.Start.Unix(),
		report.DateRange.End.Unix(),
		strings.Join(report.Domains(), ","),
		success,
		failure,
		string(rawJSON),
		time.Now().Unix(),
		filename,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	return res.LastInsertId()
}

// tlsrptListColumns excludes raw_json — list views don't need the blob,
// mirroring the DMARC convention of keeping report_xml out of list queries.
const tlsrptListColumns = `id, org_name, report_id, contact_info, date_range_begin, date_range_end,
	policy_domains, total_success, total_failure, imported_at, source_filename`

// ListTLSRPT returns TLS reports newest-first, optionally scoped to
// date_range_begin >= from, capped at limit.
func ListTLSRPT(db *sqlx.DB, from int64, limit int) ([]TLSRPTReport, error) {
	var reports []TLSRPTReport
	var err error
	if from > 0 {
		err = db.Select(&reports, `
			SELECT `+tlsrptListColumns+` FROM tlsrpt_reports
			WHERE date_range_begin >= ?
			ORDER BY date_range_begin DESC LIMIT ?`, from, limit)
	} else {
		err = db.Select(&reports, `
			SELECT `+tlsrptListColumns+` FROM tlsrpt_reports
			ORDER BY date_range_begin DESC LIMIT ?`, limit)
	}
	return reports, err
}

// GetTLSRPTJSON returns the stored raw JSON for a TLS report, or ("", nil) if not found.
func GetTLSRPTJSON(db *sqlx.DB, id int64) (string, error) {
	var rawJSON string
	err := db.Get(&rawJSON, `SELECT raw_json FROM tlsrpt_reports WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return rawJSON, nil
}

// TLSRPTSummary holds aggregate TLS session counts for a period.
type TLSRPTSummary struct {
	ReportCount  int64 `db:"report_count"`
	TotalSuccess int64 `db:"total_success"`
	TotalFailure int64 `db:"total_failure"`
}

// GetTLSRPTSummary returns aggregate counts, optionally scoped to from.
func GetTLSRPTSummary(db *sqlx.DB, from int64) (*TLSRPTSummary, error) {
	var s TLSRPTSummary
	var err error
	if from > 0 {
		err = db.Get(&s, `
			SELECT COUNT(*) AS report_count,
			       COALESCE(SUM(total_success), 0) AS total_success,
			       COALESCE(SUM(total_failure), 0) AS total_failure
			FROM tlsrpt_reports WHERE date_range_begin >= ?`, from)
	} else {
		err = db.Get(&s, `
			SELECT COUNT(*) AS report_count,
			       COALESCE(SUM(total_success), 0) AS total_success,
			       COALESCE(SUM(total_failure), 0) AS total_failure
			FROM tlsrpt_reports`)
	}
	return &s, err
}
