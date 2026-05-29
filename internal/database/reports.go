package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/jmoiron/sqlx"
)

// ErrDuplicate is returned when a report already exists (UNIQUE constraint).
var ErrDuplicate = errors.New("report already imported")

// ReportFilter holds optional filter parameters for ListReports.
type ReportFilter struct {
	Domain   string
	OrgName  string
	ReportID string
	DateFrom time.Time
	DateTo   time.Time
	Page     int
	PageSize int
	SortBy   string // "domain","org","date_begin","date_end","policy"
	SortDir  string // "asc" or "desc"
}

// SaveReport stores a parsed DMARC report, all its records, and the raw XML in a transaction.
// Returns the new report DB ID, or ErrDuplicate if already present.
func SaveReport(db *sqlx.DB, fb *models.Feedback, filename string, rawXML []byte) (int64, error) {
	tx, err := db.Beginx()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(`
		INSERT INTO reports
			(org_name, email, extra_contact_info, report_id,
			 date_range_begin, date_range_end,
			 domain, adkim, aspf, policy, subdomain_policy, pct, failure_options,
			 imported_at, source_filename)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		fb.ReportMetadata.OrgName,
		fb.ReportMetadata.Email,
		fb.ReportMetadata.ExtraContactInfo,
		fb.ReportMetadata.ReportID,
		fb.ReportMetadata.DateRange.Begin,
		fb.ReportMetadata.DateRange.End,
		fb.PolicyPublished.Domain,
		fb.PolicyPublished.ADKIM,
		fb.PolicyPublished.ASPF,
		fb.PolicyPublished.Policy,
		fb.PolicyPublished.SubdomainPolicy,
		fb.PolicyPublished.Pct,
		fb.PolicyPublished.FailureOptions,
		time.Now().Unix(),
		filename,
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return 0, ErrDuplicate
		}
		return 0, fmt.Errorf("insert report: %w", err)
	}

	reportID, _ := res.LastInsertId()

	for _, rec := range fb.Records {
		rrRes, err := tx.Exec(`
			INSERT INTO record_rows
				(report_id, source_ip, count, disposition, eval_dkim, eval_spf,
				 envelope_to, envelope_from, header_from)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			reportID,
			rec.Row.SourceIP,
			rec.Row.Count,
			rec.Row.PolicyEvaluated.Disposition,
			rec.Row.PolicyEvaluated.DKIM,
			rec.Row.PolicyEvaluated.SPF,
			rec.Identifiers.EnvelopeTo,
			rec.Identifiers.EnvelopeFrom,
			rec.Identifiers.HeaderFrom,
		)
		if err != nil {
			return 0, fmt.Errorf("insert record_row: %w", err)
		}
		rrID, _ := rrRes.LastInsertId()

		for _, d := range rec.AuthResults.DKIM {
			if _, err := tx.Exec(`
				INSERT INTO dkim_results (record_row_id, domain, selector, result, human_result)
				VALUES (?,?,?,?,?)`,
				rrID, d.Domain, d.Selector, d.Result, d.HumanResult,
			); err != nil {
				return 0, fmt.Errorf("insert dkim_result: %w", err)
			}
		}

		for _, s := range rec.AuthResults.SPF {
			if _, err := tx.Exec(`
				INSERT INTO spf_results (record_row_id, domain, scope, result)
				VALUES (?,?,?,?)`,
				rrID, s.Domain, s.Scope, s.Result,
			); err != nil {
				return 0, fmt.Errorf("insert spf_result: %w", err)
			}
		}

		for _, po := range rec.Row.PolicyEvaluated.Reasons {
			if _, err := tx.Exec(`
				INSERT INTO policy_overrides (record_row_id, type, comment)
				VALUES (?,?,?)`,
				rrID, po.Type, po.Comment,
			); err != nil {
				return 0, fmt.Errorf("insert policy_override: %w", err)
			}
		}
	}

	if len(rawXML) > 0 {
		if _, err := tx.Exec(`INSERT INTO report_xml (report_id, xml_data) VALUES (?, ?)`,
			reportID, string(rawXML)); err != nil {
			return 0, fmt.Errorf("insert report_xml: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return reportID, nil
}

// GetReportXML returns the stored raw XML for a report, or ("", nil) if not available.
func GetReportXML(db *sqlx.DB, id int64) (string, error) {
	var xmlData string
	err := db.Get(&xmlData, `SELECT xml_data FROM report_xml WHERE report_id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return xmlData, nil
}

// ListReports returns a page of reports matching the filter, plus the total count.
func ListReports(db *sqlx.DB, f ReportFilter) ([]models.Report, int, error) {
	if f.PageSize <= 0 {
		f.PageSize = 25
	}
	if f.Page <= 0 {
		f.Page = 1
	}

	where, args := buildReportWhere(f)

	var total int
	if err := db.Get(&total, "SELECT COUNT(*) FROM reports"+where, args...); err != nil {
		return nil, 0, err
	}

	offset := (f.Page - 1) * f.PageSize
	dir := "DESC"
	if f.SortDir == "asc" {
		dir = "ASC"
	}
	var orderCol string
	switch f.SortBy {
	case "domain":
		orderCol = "domain"
	case "org":
		orderCol = "org_name"
	case "date_end":
		orderCol = "date_range_end"
	case "policy":
		orderCol = "policy"
	default:
		orderCol = "date_range_begin"
	}
	query := `
		SELECT *,
			COALESCE((SELECT GROUP_CONCAT(DISTINCT envelope_to)
			          FROM record_rows
			          WHERE report_id = reports.id
			            AND envelope_to != '' AND envelope_to != '<>'), '') AS envelope_to_domains
		FROM reports` + where + ` ORDER BY ` + orderCol + ` ` + dir + ` LIMIT ? OFFSET ?`
	dataArgs := append(append([]any{}, args...), f.PageSize, offset)

	var reports []models.Report
	if err := db.Select(&reports, query, dataArgs...); err != nil {
		return nil, 0, err
	}
	return reports, total, nil
}

// ListReportDomains returns all distinct domains present in the reports table, ordered alphabetically.
func ListReportDomains(db *sqlx.DB) ([]string, error) {
	var domains []string
	err := db.Select(&domains, `SELECT DISTINCT domain FROM reports ORDER BY domain ASC`)
	return domains, err
}

// ListReportOrgs returns all distinct org_name values present in the reports table, ordered alphabetically.
func ListReportOrgs(db *sqlx.DB) ([]string, error) {
	var orgs []string
	err := db.Select(&orgs, `SELECT DISTINCT org_name FROM reports ORDER BY org_name ASC`)
	return orgs, err
}

// GetReport returns a single report by ID.
func GetReport(db *sqlx.DB, id int64) (*models.Report, error) {
	var r models.Report
	if err := db.Get(&r, "SELECT * FROM reports WHERE id = ?", id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// GetReportRecords returns all record rows for a report.
func GetReportRecords(db *sqlx.DB, reportID int64) ([]models.RecordRow, error) {
	var rows []models.RecordRow
	if err := db.Select(&rows,
		"SELECT * FROM record_rows WHERE report_id = ? ORDER BY count DESC", reportID,
	); err != nil {
		return nil, err
	}
	return rows, nil
}

// GetDKIMResults returns DKIM results for a record row.
func GetDKIMResults(db *sqlx.DB, recordRowID int64) ([]models.DKIMResult, error) {
	var results []models.DKIMResult
	if err := db.Select(&results,
		"SELECT * FROM dkim_results WHERE record_row_id = ?", recordRowID,
	); err != nil {
		return nil, err
	}
	return results, nil
}

// GetReportDKIMResults returns all DKIM results for every record row in a report,
// keyed by record_row_id. Fetches in a single query to avoid N+1 lookups.
func GetReportDKIMResults(db *sqlx.DB, reportID int64) (map[int64][]models.DKIMResult, error) {
	var results []models.DKIMResult
	if err := db.Select(&results, `
		SELECT dk.*
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		WHERE rr.report_id = ?`, reportID); err != nil {
		return nil, err
	}
	m := make(map[int64][]models.DKIMResult)
	for _, r := range results {
		m[r.RecordRowID] = append(m[r.RecordRowID], r)
	}
	return m, nil
}

// GetSPFResults returns SPF results for a record row.
func GetSPFResults(db *sqlx.DB, recordRowID int64) ([]models.SPFResult, error) {
	var results []models.SPFResult
	if err := db.Select(&results,
		"SELECT * FROM spf_results WHERE record_row_id = ?", recordRowID,
	); err != nil {
		return nil, err
	}
	return results, nil
}

// ListDomains returns all distinct domains with their aggregate message counts,
// ordered worst pass-rate first so problem domains surface immediately.
func ListDomains(db *sqlx.DB) ([]DomainStat, error) {
	var stats []DomainStat
	err := db.Select(&stats, `
		SELECT
			r.domain,
			COUNT(DISTINCT r.id) AS report_count,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id
		GROUP BY r.domain
		ORDER BY pass_rate ASC`)
	return stats, err
}

// ListDomainsPaged returns one page of domains (same ordering as ListDomains)
// and the total number of distinct domains. If from > 0, only data from reports
// whose date_range_begin >= from is included.
func ListDomainsPaged(db *sqlx.DB, page, pageSize int, from int64, sortBy, sortDir string) ([]DomainStat, int, error) {
	if page < 1 {
		page = 1
	}
	var total int
	if from > 0 {
		if err := db.Get(&total, `SELECT COUNT(DISTINCT domain) FROM reports WHERE date_range_begin >= ?`, from); err != nil {
			return nil, 0, err
		}
	} else {
		if err := db.Get(&total, `SELECT COUNT(DISTINCT domain) FROM reports`); err != nil {
			return nil, 0, err
		}
	}
	dir := "ASC"
	if sortDir == "desc" {
		dir = "DESC"
	}
	var orderCol string
	switch sortBy {
	case "domain":
		orderCol = "r.domain"
	case "reports":
		orderCol = "report_count"
	case "messages":
		orderCol = "total_messages"
	case "passed":
		orderCol = "passed"
	case "failed":
		orderCol = "failed"
	default:
		orderCol = "pass_rate"
	}

	offset := (page - 1) * pageSize
	const selectCols = `
		SELECT
			r.domain,
			COUNT(DISTINCT r.id) AS report_count,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`
	orderLimit := fmt.Sprintf(" GROUP BY r.domain ORDER BY %s %s LIMIT ? OFFSET ?", orderCol, dir)

	var stats []DomainStat
	var err error
	if from > 0 {
		err = db.Select(&stats, selectCols+` WHERE r.date_range_begin >= ?`+orderLimit, from, pageSize, offset)
	} else {
		err = db.Select(&stats, selectCols+orderLimit, pageSize, offset)
	}
	return stats, total, err
}

// GetDomainRecords returns recent record rows for a specific domain.
// If from > 0, only rows from reports whose date_range_begin >= from are returned.
func GetDomainRecords(db *sqlx.DB, domain string, from int64, limit int) ([]DomainRecord, error) {
	var rows []DomainRecord
	var err error
	if from > 0 {
		err = db.Select(&rows, `
			SELECT rr.*, r.org_name, r.date_range_begin, r.date_range_end
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ? AND r.date_range_begin >= ?
			ORDER BY r.date_range_begin DESC, rr.count DESC
			LIMIT ?`, domain, from, limit)
	} else {
		err = db.Select(&rows, `
			SELECT rr.*, r.org_name, r.date_range_begin, r.date_range_end
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ?
			ORDER BY r.date_range_begin DESC, rr.count DESC
			LIMIT ?`, domain, limit)
	}
	return rows, err
}

// ListSources returns source IPs, paginated. minMessages sets the HAVING threshold
// (minimum total message count); values < 1 are treated as 1 (show all IPs).
// sortBy accepts: "ip", "messages", "passed", "failed" (default: fail rate).
// sortDir accepts: "asc" or "desc". country="??" matches IPs with no geo data.
// If from > 0, only data from reports whose date_range_begin >= from is included.
// Returns the page of results and the total matching row count.
func ListSources(db *sqlx.DB, page, pageSize int, envelopeFrom, disposition, country, sourceIP string, from int64, minMessages int, sortBy, sortDir string) ([]SourceStat, int, error) {
	if page < 1 {
		page = 1
	}

	var clauses []string
	var args []any

	// When a date range is requested we must join reports; we always add it
	// so the join is only present when needed.
	reportsJoin := ""
	if from > 0 {
		reportsJoin = " JOIN reports r ON r.id = rr.report_id"
		clauses = append(clauses, "r.date_range_begin >= ?")
		args = append(args, from)
	}

	if envelopeFrom != "" {
		clauses = append(clauses, "rr.envelope_from = ?")
		args = append(args, envelopeFrom)
	}
	if disposition != "" {
		clauses = append(clauses, "rr.disposition = ?")
		args = append(args, disposition)
	}
	if sourceIP != "" {
		clauses = append(clauses, "rr.source_ip = ?")
		args = append(args, sourceIP)
	}

	// Country filter requires a LEFT JOIN on ip_info.
	ipJoin := ""
	if country != "" {
		ipJoin = " LEFT JOIN ip_info ii ON ii.ip = rr.source_ip"
		if country == "??" {
			clauses = append(clauses, "(ii.whois_country IS NULL OR ii.whois_country = '')")
		} else {
			clauses = append(clauses, "ii.whois_country = ?")
			args = append(args, country)
		}
	}

	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}

	min := 1
	if minMessages > 1 {
		min = minMessages
	}
	having := "HAVING SUM(rr.count) >= ?"

	dir := "DESC"
	if sortDir == "asc" {
		dir = "ASC"
	}
	var orderBy string
	switch sortBy {
	case "ip":
		orderBy = "ORDER BY rr.source_ip " + dir
	case "messages":
		orderBy = "ORDER BY SUM(rr.count) " + dir
	case "passed":
		orderBy = "ORDER BY SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) " + dir
	case "failed":
		orderBy = "ORDER BY SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) " + dir
	default:
		orderBy = "ORDER BY CAST(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS REAL) / SUM(rr.count) " + dir
	}

	joinClause := reportsJoin + ipJoin

	// Total count (wrap in subquery to apply HAVING before counting).
	var total int
	countArgs := append(append([]any{}, args...), min)
	if err := db.Get(&total, `
		SELECT COUNT(*) FROM (
			SELECT rr.source_ip
			FROM record_rows rr`+joinClause+where+`
			GROUP BY rr.source_ip
			`+having+`
		)`, countArgs...); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	dataArgs := append(append([]any{}, args...), min, pageSize, offset)
	var stats []SourceStat
	err := db.Select(&stats, `
		SELECT
			rr.source_ip,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			0.0 AS pass_rate
		FROM record_rows rr`+joinClause+where+`
		GROUP BY rr.source_ip
		`+having+`
		`+orderBy+`
		LIMIT ? OFFSET ?`, dataArgs...)
	return stats, total, err
}

// ListEnvelopeFromDomains returns all distinct non-empty envelope_from domains, ordered alphabetically.
func ListEnvelopeFromDomains(db *sqlx.DB) ([]string, error) {
	var domains []string
	err := db.Select(&domains, `
		SELECT DISTINCT envelope_from
		FROM record_rows
		WHERE envelope_from != '' AND envelope_from != '<>'
		ORDER BY envelope_from ASC`)
	return domains, err
}

// GetRecipientRecords returns record rows where envelope_to matches the given domain.
func GetRecipientRecords(db *sqlx.DB, envelopeTo string, limit int) ([]DomainRecord, error) {
	var rows []DomainRecord
	err := db.Select(&rows, `
		SELECT rr.*, r.org_name, r.date_range_begin, r.date_range_end
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE rr.envelope_to = ?
		ORDER BY r.date_range_begin DESC, rr.count DESC
		LIMIT ?`, envelopeTo, limit)
	return rows, err
}

// GetSourceRecords returns record rows for a specific source IP.
// If from > 0, only rows from reports whose date_range_begin >= from are returned.
func GetSourceRecords(db *sqlx.DB, ip string, from int64, limit int) ([]DomainRecord, error) {
	var rows []DomainRecord
	var err error
	if from > 0 {
		err = db.Select(&rows, `
			SELECT rr.*, r.org_name, r.date_range_begin, r.date_range_end
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE rr.source_ip = ? AND r.date_range_begin >= ?
			ORDER BY r.date_range_begin DESC, rr.count DESC
			LIMIT ?`, ip, from, limit)
	} else {
		err = db.Select(&rows, `
			SELECT rr.*, r.org_name, r.date_range_begin, r.date_range_end
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE rr.source_ip = ?
			ORDER BY r.date_range_begin DESC, rr.count DESC
			LIMIT ?`, ip, limit)
	}
	return rows, err
}

func buildReportWhere(f ReportFilter) (string, []any) {
	var clauses []string
	var args []any

	if f.Domain != "" {
		clauses = append(clauses, "domain = ?")
		args = append(args, f.Domain)
	}
	if f.OrgName != "" {
		clauses = append(clauses, "org_name = ?")
		args = append(args, f.OrgName)
	}
	if f.ReportID != "" {
		clauses = append(clauses, "report_id LIKE ?")
		args = append(args, "%"+f.ReportID+"%")
	}
	if !f.DateFrom.IsZero() {
		clauses = append(clauses, "date_range_begin >= ?")
		args = append(args, f.DateFrom.Unix())
	}
	if !f.DateTo.IsZero() {
		clauses = append(clauses, "date_range_end <= ?")
		args = append(args, f.DateTo.Unix())
	}

	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
