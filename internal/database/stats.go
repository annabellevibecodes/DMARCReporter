package database

import (
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/jmoiron/sqlx"
)

// cutoffUnix returns the Unix timestamp for n days ago.
func cutoffUnix(days int) int64 {
	return time.Now().AddDate(0, 0, -days).Unix()
}

// StatsFilter scopes dashboard queries by envelope_from domain and/or report date range.
// Zero values mean "no constraint" (all envelope_from domains, all time).
type StatsFilter struct {
	EnvelopeFrom string
	Domain       string // filter by r.domain (DMARC policy domain)
	From         int64  // report date_range_begin >= From  (0 = no lower bound)
	To           int64  // report date_range_begin <= To    (0 = no upper bound)
}

// where builds a WHERE clause (with aliases r=reports, rr=record_rows) for the filter.
func (f StatsFilter) where() (string, []any) {
	var clauses []string
	var args []any
	if f.EnvelopeFrom != "" {
		clauses = append(clauses, "rr.envelope_from = ?")
		args = append(args, f.EnvelopeFrom)
	}
	if f.Domain != "" {
		clauses = append(clauses, "r.domain = ?")
		args = append(args, f.Domain)
	}
	if f.From > 0 {
		clauses = append(clauses, "r.date_range_begin >= ?")
		args = append(args, f.From)
	}
	if f.To > 0 {
		clauses = append(clauses, "r.date_range_begin <= ?")
		args = append(args, f.To)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// DashboardStats holds summary numbers for the dashboard.
type DashboardStats struct {
	TotalMessages  int64   `db:"total_messages"`
	TotalReports   int64   `db:"total_reports"`
	TotalDomains   int64   `db:"total_domains"`
	TotalReporters int64   `db:"total_reporters"`
	Passed         int64   `db:"passed"`
	Failed         int64   `db:"failed"`
	Quarantined    int64   `db:"quarantined"`
	Rejected       int64   `db:"rejected"`
	PassRate       float64 // computed
}

// FailureModeStats breaks down how messages fail DMARC.
type FailureModeStats struct {
	DKIMOnlyPass int64 `db:"dkim_only_pass"`
	SPFOnlyPass  int64 `db:"spf_only_pass"`
	BothFail     int64 `db:"both_fail"`
}

// FailureRateStat holds aggregate failure-rate stats for a source IP.
type FailureRateStat struct {
	SourceIP      string  `db:"source_ip"`
	TotalMessages int64   `db:"total_messages"`
	Failed        int64   `db:"failed"`
	FailRate      float64 `db:"fail_rate"`
}

// TrendPoint is one data point in a pass/fail time series.
type TrendPoint struct {
	Week   string `db:"week"`
	Passed int64  `db:"passed"`
	Failed int64  `db:"failed"`
}

// SourceStat holds aggregate stats for a source IP.
type SourceStat struct {
	SourceIP      string  `db:"source_ip"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// DomainStat holds aggregate stats for a domain.
type DomainStat struct {
	Domain        string  `db:"domain"`
	ReportCount   int64   `db:"report_count"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// DomainRecord is a record row joined with its parent report metadata.
type DomainRecord struct {
	models.RecordRow
	OrgName        string `db:"org_name"`
	DateRangeBegin int64  `db:"date_range_begin"`
	DateRangeEnd   int64  `db:"date_range_end"`
}

// GetDashboardStats returns summary counts for the dashboard, scoped by f.
func GetDashboardStats(db *sqlx.DB, f StatsFilter) (*DashboardStats, error) {
	var s DashboardStats
	where, args := f.where()
	err := db.Get(&s, `
		SELECT
			COALESCE(SUM(rr.count), 0)   AS total_messages,
			COUNT(DISTINCT r.id)          AS total_reports,
			COUNT(DISTINCT r.domain)      AS total_domains,
			COUNT(DISTINCT r.org_name)    AS total_reporters,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'
				THEN rr.count ELSE 0 END), 0) AS failed,
			COALESCE(SUM(CASE WHEN rr.disposition = 'quarantine'
				THEN rr.count ELSE 0 END), 0) AS quarantined,
			COALESCE(SUM(CASE WHEN rr.disposition = 'reject'
				THEN rr.count ELSE 0 END), 0) AS rejected
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where, args...)
	if err != nil {
		return nil, err
	}
	if s.TotalMessages > 0 {
		s.PassRate = float64(s.Passed) / float64(s.TotalMessages) * 100
	}
	return &s, nil
}

// GetTrendData returns weekly pass/fail counts scoped by f.
func GetTrendData(db *sqlx.DB, f StatsFilter) ([]TrendPoint, error) {
	var points []TrendPoint
	where, args := f.where()
	err := db.Select(&points, `
		SELECT
			strftime('%G-%V', datetime(r.date_range_begin, 'unixepoch')) AS week,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'
				THEN rr.count ELSE 0 END), 0) AS failed
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY week
		ORDER BY week`, args...)
	return points, err
}


// GetFailureModeBreakdown returns a breakdown of how messages fail DMARC, scoped by f.
func GetFailureModeBreakdown(db *sqlx.DB, f StatsFilter) (*FailureModeStats, error) {
	var s FailureModeStats
	where, args := f.where()
	err := db.Get(&s, `
		SELECT
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_only_pass,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_only_pass,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS both_fail
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where, args...)
	return &s, err
}

// GetTopFailingSources returns source IPs ordered by failure rate, scoped by f.
// Only IPs with at least minMessages total messages are included.
func GetTopFailingSources(db *sqlx.DB, minMessages int, limit int, f StatsFilter) ([]FailureRateStat, error) {
	var stats []FailureRateStat
	where, fArgs := f.where()
	args := append(fArgs, minMessages, limit)
	err := db.Select(&stats, `
		SELECT
			rr.source_ip,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			CAST(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS REAL)
				/ SUM(rr.count) AS fail_rate
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY rr.source_ip
		HAVING SUM(rr.count) >= ?
		ORDER BY fail_rate DESC
		LIMIT ?`, args...)
	return stats, err
}

// DomainRiskStat holds compliance rate and volume for a domain below a threshold.
type DomainRiskStat struct {
	Domain        string  `db:"domain"`
	PassRatePct   float64 `db:"compliance_rate_pct"`
	TotalMessages int64   `db:"total_messages"`
}

// GetDomainsAtRisk returns domains whose compliance rate is below thresholdPct, scoped by f.
func GetDomainsAtRisk(db *sqlx.DB, thresholdPct float64, f StatsFilter) ([]DomainRiskStat, error) {
	var stats []DomainRiskStat
	where, fArgs := f.where()
	args := append(fArgs, thresholdPct)
	err := db.Select(&stats, `
		SELECT domain, compliance_rate_pct, total_messages FROM (
			SELECT
				r.domain,
				ROUND(
					100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
						THEN rr.count ELSE 0 END)
					/ NULLIF(SUM(rr.count), 0),
				2) AS compliance_rate_pct,
				SUM(rr.count) AS total_messages
			FROM reports r
			JOIN record_rows rr ON rr.report_id = r.id`+where+`
			GROUP BY r.domain
		)
		WHERE compliance_rate_pct < ?
		ORDER BY compliance_rate_pct ASC`, args...)
	return stats, err
}

// RecipientSenderStat holds aggregate stats for a sending domain (header_from) as seen
// by a specific recipient (envelope_to).
type RecipientSenderStat struct {
	SendingDomain string  `db:"sending_domain"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// GetRecipientSenderBreakdown returns per sending-domain (header_from) stats for all
// messages received by a given envelope_to domain.
func GetRecipientSenderBreakdown(db *sqlx.DB, envelopeTo string, limit int) ([]RecipientSenderStat, error) {
	var stats []RecipientSenderStat
	err := db.Select(&stats, `
		SELECT
			rr.header_from AS sending_domain,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
		FROM record_rows rr
		WHERE rr.envelope_to = ?
		GROUP BY rr.header_from
		ORDER BY total_messages DESC
		LIMIT ?`, envelopeTo, limit)
	return stats, err
}

// EnvelopeToStat holds aggregate stats for a recipient (envelope_to) domain.
type EnvelopeToStat struct {
	EnvelopeTo    string  `db:"envelope_to"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// GetEnvelopeToBreakdown returns the top recipient domains (envelope_to) for a given
// sending domain, ordered by volume. Empty and null-sender ("<>") entries are excluded.
func GetEnvelopeToBreakdown(db *sqlx.DB, domain string, limit int) ([]EnvelopeToStat, error) {
	var stats []EnvelopeToStat
	err := db.Select(&stats, `
		SELECT
			rr.envelope_to,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE r.domain = ?
		  AND rr.envelope_to != ''
		  AND rr.envelope_to != '<>'
		GROUP BY rr.envelope_to
		ORDER BY total_messages DESC
		LIMIT ?`, domain, limit)
	return stats, err
}

// GetActivePolicy returns the DMARC policy (none/quarantine/reject) that covers the most
// messages within the given filter. Returns an empty string when there are no matching reports.
func GetActivePolicy(db *sqlx.DB, f StatsFilter) (string, error) {
	where, args := f.where()
	var policy string
	err := db.Get(&policy, `
		SELECT r.policy
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY r.policy
		ORDER BY SUM(rr.count) DESC
		LIMIT 1`, args...)
	if err != nil && err.Error() == "sql: no rows in result set" {
		return "", nil
	}
	return policy, err
}

// GeoStat holds aggregate message volume for a country code.
type GeoStat struct {
	Country       string `db:"country"`
	TotalMessages int64  `db:"total_messages"`
}

// PolicyBucket holds a count of domains using a given DMARC policy.
type PolicyBucket struct {
	Policy      string `db:"policy"`
	DomainCount int64  `db:"domain_count"`
}

// GetTopSourcesByVolume returns source IPs ordered by total message volume, scoped by f.
func GetTopSourcesByVolume(db *sqlx.DB, limit int, f StatsFilter) ([]SourceStat, error) {
	var stats []SourceStat
	where, fArgs := f.where()
	args := append(fArgs, limit)
	err := db.Select(&stats, `
		SELECT
			rr.source_ip,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY rr.source_ip
		ORDER BY total_messages DESC
		LIMIT ?`, args...)
	return stats, err
}

// GetGeoDistribution returns message volume grouped by country code, scoped by f.
// IPs not yet looked up appear under country code "??".
func GetGeoDistribution(db *sqlx.DB, limit int, f StatsFilter) ([]GeoStat, error) {
	var stats []GeoStat
	where, fArgs := f.where()
	args := append(fArgs, limit)
	err := db.Select(&stats, `
		SELECT
			CASE WHEN ii.whois_country IS NULL OR ii.whois_country = '' THEN '??' ELSE ii.whois_country END AS country,
			SUM(rr.count) AS total_messages
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip`+where+`
		GROUP BY country
		ORDER BY total_messages DESC
		LIMIT ?`, args...)
	return stats, err
}

// GetDomainPolicyBreakdown returns the count of domains grouped by their dominant DMARC policy.
// For each domain the policy covering the most messages is used.
func GetDomainPolicyBreakdown(db *sqlx.DB, f StatsFilter) ([]PolicyBucket, error) {
	var buckets []PolicyBucket
	where, args := f.where()
	err := db.Select(&buckets, `
		WITH domain_policy_volumes AS (
			SELECT r.domain, r.policy, SUM(rr.count) AS msg_count
			FROM reports r
			JOIN record_rows rr ON rr.report_id = r.id`+where+`
			GROUP BY r.domain, r.policy
		),
		dominant AS (
			SELECT domain, policy
			FROM domain_policy_volumes dp
			WHERE msg_count = (
				SELECT MAX(msg_count) FROM domain_policy_volumes dp2 WHERE dp2.domain = dp.domain
			)
		)
		SELECT policy, COUNT(*) AS domain_count
		FROM dominant
		GROUP BY policy
		ORDER BY domain_count DESC`, args...)
	return buckets, err
}

// DKIMSelectorStat holds aggregate stats for a DKIM selector observed in reports for a domain.
type DKIMSelectorStat struct {
	Selector      string  `db:"selector"`
	SigningDomain string  `db:"signing_domain"`
	Total         int64   `db:"total"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// GetDKIMSelectorStats returns per-selector aggregate stats for all DKIM results tied to
// record rows in reports for the given DMARC policy domain.
func GetDKIMSelectorStats(db *sqlx.DB, domain string) ([]DKIMSelectorStat, error) {
	var stats []DKIMSelectorStat
	err := db.Select(&stats, `
		SELECT
			dk.selector,
			dk.domain AS signing_domain,
			COUNT(*) AS total,
			SUM(CASE WHEN dk.result = 'pass' THEN 1 ELSE 0 END) AS passed,
			SUM(CASE WHEN dk.result != 'pass' THEN 1 ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN dk.result = 'pass' THEN 1 ELSE 0 END)
				/ NULLIF(COUNT(*), 0), 1) AS pass_rate
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE r.domain = ?
		  AND dk.selector != ''
		GROUP BY dk.selector, dk.domain
		ORDER BY total DESC`, domain)
	return stats, err
}

// GetDomainTrend returns weekly pass/fail counts for a specific domain over the last n days.
func GetDomainTrend(db *sqlx.DB, domain string, days int) ([]TrendPoint, error) {
	var points []TrendPoint
	err := db.Select(&points, `
		SELECT
			strftime('%G-%V', datetime(r.date_range_begin, 'unixepoch')) AS week,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'
				THEN rr.count ELSE 0 END), 0) AS failed
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id
		WHERE r.domain = ?
		  AND r.date_range_begin >= ?
		GROUP BY week
		ORDER BY week`, domain, cutoffUnix(days))
	return points, err
}
