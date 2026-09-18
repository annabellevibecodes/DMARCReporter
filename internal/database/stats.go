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

// cutoffUnix returns the Unix timestamp for n days ago.
func cutoffUnix(days int) int64 {
	return time.Now().AddDate(0, 0, -days).Unix()
}

// StatsFilter scopes dashboard queries by envelope_from domain and/or report date range.
// Zero values mean "no constraint" (all envelope_from domains, all time).
type StatsFilter struct {
	EnvelopeFrom string
	Domain       string // filter by r.domain (DMARC policy domain)
	SourceIP     string // filter by rr.source_ip
	From         int64  // report date_range_begin >= From  (0 = no lower bound)
	To           int64  // report date_range_begin <= To    (0 = no upper bound)
	// Compare requests that handlers also compute the same query for the
	// preceding window of equal length (see PreviousWindow / WithComparison).
	Compare bool
}

// where builds a WHERE clause (with aliases r=reports, rr=record_rows) for the filter.
func (f StatsFilter) where() (string, []any) {
	clauses, args := f.clauses(true)
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// whereNoTime is where() without the date constraints — used for "all-time"
// facts about an entity (first/last seen) inside an otherwise scoped query.
func (f StatsFilter) whereNoTime() (string, []any) {
	clauses, args := f.clauses(false)
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// andClauses returns the filter as "AND a AND b" fragments (no leading WHERE)
// for queries that already have a WHERE.
func (f StatsFilter) andClauses() (string, []any) {
	clauses, args := f.clauses(true)
	if len(clauses) == 0 {
		return "", nil
	}
	return " AND " + strings.Join(clauses, " AND "), args
}

func (f StatsFilter) clauses(withTime bool) ([]string, []any) {
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
	if f.SourceIP != "" {
		clauses = append(clauses, "rr.source_ip = ?")
		args = append(args, f.SourceIP)
	}
	if withTime {
		if f.From > 0 {
			clauses = append(clauses, "r.date_range_begin >= ?")
			args = append(args, f.From)
		}
		if f.To > 0 {
			clauses = append(clauses, "r.date_range_begin <= ?")
			args = append(args, f.To)
		}
	}
	return clauses, args
}

// WindowEnd returns the effective upper bound of the filter (To, or now).
func (f StatsFilter) WindowEnd() int64 {
	if f.To > 0 {
		return f.To
	}
	return time.Now().Unix()
}

// PreviousWindow returns a filter for the window of equal length immediately
// preceding f. ok is false when f is unbounded (all time), in which case no
// comparison is possible.
func (f StatsFilter) PreviousWindow() (prev StatsFilter, ok bool) {
	if f.From <= 0 {
		return f, false
	}
	end := f.WindowEnd()
	length := end - f.From
	if length <= 0 {
		return f, false
	}
	prev = f
	prev.Compare = false
	prev.To = f.From - 1
	prev.From = f.From - length
	if prev.From < 1 {
		prev.From = 1
	}
	return prev, true
}

// Comparison pairs a value for the current window with the same value for
// the preceding window (nil when f.Compare was false or no previous window exists).
type Comparison[T any] struct {
	Current  T
	Previous *T
}

// WithComparison runs fn for f and, when f.Compare is set and a previous
// window exists, again for the previous window.
func WithComparison[T any](f StatsFilter, fn func(StatsFilter) (T, error)) (Comparison[T], error) {
	var c Comparison[T]
	cur, err := fn(f)
	if err != nil {
		return c, err
	}
	c.Current = cur
	if !f.Compare {
		return c, nil
	}
	prev, ok := f.PreviousWindow()
	if !ok {
		return c, nil
	}
	p, err := fn(prev)
	if err != nil {
		return c, err
	}
	c.Previous = &p
	return c, nil
}

// DashboardStats holds summary numbers for the dashboard (C1–C4, C6).
type DashboardStats struct {
	TotalMessages   int64   `db:"total_messages"`
	TotalReports    int64   `db:"total_reports"`
	TotalDomains    int64   `db:"total_domains"`
	TotalReporters  int64   `db:"total_reporters"`
	Passed          int64   `db:"passed"`
	Failed          int64   `db:"failed"`
	DKIMAlignedPass int64   `db:"dkim_aligned_pass"` // C3: policy_evaluated dkim = pass
	SPFAlignedPass  int64   `db:"spf_aligned_pass"`  // C4: policy_evaluated spf = pass
	DispositionNone int64   `db:"disposition_none"`  // C6
	Quarantined     int64   `db:"quarantined"`
	Rejected        int64   `db:"rejected"`
	PassRate        float64 // computed, percent
	DKIMPassRate    float64 // computed, percent
	SPFPassRate     float64 // computed, percent
}

// FailureModeStats is the 2×2 authentication matrix (C5): how messages
// combined aligned-DKIM and aligned-SPF results. The name predates BothPass;
// GetAuthMatrix returns the same struct.
type FailureModeStats struct {
	BothPass     int64 `db:"both_pass"`
	DKIMOnlyPass int64 `db:"dkim_only_pass"`
	SPFOnlyPass  int64 `db:"spf_only_pass"`
	BothFail     int64 `db:"both_fail"`
}

// AuthMatrix is the preferred name for the 2×2 matrix.
type AuthMatrix = FailureModeStats

// Total returns the sum of all four buckets.
func (m FailureModeStats) Total() int64 {
	return m.BothPass + m.DKIMOnlyPass + m.SPFOnlyPass + m.BothFail
}

// Share returns bucket/total in percent (0 when total is 0).
func (m FailureModeStats) Share(bucket int64) float64 {
	t := m.Total()
	if t == 0 {
		return 0
	}
	return float64(bucket) / float64(t) * 100
}

// FailureRateStat holds aggregate failure-rate stats for a source IP.
type FailureRateStat struct {
	SourceIP      string  `db:"source_ip"`
	TotalMessages int64   `db:"total_messages"`
	Failed        int64   `db:"failed"`
	FailRate      float64 `db:"fail_rate"`
	RDNS          string  `db:"rdns"`
	Provider      string  // friendly name derived from RDNS; filled by handlers
}

// TrendPoint is one data point in a pass/fail time series. Week holds the
// bucket label: an ISO week ("2026-31") or a date ("2026-08-01") depending on
// the granularity the series was queried with.
type TrendPoint struct {
	Week       string `db:"week"`
	Passed     int64  `db:"passed"`
	Failed     int64  `db:"failed"`
	DKIMPassed int64  `db:"dkim_passed"` // aligned DKIM pass (C3 series)
	SPFPassed  int64  `db:"spf_passed"`  // aligned SPF pass (C4 series)
}

// Total returns passed+failed.
func (p TrendPoint) Total() int64 { return p.Passed + p.Failed }

// TrendDaily reports whether a period starting at from (Unix; 0 = all time)
// is short enough to chart with daily rather than weekly buckets.
func TrendDaily(from int64) bool {
	return from > 0 && time.Since(time.Unix(from, 0)) <= 92*24*time.Hour
}

// trendBucketExpr returns the SQLite strftime expression for the bucket label.
func trendBucketExpr(daily bool) string {
	if daily {
		return "strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch'))"
	}
	return "strftime('%G-%V', datetime(r.date_range_begin, 'unixepoch'))"
}

// trendBucketLabel formats t the same way trendBucketExpr does in SQL.
func trendBucketLabel(t time.Time, daily bool) string {
	if daily {
		return t.UTC().Format("2006-01-02")
	}
	y, w := t.UTC().ISOWeek()
	return fmt.Sprintf("%04d-%02d", y, w)
}

// FillTrendGaps inserts zero-valued points for every bucket between from and to
// (or between the first data point and now) that has no data, so charts show
// quiet periods instead of interpolating across them.
func FillTrendGaps(points []TrendPoint, from, to int64, daily bool) []TrendPoint {
	if len(points) == 0 {
		return points
	}
	byLabel := make(map[string]TrendPoint, len(points))
	for _, p := range points {
		byLabel[p.Week] = p
	}

	step := 7 * 24 * time.Hour
	if daily {
		step = 24 * time.Hour
	}
	start := time.Unix(from, 0)
	if from == 0 {
		// All time: no explicit lower bound — start at the first observed bucket.
		start = bucketStartFromLabel(points[0].Week, daily)
	}
	end := time.Now().UTC()
	if to > 0 {
		end = time.Unix(to, 0)
	}

	var filled []TrendPoint
	for t := start; !t.After(end); t = t.Add(step) {
		label := trendBucketLabel(t, daily)
		if len(filled) > 0 && filled[len(filled)-1].Week == label {
			continue // week boundaries can repeat when stepping by 7d across DST
		}
		if p, ok := byLabel[label]; ok {
			filled = append(filled, p)
		} else {
			filled = append(filled, TrendPoint{Week: label})
		}
	}
	return filled
}

// bucketStartFromLabel parses a bucket label back into its starting time.
func bucketStartFromLabel(label string, daily bool) time.Time {
	if daily {
		if t, err := time.Parse("2006-01-02", label); err == nil {
			return t
		}
		return time.Now().UTC()
	}
	var y, w int
	if _, err := fmt.Sscanf(label, "%d-%d", &y, &w); err != nil {
		return time.Now().UTC()
	}
	// Jan 4 is always in ISO week 1; walk back to Monday, then forward w-1 weeks.
	jan4 := time.Date(y, 1, 4, 0, 0, 0, 0, time.UTC)
	monday := jan4.AddDate(0, 0, -(int(jan4.Weekday())+6)%7)
	return monday.AddDate(0, 0, (w-1)*7)
}

// SourceStat holds aggregate stats for a source IP.
type SourceStat struct {
	SourceIP      string  `db:"source_ip"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
	RDNS          string  `db:"rdns"`
	Provider      string  // friendly name derived from RDNS; filled by handlers
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
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_aligned_pass,
			COALESCE(SUM(CASE WHEN rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_aligned_pass,
			COALESCE(SUM(CASE WHEN rr.disposition = 'quarantine'
				THEN rr.count ELSE 0 END), 0) AS quarantined,
			COALESCE(SUM(CASE WHEN rr.disposition = 'reject'
				THEN rr.count ELSE 0 END), 0) AS rejected,
			COALESCE(SUM(CASE WHEN rr.disposition != 'quarantine' AND rr.disposition != 'reject'
				THEN rr.count ELSE 0 END), 0) AS disposition_none
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where, args...)
	if err != nil {
		return nil, err
	}
	if s.TotalMessages > 0 {
		s.PassRate = float64(s.Passed) / float64(s.TotalMessages) * 100
		s.DKIMPassRate = float64(s.DKIMAlignedPass) / float64(s.TotalMessages) * 100
		s.SPFPassRate = float64(s.SPFAlignedPass) / float64(s.TotalMessages) * 100
	}
	return &s, nil
}

// GetTrendData returns pass/fail counts scoped by f, bucketed daily or weekly.
func GetTrendData(db *sqlx.DB, f StatsFilter, daily bool) ([]TrendPoint, error) {
	var points []TrendPoint
	where, args := f.where()
	err := db.Select(&points, `
		SELECT
			`+trendBucketExpr(daily)+` AS week,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'
				THEN rr.count ELSE 0 END), 0) AS failed,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_passed,
			COALESCE(SUM(CASE WHEN rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_passed
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY week
		ORDER BY week`, args...)
	return points, err
}

// GetFailureModeBreakdown returns the full 2×2 authentication matrix (C5),
// scoped by f. Kept under its original name for existing callers; see GetAuthMatrix.
func GetFailureModeBreakdown(db *sqlx.DB, f StatsFilter) (*FailureModeStats, error) {
	var s FailureModeStats
	where, args := f.where()
	err := db.Get(&s, `
		SELECT
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' AND rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS both_pass,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS dkim_only_pass,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS spf_only_pass,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS both_fail
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where, args...)
	return &s, err
}

// GetAuthMatrix returns the 2×2 authentication matrix (C5) scoped by f.
func GetAuthMatrix(db *sqlx.DB, f StatsFilter) (*AuthMatrix, error) {
	return GetFailureModeBreakdown(db, f)
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
				/ SUM(rr.count) AS fail_rate,
			COALESCE(MAX(ii.rdns), '') AS rdns
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip`+where+`
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
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return policy, err
}

// PolicyOverrideStat holds message volume for one policy-override reason
// (forwarded, mailing_list, local_policy, trusted_forwarder, sampled_out, other).
type PolicyOverrideStat struct {
	Type          string `db:"type"`
	TotalMessages int64  `db:"total_messages"`
	SourceCount   int64  `db:"source_count"`
}

// GetPolicyOverrideBreakdown returns message volume grouped by policy-override
// reason, scoped by f. These explain why receivers did not apply the published
// policy — the main signal for separating forwarding from real spoofing.
func GetPolicyOverrideBreakdown(db *sqlx.DB, f StatsFilter) ([]PolicyOverrideStat, error) {
	var stats []PolicyOverrideStat
	where, args := f.where()
	err := db.Select(&stats, `
		SELECT
			CASE WHEN po.type = '' THEN 'other' ELSE po.type END AS type,
			SUM(rr.count) AS total_messages,
			COUNT(DISTINCT rr.source_ip) AS source_count
		FROM policy_overrides po
		JOIN record_rows rr ON rr.id = po.record_row_id
		JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY 1
		ORDER BY total_messages DESC`, args...)
	return stats, err
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
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate,
			COALESCE(MAX(ii.rdns), '') AS rdns
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip`+where+`
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

// GetDomainTrend returns pass/fail counts for a specific domain, bucketed daily or weekly.
// If from > 0, only data from reports whose date_range_begin >= from is included.
func GetDomainTrend(db *sqlx.DB, domain string, from int64, daily bool) ([]TrendPoint, error) {
	f := StatsFilter{Domain: domain, From: from}
	return GetTrendData(db, f, daily)
}

// ListDomainsFiltered returns per-domain aggregate stats scoped by f,
// ordered worst pass-rate first. Used by exports so the downloaded report
// matches the on-screen period/domain scope.
func ListDomainsFiltered(db *sqlx.DB, f StatsFilter) ([]DomainStat, error) {
	var stats []DomainStat
	where, args := f.where()
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
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY r.domain
		ORDER BY pass_rate ASC`, args...)
	return stats, err
}

// DomainAggStats holds period-scoped aggregate stats for a single policy domain.
type DomainAggStats struct {
	TotalMessages    int64 `db:"total_messages"`
	Passed           int64 `db:"passed"`
	Failed           int64 `db:"failed"`
	UniqueSenders    int64 `db:"unique_senders"`
	UniqueRecipients int64 `db:"unique_recipients"`
	PassRate         float64
}

// GetDomainAggStats returns aggregate stats for a policy domain, optionally scoped to from.
func GetDomainAggStats(db *sqlx.DB, domain string, from int64) (*DomainAggStats, error) {
	var s DomainAggStats
	var err error
	if from > 0 {
		err = db.Get(&s, `
			SELECT
				COALESCE(SUM(rr.count), 0) AS total_messages,
				COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS passed,
				COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS failed,
				COUNT(DISTINCT rr.source_ip) AS unique_senders,
				COUNT(DISTINCT CASE WHEN rr.envelope_to != '' AND rr.envelope_to != '<>' THEN rr.envelope_to END) AS unique_recipients
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ? AND r.date_range_begin >= ?`, domain, from)
	} else {
		err = db.Get(&s, `
			SELECT
				COALESCE(SUM(rr.count), 0) AS total_messages,
				COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS passed,
				COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS failed,
				COUNT(DISTINCT rr.source_ip) AS unique_senders,
				COUNT(DISTINCT CASE WHEN rr.envelope_to != '' AND rr.envelope_to != '<>' THEN rr.envelope_to END) AS unique_recipients
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ?`, domain)
	}
	if err != nil {
		return nil, err
	}
	if s.TotalMessages > 0 {
		s.PassRate = float64(s.Passed) / float64(s.TotalMessages) * 100
	}
	return &s, nil
}

// SourceAggStats holds period-scoped aggregate stats for a single source IP.
type SourceAggStats struct {
	TotalMessages int64 `db:"total_messages"`
	Passed        int64 `db:"passed"`
	Failed        int64 `db:"failed"`
	PassRate      float64
}

// GetSourceAggStats returns aggregate stats for a source IP, optionally scoped to from.
func GetSourceAggStats(db *sqlx.DB, ip string, from int64) (*SourceAggStats, error) {
	var s SourceAggStats
	var err error
	if from > 0 {
		err = db.Get(&s, `
			SELECT
				COALESCE(SUM(rr.count), 0) AS total_messages,
				COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS passed,
				COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS failed
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE rr.source_ip = ? AND r.date_range_begin >= ?`, ip, from)
	} else {
		err = db.Get(&s, `
			SELECT
				COALESCE(SUM(rr.count), 0) AS total_messages,
				COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS passed,
				COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS failed
			FROM record_rows rr
			WHERE rr.source_ip = ?`, ip)
	}
	if err != nil {
		return nil, err
	}
	if s.TotalMessages > 0 {
		s.PassRate = float64(s.Passed) / float64(s.TotalMessages) * 100
	}
	return &s, nil
}

// EnvelopeFromStat holds aggregate stats grouped by envelope_from domain.
type EnvelopeFromStat struct {
	EnvelopeFrom  string  `db:"envelope_from"`
	TotalMessages int64   `db:"total_messages"`
	Passed        int64   `db:"passed"`
	Failed        int64   `db:"failed"`
	PassRate      float64 `db:"pass_rate"`
}

// GetEnvelopeFromBreakdown returns per-envelope_from aggregate stats for a policy domain.
func GetEnvelopeFromBreakdown(db *sqlx.DB, domain string, from int64) ([]EnvelopeFromStat, error) {
	var stats []EnvelopeFromStat
	var err error
	if from > 0 {
		err = db.Select(&stats, `
			SELECT
				CASE WHEN rr.envelope_from = '' OR rr.envelope_from IS NULL THEN '(none)' ELSE rr.envelope_from END AS envelope_from,
				SUM(rr.count) AS total_messages,
				SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
				SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
				ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
					/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ? AND r.date_range_begin >= ?
			GROUP BY rr.envelope_from
			ORDER BY total_messages DESC`, domain, from)
	} else {
		err = db.Select(&stats, `
			SELECT
				CASE WHEN rr.envelope_from = '' OR rr.envelope_from IS NULL THEN '(none)' ELSE rr.envelope_from END AS envelope_from,
				SUM(rr.count) AS total_messages,
				SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
				SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
				ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
					/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			WHERE r.domain = ?
			GROUP BY rr.envelope_from
			ORDER BY total_messages DESC`, domain)
	}
	return stats, err
}
