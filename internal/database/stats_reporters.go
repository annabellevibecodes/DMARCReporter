package database

import (
	"sort"
	"time"

	"github.com/jmoiron/sqlx"
)

// ReporterInventoryRow is R1: one reporting organisation.
type ReporterInventoryRow struct {
	OrgName          string  `db:"org_name" json:"org_name"`
	Email            string  `db:"email" json:"email"`
	ExtraContactInfo string  `db:"extra_contact_info" json:"extra_contact_info"`
	Reports          int64   `db:"reports" json:"reports"`
	Messages         int64   `db:"messages" json:"messages"`
	Share            float64 `db:"-" json:"share"` // percent of all messages in the window
	Versions         string  `db:"versions" json:"versions"`
	Namespaces       string  `db:"namespaces" json:"namespaces"`
	FirstReport      int64   `db:"first_report" json:"first_report"` // min date_range_begin
	LastReport       int64   `db:"last_report" json:"last_report"`   // max date_range_end
	LastReceived     int64   `db:"last_received" json:"last_received"`
	Domains          int64   `db:"domains" json:"domains"`
	// Filled by the handler from R2/R3:
	DaysSilent    int     `db:"-" json:"days_silent"`
	Gap           bool    `db:"-" json:"gap"`
	Presence      []int   `db:"-" json:"presence"`
	LatencyMedian float64 `db:"-" json:"latency_median_h"`
	LatencyP95    float64 `db:"-" json:"latency_p95_h"`
	LatencyN      int     `db:"-" json:"latency_samples"`
}

// GetReporterInventory returns R1 for the window.
func GetReporterInventory(db *sqlx.DB, f StatsFilter) ([]ReporterInventoryRow, error) {
	var out []ReporterInventoryRow
	where, args := f.where()
	err := db.Select(&out, `
		SELECT
			r.org_name,
			COALESCE(MAX(r.email), '') AS email,
			COALESCE(MAX(r.extra_contact_info), '') AS extra_contact_info,
			COUNT(DISTINCT r.id) AS reports,
			COALESCE(SUM(rr.count), 0) AS messages,
			COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN r.version = '' THEN '(none)' ELSE r.version END), '') AS versions,
			COALESCE(GROUP_CONCAT(DISTINCT CASE WHEN r.xml_namespace = '' THEN 'rfc7489' ELSE 'dmarc-2.0' END), '') AS namespaces,
			MIN(r.date_range_begin) AS first_report,
			MAX(r.date_range_end) AS last_report,
			MAX(r.received_at) AS last_received,
			COUNT(DISTINCT r.domain) AS domains
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY r.org_name
		ORDER BY messages DESC, reports DESC`, args...)
	var total int64
	for _, r := range out {
		total += r.Messages
	}
	if total > 0 {
		for i := range out {
			out[i].Share = float64(out[i].Messages) / float64(total) * 100
		}
	}
	return out, err
}

// ReporterGap is R2: a reporter that was active recently but has gone quiet.
type ReporterGap struct {
	OrgName    string `db:"org_name" json:"org_name"`
	LastBegin  int64  `db:"last_begin" json:"last_begin"`
	LastEnd    int64  `db:"last_end" json:"last_end"`
	DaysSilent int    `db:"-" json:"days_silent"`
}

// GetReporterGaps returns reporters with at least one report whose window
// began in the last activeDays but none beginning in the last gapDays.
func GetReporterGaps(db *sqlx.DB, activeDays, gapDays int) ([]ReporterGap, error) {
	now := time.Now().UTC()
	var out []ReporterGap
	err := db.Select(&out, `
		SELECT r.org_name, MAX(r.date_range_begin) AS last_begin, MAX(r.date_range_end) AS last_end
		FROM reports r
		GROUP BY r.org_name
		HAVING MAX(r.date_range_begin) >= ? AND MAX(r.date_range_begin) < ?
		ORDER BY last_begin ASC`,
		now.AddDate(0, 0, -activeDays).Unix(), now.AddDate(0, 0, -gapDays).Unix())
	for i := range out {
		out[i].DaysSilent = int(now.Sub(time.Unix(out[i].LastEnd, 0)).Hours() / 24)
	}
	return out, err
}

// ReporterPresence is the per-day report count for one reporter (heat strip).
type ReporterPresence struct {
	OrgName string `json:"org_name"`
	Days    []int  `json:"days"` // oldest first, len == requested days
}

// GetReporterPresence returns, for every reporter with a report in the last
// `days` days, the number of reports per day (by date_range_begin), oldest first.
func GetReporterPresence(db *sqlx.DB, days int) ([]ReporterPresence, error) {
	if days <= 0 {
		days = 30
	}
	now := time.Now().UTC()
	start := now.AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)
	type row struct {
		OrgName string `db:"org_name"`
		Day     string `db:"day"`
		N       int    `db:"n"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT r.org_name, strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch')) AS day, COUNT(*) AS n
		FROM reports r
		WHERE r.date_range_begin >= ?
		GROUP BY r.org_name, day`, start.Unix()); err != nil {
		return nil, err
	}
	idx := map[string]int{}
	for i := 0; i < days; i++ {
		idx[start.AddDate(0, 0, i).Format("2006-01-02")] = i
	}
	byOrg := map[string]*ReporterPresence{}
	var names []string
	for _, r := range rows {
		p, ok := byOrg[r.OrgName]
		if !ok {
			p = &ReporterPresence{OrgName: r.OrgName, Days: make([]int, days)}
			byOrg[r.OrgName] = p
			names = append(names, r.OrgName)
		}
		if i, ok := idx[r.Day]; ok {
			p.Days[i] += r.N
		}
	}
	sort.Strings(names)
	out := make([]ReporterPresence, 0, len(names))
	for _, n := range names {
		out = append(out, *byOrg[n])
	}
	return out, nil
}

// ReporterLatency is R3: how long after a report window closes the report arrives.
type ReporterLatency struct {
	OrgName     string  `json:"org_name"`
	Samples     int     `json:"samples"`
	MedianHours float64 `json:"median_hours"`
	P95Hours    float64 `json:"p95_hours"`
	MinHours    float64 `json:"min_hours"`
	MaxHours    float64 `json:"max_hours"`
}

// GetReportLatency computes received_at − date_range_end per reporter,
// skipping reports without a received_at (bare uploads, pre-extension imports).
func GetReportLatency(db *sqlx.DB, f StatsFilter) ([]ReporterLatency, error) {
	type row struct {
		ID      int64  `db:"id"`
		OrgName string `db:"org_name"`
		Delta   int64  `db:"delta"`
	}
	var rows []row
	and, args := f.andClauses()
	// f's clauses reference rr.* only for envelope_from / source_ip; join when needed.
	join := ""
	if f.EnvelopeFrom != "" || f.SourceIP != "" {
		join = " JOIN record_rows rr ON rr.report_id = r.id"
	}
	if err := db.Select(&rows, `
		SELECT DISTINCT r.id, r.org_name, r.received_at - r.date_range_end AS delta
		FROM reports r`+join+`
		WHERE r.received_at > 0`+and+`
		ORDER BY r.org_name, delta`, args...); err != nil {
		return nil, err
	}
	byOrg := map[string][]float64{}
	var names []string
	for _, r := range rows {
		if _, ok := byOrg[r.OrgName]; !ok {
			names = append(names, r.OrgName)
		}
		byOrg[r.OrgName] = append(byOrg[r.OrgName], float64(r.Delta)/3600)
	}
	sort.Strings(names)
	out := make([]ReporterLatency, 0, len(names))
	for _, n := range names {
		v := byOrg[n]
		sort.Float64s(v)
		out = append(out, ReporterLatency{
			OrgName: n, Samples: len(v),
			MedianHours: percentile(v, 50), P95Hours: percentile(v, 95),
			MinHours: v[0], MaxHours: v[len(v)-1],
		})
	}
	return out, nil
}

// percentile returns the p-th percentile (nearest-rank) of sorted values.
func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(float64(len(sorted))*p/100+0.5) - 1
	if rank < 0 {
		rank = 0
	}
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

// DateRangeAnomaly is R4: a report whose window is not ~24 hours.
type DateRangeAnomaly struct {
	ID            int64   `db:"id" json:"id"`
	OrgName       string  `db:"org_name" json:"org_name"`
	ReportID      string  `db:"report_id" json:"report_id"`
	Domain        string  `db:"domain" json:"domain"`
	Begin         int64   `db:"date_range_begin" json:"begin"`
	End           int64   `db:"date_range_end" json:"end"`
	DurationHours float64 `db:"-" json:"duration_hours"`
}

// GetDateRangeAnomalies returns reports with (end − begin) outside 23h–25h
// plus the total count.
func GetDateRangeAnomalies(db *sqlx.DB, f StatsFilter, limit int) ([]DateRangeAnomaly, int, error) {
	if limit <= 0 {
		limit = 50
	}
	and, args := f.andClauses()
	join := ""
	if f.EnvelopeFrom != "" || f.SourceIP != "" {
		join = " JOIN record_rows rr ON rr.report_id = r.id"
	}
	const cond = ` AND (r.date_range_end - r.date_range_begin < 23*3600 OR r.date_range_end - r.date_range_begin > 25*3600)`
	var total int
	if err := db.Get(&total, `SELECT COUNT(DISTINCT r.id) FROM reports r`+join+` WHERE 1=1`+cond+and, args...); err != nil {
		return nil, 0, err
	}
	var out []DateRangeAnomaly
	pageArgs := append(append([]any{}, args...), limit)
	if err := db.Select(&out, `
		SELECT DISTINCT r.id, r.org_name, r.report_id, r.domain, r.date_range_begin, r.date_range_end
		FROM reports r`+join+`
		WHERE 1=1`+cond+and+`
		ORDER BY r.date_range_begin DESC
		LIMIT ?`, pageArgs...); err != nil {
		return nil, 0, err
	}
	for i := range out {
		out[i].DurationHours = float64(out[i].End-out[i].Begin) / 3600
	}
	return out, total, nil
}

// SchemaDistributionRow is R6: reports by version + namespace.
type SchemaDistributionRow struct {
	Version   string `db:"version" json:"version"`
	Namespace string `db:"xml_namespace" json:"namespace"`
	Reports   int64  `db:"reports" json:"reports"`
	Reporters string `db:"reporters" json:"reporters"`
}

// GetSchemaDistribution returns R6's version/namespace breakdown.
func GetSchemaDistribution(db *sqlx.DB, f StatsFilter) ([]SchemaDistributionRow, error) {
	var out []SchemaDistributionRow
	and, args := f.andClauses()
	join := ""
	if f.EnvelopeFrom != "" || f.SourceIP != "" {
		join = " JOIN record_rows rr ON rr.report_id = r.id"
	}
	err := db.Select(&out, `
		SELECT
			CASE WHEN r.version = '' THEN '(none)' ELSE r.version END AS version,
			CASE WHEN r.xml_namespace = '' THEN 'rfc7489' ELSE 'dmarc-2.0' END AS xml_namespace,
			COUNT(DISTINCT r.id) AS reports,
			GROUP_CONCAT(DISTINCT r.org_name) AS reporters
		FROM reports r`+join+`
		WHERE 1=1`+and+`
		GROUP BY 1, 2
		ORDER BY reports DESC`, args...)
	return out, err
}

// UnmanagedDomain is R7: a policy domain that is not in managed_domains.
type UnmanagedDomain struct {
	Domain    string `db:"domain" json:"domain"`
	Reports   int64  `db:"reports" json:"reports"`
	Messages  int64  `db:"messages" json:"messages"`
	FirstSeen int64  `db:"first_seen" json:"first_seen"`
	LastSeen  int64  `db:"last_seen" json:"last_seen"`
}

// GetUnmanagedDomains returns R7 for the window.
func GetUnmanagedDomains(db *sqlx.DB, f StatsFilter) ([]UnmanagedDomain, error) {
	var out []UnmanagedDomain
	and, args := f.andClauses()
	err := db.Select(&out, `
		SELECT r.domain, COUNT(DISTINCT r.id) AS reports, COALESCE(SUM(rr.count), 0) AS messages,
			MIN(r.date_range_begin) AS first_seen, MAX(r.date_range_begin) AS last_seen
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id
		WHERE LOWER(r.domain) NOT IN (SELECT LOWER(domain) FROM managed_domains)`+and+`
		GROUP BY r.domain
		ORDER BY messages DESC`, args...)
	return out, err
}

// GetEnvelopeToStats is R8 scoped by f: recipient domains with pass rate.
func GetEnvelopeToStats(db *sqlx.DB, f StatsFilter, limit int) ([]EnvelopeToStat, error) {
	if limit <= 0 {
		limit = 25
	}
	var stats []EnvelopeToStat
	and, args := f.andClauses()
	args = append(args, limit)
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
		WHERE rr.envelope_to != '' AND rr.envelope_to != '<>'`+and+`
		GROUP BY rr.envelope_to
		ORDER BY total_messages DESC
		LIMIT ?`, args...)
	return stats, err
}
