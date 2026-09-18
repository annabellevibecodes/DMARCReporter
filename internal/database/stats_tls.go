package database

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// TLSFilter scopes TLS-RPT queries by policy domain and report window, the
// same way StatsFilter does for DMARC. Zero values mean "no constraint".
//
// RequireDKIM carries TLSRPT_REQUIRE_DKIM into every query rather than leaving
// each metric to remember it: RFC 8460 §3 says a mailed report without a valid
// signature must be ignored, and a metric that forgot the clause would quietly
// count reports the operator believes are excluded.
type TLSFilter struct {
	Domain      string
	From, To    int64
	Compare     bool
	RequireDKIM bool

	// MXHostname and ReceivingIP narrow the failure-detail metrics only.
	// Session counts come from the policy summaries, which carry no
	// addresses at all, so a drill-down on one host or node cannot scope
	// them — the page says which figures the filter reached rather than
	// showing a total that quietly ignores it.
	MXHostname  string
	ReceivingIP string
	// ResultType and SendingIP narrow the failure-detail metrics too, and
	// exist for /api/tls/failures rather than the page.
	ResultType string
	SendingIP  string
}

// clauses builds the shared predicates over aliases r (tlsrpt_reports) and
// p (tlsrpt_policies). withPolicy must be false for report-level queries that
// do not join tlsrpt_policies.
func (f TLSFilter) clauses(withPolicy, withTime bool) ([]string, []any) {
	var clauses []string
	var args []any
	if f.Domain != "" {
		if withPolicy {
			clauses = append(clauses, "p.policy_domain = ?")
		} else {
			clauses = append(clauses, "EXISTS (SELECT 1 FROM tlsrpt_policies dp WHERE dp.tlsrpt_report_id = r.id AND dp.policy_domain = ?)")
		}
		args = append(args, strings.ToLower(f.Domain))
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
	if f.RequireDKIM {
		// Only mailed reports can be excluded: an uploaded file has no
		// carrying message, so there is no signature to hold against it.
		clauses = append(clauses, "NOT (r.transport = ? AND r.dkim_status != ?)")
		args = append(args, TransportSMTP, tlsDKIMValid)
	}
	return clauses, args
}

// tlsDKIMValid is dkimcheck.StatusValid as stored. Spelled out here so the
// SQL layer does not depend on the verification package.
const tlsDKIMValid = "valid"

// where returns a WHERE clause for queries joining reports and policies.
func (f TLSFilter) where() (string, []any) {
	clauses, args := f.clauses(true, true)
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// whereFailures is where() plus the drill-down predicates that only apply to
// failure-detail rows (alias f).
func (f TLSFilter) whereFailures() (string, []any) {
	clauses, args := f.clauses(true, true)
	if f.MXHostname != "" {
		clauses = append(clauses, "f.receiving_mx_hostname = ?")
		args = append(args, strings.ToLower(f.MXHostname))
	}
	if f.ReceivingIP != "" {
		clauses = append(clauses, "f.receiving_ip = ?")
		args = append(args, f.ReceivingIP)
	}
	if f.ResultType != "" {
		clauses = append(clauses, "f.result_type = ?")
		args = append(args, strings.ToLower(f.ResultType))
	}
	if f.SendingIP != "" {
		clauses = append(clauses, "f.sending_mta_ip = ?")
		args = append(args, f.SendingIP)
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// whereReports is where() for queries over tlsrpt_reports alone.
func (f TLSFilter) whereReports() (string, []any) {
	clauses, args := f.clauses(false, true)
	if len(clauses) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

// WindowEnd returns the effective upper bound of the filter (To, or now).
func (f TLSFilter) WindowEnd() int64 {
	if f.To > 0 {
		return f.To
	}
	return time.Now().Unix()
}

// PreviousWindow returns the window of equal length immediately before f.
func (f TLSFilter) PreviousWindow() (prev TLSFilter, ok bool) {
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

// TLSWithComparison is WithComparison for TLS metrics: it runs fn for f and,
// when f.Compare is set and a previous window exists, again for that window.
func TLSWithComparison[T any](f TLSFilter, fn func(TLSFilter) (T, error)) (Comparison[T], error) {
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

// tlsSessionsCTE is the one definition of "a session count" in this codebase.
//
// Within a report, policy entries that share a policy domain and mx-host
// pattern are collapsed by taking the maximum rather than the sum (I2): an
// MTA-STS policy and a TLSA record can describe the same sessions, and adding
// them counts that traffic twice. Every session-level metric builds on this,
// so the rule is applied once and cannot drift between metrics.
const tlsSessionsCTE = `
	WITH sessions AS (
		SELECT p.tlsrpt_report_id   AS report_id,
		       r.org_name           AS org_name,
		       r.date_range_begin   AS begin_ts,
		       r.date_range_end     AS end_ts,
		       p.policy_domain      AS policy_domain,
		       p.mx_host_pattern    AS mx_host_pattern,
		       MAX(p.success_count) AS success,
		       MAX(p.failure_count) AS failure
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id%s
		 GROUP BY p.tlsrpt_report_id, p.policy_domain, p.mx_host_pattern
	)`

// tlsSessions returns the CTE with f's predicates inlined, plus its arguments.
func tlsSessions(f TLSFilter) (string, []any) {
	where, args := f.where()
	return fmt.Sprintf(tlsSessionsCTE, where), args
}

// tlsRate is success as a percentage of attempted sessions.
func tlsRate(success, failure int64) float64 {
	total := success + failure
	if total <= 0 {
		return 0
	}
	return float64(success) / float64(total) * 100
}

// TLSRate is T1 for one scope: the headline success rate.
type TLSRate struct {
	Success int64   `db:"success" json:"success"`
	Failure int64   `db:"failure" json:"failure"`
	Total   int64   `db:"total" json:"total"`
	Rate    float64 `db:"-" json:"rate"`
}

// GetTLSRate is T1 overall: the share of attempted sessions that negotiated
// TLS successfully, over the whole filtered window.
func GetTLSRate(db *sqlx.DB, f TLSFilter) (*TLSRate, error) {
	cte, args := tlsSessions(f)
	var out TLSRate
	if err := db.Get(&out, cte+`
		SELECT COALESCE(SUM(success), 0) AS success,
		       COALESCE(SUM(failure), 0) AS failure,
		       COALESCE(SUM(success), 0) + COALESCE(SUM(failure), 0) AS total
		  FROM sessions`, args...); err != nil {
		return nil, err
	}
	out.Rate = tlsRate(out.Success, out.Failure)
	return &out, nil
}

// TLSDomainRate is T1 per policy domain.
type TLSDomainRate struct {
	PolicyDomain string  `db:"policy_domain" json:"policy_domain"`
	Success      int64   `db:"success" json:"success"`
	Failure      int64   `db:"failure" json:"failure"`
	Total        int64   `db:"total" json:"total"`
	Rate         float64 `db:"-" json:"rate"`
}

// GetTLSRateByDomain is T1 broken out per policy domain, worst rate first so
// the domain needing attention is at the top.
func GetTLSRateByDomain(db *sqlx.DB, f TLSFilter) ([]TLSDomainRate, error) {
	cte, args := tlsSessions(f)
	var out []TLSDomainRate
	if err := db.Select(&out, cte+`
		SELECT policy_domain,
		       COALESCE(SUM(success), 0) AS success,
		       COALESCE(SUM(failure), 0) AS failure,
		       COALESCE(SUM(success), 0) + COALESCE(SUM(failure), 0) AS total
		  FROM sessions
		 GROUP BY policy_domain
		 ORDER BY failure DESC, total DESC`, args...); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Rate = tlsRate(out[i].Success, out[i].Failure)
	}
	return out, nil
}

// TLSDayPoint is one day of the T1/T2 series.
type TLSDayPoint struct {
	Day     string  `db:"day" json:"day"`
	Success int64   `db:"success" json:"success"`
	Failure int64   `db:"failure" json:"failure"`
	Rate    float64 `db:"-" json:"rate"`
}

// GetTLSDailySeries is T1 per day, bucketed on the report window's start —
// never the mail date or the filename (I4).
func GetTLSDailySeries(db *sqlx.DB, f TLSFilter) ([]TLSDayPoint, error) {
	cte, args := tlsSessions(f)
	var out []TLSDayPoint
	if err := db.Select(&out, cte+`
		SELECT strftime('%Y-%m-%d', datetime(begin_ts, 'unixepoch')) AS day,
		       COALESCE(SUM(success), 0) AS success,
		       COALESCE(SUM(failure), 0) AS failure
		  FROM sessions
		 GROUP BY day
		 ORDER BY day`, args...); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Rate = tlsRate(out[i].Success, out[i].Failure)
	}
	return out, nil
}

// TLSReporterShare is one reporting organisation's slice of T2.
type TLSReporterShare struct {
	OrgName  string  `db:"org_name" json:"org_name"`
	Reports  int64   `db:"reports" json:"reports"`
	Success  int64   `db:"success" json:"success"`
	Failure  int64   `db:"failure" json:"failure"`
	Sessions int64   `db:"sessions" json:"sessions"`
	Share    float64 `db:"-" json:"share"` // percent of all sessions in the window
	Rate     float64 `db:"-" json:"rate"`
}

// TLSVolume is T2: how much traffic was reported, by whom, and the two
// success rates that answer different questions.
type TLSVolume struct {
	Sessions      int64              `json:"sessions"`
	Reports       int64              `json:"reports"`
	ReporterCount int                `json:"reporter_count"`
	ByDay         []TLSDayPoint      `json:"by_day"`
	Reporters     []TLSReporterShare `json:"reporter_shares"`

	// WeightedRate is the session-weighted success rate — the true rate for
	// the traffic as a whole.
	WeightedRate float64 `json:"weighted_rate"`
	// MedianReporterRate is the median of the per-reporter rates, each
	// counted once. One hyperscaler sending most of the volume otherwise
	// masks a smaller receiver that is failing completely.
	MedianReporterRate float64 `json:"median_reporter_rate"`
}

// GetTLSVolume is T2.
func GetTLSVolume(db *sqlx.DB, f TLSFilter) (*TLSVolume, error) {
	cte, args := tlsSessions(f)

	out := &TLSVolume{}
	if err := db.Select(&out.Reporters, cte+`
		SELECT org_name,
		       COUNT(DISTINCT report_id) AS reports,
		       COALESCE(SUM(success), 0) AS success,
		       COALESCE(SUM(failure), 0) AS failure,
		       COALESCE(SUM(success), 0) + COALESCE(SUM(failure), 0) AS sessions
		  FROM sessions
		 GROUP BY org_name
		 ORDER BY sessions DESC, org_name`, args...); err != nil {
		return nil, err
	}

	var rates []float64
	for i := range out.Reporters {
		r := &out.Reporters[i]
		r.Rate = tlsRate(r.Success, r.Failure)
		out.Sessions += r.Sessions
		out.Reports += r.Reports
		if r.Sessions > 0 {
			rates = append(rates, r.Rate)
		}
	}
	out.ReporterCount = len(out.Reporters)
	for i := range out.Reporters {
		if out.Sessions > 0 {
			out.Reporters[i].Share = float64(out.Reporters[i].Sessions) / float64(out.Sessions) * 100
		}
	}

	total, err := GetTLSRate(db, f)
	if err != nil {
		return nil, err
	}
	out.WeightedRate = total.Rate
	out.MedianReporterRate = medianOf(rates)

	if out.ByDay, err = GetTLSDailySeries(db, f); err != nil {
		return nil, err
	}
	if out.Reporters == nil {
		out.Reporters = []TLSReporterShare{}
	}
	if out.ByDay == nil {
		out.ByDay = []TLSDayPoint{}
	}
	return out, nil
}

// medianOf returns the median of xs (0 for an empty slice).
func medianOf(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// TLSPolicyTypeRow is one policy type's slice of T3.
type TLSPolicyTypeRow struct {
	PolicyType string  `db:"policy_type" json:"policy_type"`
	Sessions   int64   `db:"sessions" json:"sessions"`
	Success    int64   `db:"success" json:"success"`
	Failure    int64   `db:"failure" json:"failure"`
	Share      float64 `db:"-" json:"share"`
	Rate       float64 `db:"-" json:"rate"`
}

// TLSPolicyMix is T3: which policy the sender actually applied.
//
// The share of no-policy-found is the adoption number for an MTA-STS or DANE
// rollout: it is the traffic that found no policy to apply at all.
type TLSPolicyMix struct {
	Overall    []TLSPolicyTypeRow            `json:"overall"`
	ByReporter map[string][]TLSPolicyTypeRow `json:"by_reporter"`
	// MultiPolicySessions is traffic described under more than one policy
	// type in the same report. Such sessions are counted under each type they
	// were reported with, so the type shares can add up to more than 100%.
	MultiPolicySessions int64 `json:"multi_policy_sessions"`
}

// GetTLSPolicyMix is T3.
//
// Unlike the session metrics this counts per policy entry rather than per
// rollup group: the question is which policy types were applied, and the
// rollup deliberately discards that distinction.
func GetTLSPolicyMix(db *sqlx.DB, f TLSFilter) (*TLSPolicyMix, error) {
	where, args := f.where()
	out := &TLSPolicyMix{ByReporter: map[string][]TLSPolicyTypeRow{}}

	if err := db.Select(&out.Overall, `
		SELECT CASE WHEN p.policy_type = '' THEN '(unspecified)' ELSE p.policy_type END AS policy_type,
		       COALESCE(SUM(p.success_count), 0) + COALESCE(SUM(p.failure_count), 0) AS sessions,
		       COALESCE(SUM(p.success_count), 0) AS success,
		       COALESCE(SUM(p.failure_count), 0) AS failure
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
		 GROUP BY policy_type
		 ORDER BY sessions DESC`, args...); err != nil {
		return nil, err
	}
	var total int64
	for _, row := range out.Overall {
		total += row.Sessions
	}
	for i := range out.Overall {
		if total > 0 {
			out.Overall[i].Share = float64(out.Overall[i].Sessions) / float64(total) * 100
		}
		out.Overall[i].Rate = tlsRate(out.Overall[i].Success, out.Overall[i].Failure)
	}

	var byReporter []struct {
		OrgName string `db:"org_name"`
		TLSPolicyTypeRow
	}
	if err := db.Select(&byReporter, `
		SELECT r.org_name,
		       CASE WHEN p.policy_type = '' THEN '(unspecified)' ELSE p.policy_type END AS policy_type,
		       COALESCE(SUM(p.success_count), 0) + COALESCE(SUM(p.failure_count), 0) AS sessions,
		       COALESCE(SUM(p.success_count), 0) AS success,
		       COALESCE(SUM(p.failure_count), 0) AS failure
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
		 GROUP BY r.org_name, policy_type
		 ORDER BY r.org_name, sessions DESC`, args...); err != nil {
		return nil, err
	}
	perOrgTotal := map[string]int64{}
	for _, row := range byReporter {
		perOrgTotal[row.OrgName] += row.Sessions
	}
	for _, row := range byReporter {
		r := row.TLSPolicyTypeRow
		if t := perOrgTotal[row.OrgName]; t > 0 {
			r.Share = float64(r.Sessions) / float64(t) * 100
		}
		r.Rate = tlsRate(r.Success, r.Failure)
		out.ByReporter[row.OrgName] = append(out.ByReporter[row.OrgName], r)
	}

	if err := db.Get(&out.MultiPolicySessions, `
		SELECT COALESCE(SUM(sessions), 0) FROM (
			SELECT MAX(p.success_count) + MAX(p.failure_count) AS sessions
			  FROM tlsrpt_policies p
			  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
			 GROUP BY p.tlsrpt_report_id, p.policy_domain, p.mx_host_pattern
			HAVING COUNT(*) > 1
		)`, args...); err != nil {
		return nil, err
	}
	if out.Overall == nil {
		out.Overall = []TLSPolicyTypeRow{}
	}
	return out, nil
}

// TLSModeRow is one observed MTA-STS mode.
type TLSModeRow struct {
	Mode     string  `db:"mode" json:"mode"`
	Sessions int64   `db:"sessions" json:"sessions"`
	Success  int64   `db:"success" json:"success"`
	Failure  int64   `db:"failure" json:"failure"`
	Share    float64 `db:"-" json:"share"`
}

// TLSEnforcementReadiness is T9: the MTA-STS analogue of the DMARC
// enforcement-readiness view.
type TLSEnforcementReadiness struct {
	Modes []TLSModeRow `json:"modes"`
	// TestingSessions and TestingFailures are the traffic seen under
	// mode=testing, where a failure is reported but mail still flows.
	TestingSessions int64 `json:"testing_sessions"`
	TestingFailures int64 `json:"testing_failures"`
	// WouldBlock is what moving those policies to mode=enforce would have
	// cost over this window: every failing session becomes undeliverable.
	WouldBlock int64 `json:"would_block"`
	// EnforceSessions is traffic already under mode=enforce.
	EnforceSessions int64   `json:"enforce_sessions"`
	EnforceFailures int64   `json:"enforce_failures"`
	TestingRate     float64 `json:"testing_rate"`
}

// GetTLSEnforcementReadiness is T9.
func GetTLSEnforcementReadiness(db *sqlx.DB, f TLSFilter) (*TLSEnforcementReadiness, error) {
	where, args := f.where()
	out := &TLSEnforcementReadiness{}
	if err := db.Select(&out.Modes, `
		SELECT CASE WHEN p.sts_mode = '' THEN '(none)' ELSE p.sts_mode END AS mode,
		       COALESCE(SUM(p.success_count), 0) + COALESCE(SUM(p.failure_count), 0) AS sessions,
		       COALESCE(SUM(p.success_count), 0) AS success,
		       COALESCE(SUM(p.failure_count), 0) AS failure
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
		 GROUP BY mode
		 ORDER BY sessions DESC`, args...); err != nil {
		return nil, err
	}
	var total int64
	for _, m := range out.Modes {
		total += m.Sessions
	}
	for i := range out.Modes {
		if total > 0 {
			out.Modes[i].Share = float64(out.Modes[i].Sessions) / float64(total) * 100
		}
		switch out.Modes[i].Mode {
		case "testing":
			out.TestingSessions = out.Modes[i].Sessions
			out.TestingFailures = out.Modes[i].Failure
			out.WouldBlock = out.Modes[i].Failure
			out.TestingRate = tlsRate(out.Modes[i].Success, out.Modes[i].Failure)
		case "enforce":
			out.EnforceSessions = out.Modes[i].Sessions
			out.EnforceFailures = out.Modes[i].Failure
		}
	}
	if out.Modes == nil {
		out.Modes = []TLSModeRow{}
	}
	return out, nil
}

// TLSPolicyDivergence is the part of T8 that needs no published snapshot:
// more than one distinct policy string seen for a domain on a single day,
// which means either a stale cache somewhere or a divergent policy being
// served.
type TLSPolicyDivergence struct {
	Day          string   `json:"day"`
	PolicyDomain string   `json:"policy_domain"`
	Distinct     int      `json:"distinct"`
	Strings      []string `json:"strings"`
}

// GetTLSPolicyDivergence is T8's same-day divergence check.
//
// Drift against the currently published policy needs the DNS snapshots that
// arrive with the Enrich extension; until then this covers what the reports
// alone can prove.
func GetTLSPolicyDivergence(db *sqlx.DB, f TLSFilter) ([]TLSPolicyDivergence, error) {
	where, args := f.where()
	var rows []struct {
		Day          string `db:"day"`
		PolicyDomain string `db:"policy_domain"`
		PolicyString string `db:"policy_string"`
	}
	if err := db.Select(&rows, `
		SELECT DISTINCT strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch')) AS day,
		       p.policy_domain, p.policy_string
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
		   AND p.policy_string NOT IN ('', '[]', 'null')
		 ORDER BY day, p.policy_domain`, args...); err != nil {
		return nil, err
	}

	type key struct{ day, domain string }
	grouped := map[key][]string{}
	var order []key
	for _, row := range rows {
		k := key{row.Day, row.PolicyDomain}
		if _, seen := grouped[k]; !seen {
			order = append(order, k)
		}
		grouped[k] = append(grouped[k], row.PolicyString)
	}

	var out []TLSPolicyDivergence
	for _, k := range order {
		if len(grouped[k]) < 2 {
			continue
		}
		out = append(out, TLSPolicyDivergence{
			Day: k.day, PolicyDomain: k.domain,
			Distinct: len(grouped[k]), Strings: grouped[k],
		})
	}
	return out, nil
}

// TLSReporterGap is a TLS reporter that stopped reporting.
type TLSReporterGap struct {
	OrgName    string `db:"org_name" json:"org_name"`
	LastBegin  int64  `db:"last_begin" json:"last_begin"`
	LastEnd    int64  `db:"last_end" json:"last_end"`
	DaysSilent int    `db:"days_silent" json:"days_silent"`
}

// TLSLatency is the arrival delay of TLS reports (T12).
type TLSLatency struct {
	MedianHours float64 `json:"median_hours"`
	P95Hours    float64 `json:"p95_hours"`
	Samples     int     `json:"samples"`
}

// TLSCoverage is T12: who is reporting, who stopped, and how promptly.
//
// Absence is the point. RFC 8460 frames the success counts as a heartbeat:
// an attacker who suppresses a domain's _smtp._tls record also suppresses the
// reports, so a reporter going quiet is a finding, not a gap in the chart.
type TLSCoverage struct {
	Reporters int              `json:"reporters"`
	New       []string         `json:"new_reporters"`
	Lapsed    []TLSReporterGap `json:"lapsed_reporters"`
	// DaysWithNoReport counts days inside the window for which no report
	// window began. It is only meaningful for a bounded window.
	DaysWithNoReport int        `json:"days_with_no_report"`
	WindowDays       int        `json:"window_days"`
	Latency          TLSLatency `json:"latency"`
}

// GetTLSCoverage is T12. gapDays is the silence that makes a reporter lapsed
// (ALERT_TLS_REPORTER_GAP_DAYS in phase 6; callers pass their configured value).
func GetTLSCoverage(db *sqlx.DB, f TLSFilter, gapDays int, now time.Time) (*TLSCoverage, error) {
	if gapDays <= 0 {
		gapDays = 3
	}
	where, args := f.whereReports()
	out := &TLSCoverage{New: []string{}, Lapsed: []TLSReporterGap{}}

	if err := db.Get(&out.Reporters, `
		SELECT COUNT(DISTINCT r.org_name) FROM tlsrpt_reports r`+where, args...); err != nil {
		return nil, err
	}

	// New: first report ever falls inside the window. Compared against all of
	// history, not just the window, or every reporter looks new.
	if f.From > 0 {
		if err := db.Select(&out.New, `
			SELECT org_name FROM (
				SELECT r.org_name, MIN(r.date_range_begin) AS first_begin
				  FROM tlsrpt_reports r
				 GROUP BY r.org_name
			) WHERE first_begin >= ? ORDER BY org_name`, f.From); err != nil {
			return nil, err
		}
	}

	// Lapsed: active in the last 14 days of history, silent for gapDays.
	active := now.AddDate(0, 0, -14).Unix()
	cutoff := now.AddDate(0, 0, -gapDays).Unix()
	if err := db.Select(&out.Lapsed, `
		SELECT org_name, last_begin, last_end,
		       CAST((? - last_end) / 86400 AS INTEGER) AS days_silent
		  FROM (
			SELECT r.org_name,
			       MAX(r.date_range_begin) AS last_begin,
			       MAX(r.date_range_end) AS last_end
			  FROM tlsrpt_reports r
			 GROUP BY r.org_name
		  )
		 WHERE last_end >= ? AND last_end < ?
		 ORDER BY last_end`, now.Unix(), active, cutoff); err != nil {
		return nil, err
	}

	// Latency: mail arrival minus the end of the window it covers.
	var latencies []float64
	if err := db.Select(&latencies, `
		SELECT (r.received_at - r.date_range_end) / 3600.0
		  FROM tlsrpt_reports r`+whereAnd(where, "r.received_at > 0 AND r.received_at >= r.date_range_end"),
		args...); err != nil {
		return nil, err
	}
	out.Latency = TLSLatency{Samples: len(latencies)}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		out.Latency.MedianHours = medianOf(latencies)
		out.Latency.P95Hours = latencies[percentileIndex(len(latencies), 0.95)]
	}

	if f.From > 0 {
		end := f.WindowEnd()
		out.WindowDays = int((end-f.From)/86400) + 1
		var daysWithReports int
		if err := db.Get(&daysWithReports, `
			SELECT COUNT(DISTINCT strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch')))
			  FROM tlsrpt_reports r`+where, args...); err != nil {
			return nil, err
		}
		if out.DaysWithNoReport = out.WindowDays - daysWithReports; out.DaysWithNoReport < 0 {
			out.DaysWithNoReport = 0
		}
	}
	return out, nil
}

// whereAnd appends an extra predicate to an existing WHERE clause (or starts one).
func whereAnd(where, predicate string) string {
	if where == "" {
		return " WHERE " + predicate
	}
	return where + " AND " + predicate
}

// percentileIndex returns the index of the p-th percentile in a sorted slice of n.
func percentileIndex(n int, p float64) int {
	if n <= 0 {
		return 0
	}
	i := int(float64(n)*p) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return i
}

// TLSStatusCount is one dkim_status with its report count (T13).
type TLSStatusCount struct {
	Status string `db:"status" json:"status"`
	Count  int64  `db:"count" json:"count"`
}

// TLSHygiene is T13: everything that makes the numbers above less trustworthy
// than they look.
type TLSHygiene struct {
	Reports int64 `db:"reports" json:"reports"`
	// Ingest outcomes for TLS attachments in the window.
	Duplicates     int64 `db:"duplicates" json:"duplicates"`
	DuplicateRange int64 `db:"duplicate_range" json:"duplicate_range"`
	ParseErrors    int64 `db:"parse_errors" json:"parse_errors"`
	Rejected       int64 `db:"rejected" json:"rejected"`

	// DKIM. Excluded is how many reports the RFC 8460 §3 rule actually keeps
	// out of every other metric on this page.
	DKIMByStatus []TLSStatusCount `db:"-" json:"dkim_by_status"`
	Excluded     int64            `db:"-" json:"excluded"`

	UnattributedFailures int64 `db:"unattributed_failures" json:"unattributed_failures"`
	MultiPolicyReports   int64 `db:"multi_policy_reports" json:"multi_policy_reports"`
	UnknownResultTypes   int64 `db:"unknown_result_types" json:"unknown_result_types"`
	MalformedIPs         int64 `db:"malformed_ips" json:"malformed_ips"`
	RangeVariance        int64 `db:"range_variance" json:"range_variance"`

	NonDailyWindows int64 `db:"non_daily_windows" json:"non_daily_windows"`
	MultiDayWindows int64 `db:"multi_day_windows" json:"multi_day_windows"`

	TransportSMTP   int64 `db:"transport_smtp" json:"transport_smtp"`
	TransportUpload int64 `db:"transport_upload" json:"transport_upload"`
	TransportBefore int64 `db:"transport_unknown" json:"transport_unknown"` // imported before the column existed
	Compressed      int64 `db:"compressed" json:"compressed"`
	Plain           int64 `db:"plain" json:"plain"`
}

// GetTLSHygiene is T13.
//
// The DKIM and ingest counts deliberately ignore f.RequireDKIM: this is the
// panel that has to show what was excluded, so it cannot itself apply the
// exclusion.
func GetTLSHygiene(db *sqlx.DB, f TLSFilter) (*TLSHygiene, error) {
	unfiltered := f
	unfiltered.RequireDKIM = false
	where, args := unfiltered.whereReports()

	out := &TLSHygiene{}
	if err := db.Get(out, `
		SELECT COUNT(*) AS reports,
		       COALESCE(SUM(r.unattributed_failures), 0) AS unattributed_failures,
		       COALESCE(SUM(r.multi_policy), 0) AS multi_policy_reports,
		       COALESCE(SUM(r.unknown_result_types), 0) AS unknown_result_types,
		       COALESCE(SUM(r.malformed_ips), 0) AS malformed_ips,
		       COALESCE(SUM(r.range_variance), 0) AS range_variance,
		       COALESCE(SUM(CASE WHEN (r.date_range_end - r.date_range_begin) < 86340 THEN 1 ELSE 0 END), 0) AS non_daily_windows,
		       COALESCE(SUM(CASE WHEN (r.date_range_end - r.date_range_begin) > 86400 THEN 1 ELSE 0 END), 0) AS multi_day_windows,
		       COALESCE(SUM(CASE WHEN r.transport = 'smtp' THEN 1 ELSE 0 END), 0) AS transport_smtp,
		       COALESCE(SUM(CASE WHEN r.transport = 'upload' THEN 1 ELSE 0 END), 0) AS transport_upload,
		       COALESCE(SUM(CASE WHEN r.transport = '' THEN 1 ELSE 0 END), 0) AS transport_unknown,
		       COALESCE(SUM(CASE WHEN lower(r.source_filename) LIKE '%.gz' THEN 1 ELSE 0 END), 0) AS compressed,
		       COALESCE(SUM(CASE WHEN lower(r.source_filename) NOT LIKE '%.gz' THEN 1 ELSE 0 END), 0) AS plain
		  FROM tlsrpt_reports r`+where, args...); err != nil {
		return nil, err
	}

	if err := db.Select(&out.DKIMByStatus, `
		SELECT r.dkim_status AS status, COUNT(*) AS count
		  FROM tlsrpt_reports r`+whereAnd(where, "r.transport = 'smtp'")+`
		 GROUP BY r.dkim_status ORDER BY count DESC`, args...); err != nil {
		return nil, err
	}
	for _, s := range out.DKIMByStatus {
		if s.Status != tlsDKIMValid {
			out.Excluded += s.Count
		}
	}
	if !f.RequireDKIM {
		// Nothing is actually being kept out; the breakdown still shows what
		// would be if the requirement were switched on.
		out.Excluded = 0
	}
	if out.DKIMByStatus == nil {
		out.DKIMByStatus = []TLSStatusCount{}
	}

	if err := db.Get(out, `
		SELECT
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS duplicates,
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS duplicate_range,
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS parse_errors,
			COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0) AS rejected
		  FROM ingest_events
		 WHERE kind = ? AND (? = 0 OR at >= ?)`,
		IngestStatusDuplicate, IngestStatusDuplicateRange, IngestStatusParseError, IngestStatusRejected,
		IngestKindTLSRPT, f.From, f.From); err != nil {
		return nil, err
	}
	return out, nil
}
