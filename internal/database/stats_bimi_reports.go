package database

import (
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// Statistics over the <bimi> element of aggregate reports: B11 to B20.
//
// Two things constrain every query here. First, the <bimi> element is a
// sibling of <record>, not a child, so nothing in it can be attributed to a
// source IP, a disposition or an individual message — the counts are the
// evaluator's own aggregates for the whole period. Second, adoption is close
// to zero, so every one of these numbers has to be read next to B18: an empty
// result means "nobody told us", never "nothing is wrong".

// bimiWhere builds the WHERE clause for queries over bimi_assertions joined to
// reports.
//
// The envelope-from and source-IP filters are deliberately dropped: BIMI data
// hangs off the report, not off a record row, so there is no envelope sender
// or source address to filter it by. Silently applying those filters to the
// report as a whole would answer a different question from the one the page
// asked, which is worse than not filtering at all.
func bimiWhere(f StatsFilter) (string, []any) {
	var clauses []string
	var args []any
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

// BIMIEligibility is B11: the volume that met the authentication
// preconditions, which is the denominator every other BIMI rate divides by.
type BIMIEligibility struct {
	// Eligible is messages that passed DMARC under a policy that qualifies
	// for BIMI at all (core spec §7.1).
	Eligible int64 `json:"eligible"`
	// Total is every message in scope, eligible or not.
	Total int64 `json:"total"`
	// Passed is messages that passed DMARC regardless of policy, so the gap
	// between Passed and Eligible is what the policy alone is costing.
	Passed  int64                  `json:"passed"`
	Share   float64                `json:"share"`
	Domains []BIMIEligibilityByDom `json:"domains,omitempty"`
}

// BIMIEligibilityByDom is B11 for one policy domain.
type BIMIEligibilityByDom struct {
	Domain   string  `db:"domain" json:"domain"`
	Eligible int64   `db:"eligible" json:"eligible"`
	Passed   int64   `db:"passed" json:"passed"`
	Total    int64   `db:"total" json:"total"`
	Share    float64 `db:"-" json:"share"`
}

// bimiEligibleSQL is the §7.1 precondition as SQL, evaluated per report so
// each message is judged against the policy the reporter that counted it
// actually saw. pct is read through pct_present, never defaulted: RFC 9990
// removes the tag altogether.
const bimiEligibleSQL = `
	(rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass')
	AND r.policy IN ('quarantine','reject')
	AND (r.policy = 'reject' OR r.pct_present = 0 OR r.pct = 100)
	AND NOT (r.sp_present = 1 AND r.subdomain_policy = 'none')`

// GetBIMIEligibleVolume is B11.
func GetBIMIEligibleVolume(db *sqlx.DB, f StatsFilter) (*BIMIEligibility, error) {
	where, args := f.where()
	out := &BIMIEligibility{}

	var rows []BIMIEligibilityByDom
	if err := db.Select(&rows, `
		SELECT r.domain,
		       COALESCE(SUM(CASE WHEN `+bimiEligibleSQL+` THEN rr.count ELSE 0 END), 0) AS eligible,
		       COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END), 0) AS passed,
		       COALESCE(SUM(rr.count), 0) AS total
		  FROM reports r
		  JOIN record_rows rr ON rr.report_id = r.id`+where+`
		 GROUP BY r.domain
		 ORDER BY eligible DESC, r.domain`, args...); err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].Total > 0 {
			rows[i].Share = float64(rows[i].Eligible) / float64(rows[i].Total) * 100
		}
		out.Eligible += rows[i].Eligible
		out.Passed += rows[i].Passed
		out.Total += rows[i].Total
	}
	if out.Total > 0 {
		out.Share = float64(out.Eligible) / float64(out.Total) * 100
	}
	out.Domains = rows
	return out, nil
}

// BIMIErrorStat is one row of B12: an error tuple as one evaluator reported it.
type BIMIErrorStat struct {
	OrgName     string `db:"org_name" json:"org_name"`
	Domain      string `db:"aligned_domain" json:"domain"`
	Selector    string `db:"selector" json:"selector"`
	Element     string `db:"element" json:"element"`
	Class       string `db:"class" json:"class"`
	Type        string `db:"type" json:"type"`
	Description string `db:"description" json:"description,omitempty"`
	Count       int64  `db:"count" json:"count"`
	Reports     int64  `db:"reports" json:"reports"`
	FirstSeen   int64  `db:"first_seen" json:"first_seen"`
	LastSeen    int64  `db:"last_seen" json:"last_seen"`
}

// GetBIMIErrors is B12: reported error volume by element, class and type, with
// the evaluator, domain and selector each was reported for.
func GetBIMIErrors(db *sqlx.DB, f StatsFilter) ([]BIMIErrorStat, error) {
	where, args := bimiWhere(f)
	out := []BIMIErrorStat{}
	err := db.Select(&out, `
		SELECT r.org_name, a.aligned_domain, a.selector,
		       e.element, e.class, e.type,
		       MAX(e.description) AS description,
		       SUM(e.count) AS count,
		       COUNT(DISTINCT r.id) AS reports,
		       MIN(r.date_range_begin) AS first_seen,
		       MAX(r.date_range_begin) AS last_seen
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY r.org_name, a.aligned_domain, a.selector, e.element, e.class, e.type
		 ORDER BY count DESC, r.org_name`, args...)
	return out, err
}

// BIMIPermanentShare is B13: how much of the reported error volume an
// evaluator classed permanent.
//
// The distinction is operational, not cosmetic. §3.4 lets an evaluator that
// reports a permanent error stop evaluating BIMI for the domain entirely until
// something changes, where a temporary one only skips the message in hand.
type BIMIPermanentShare struct {
	Total     int64                  `json:"total"`
	Permanent int64                  `json:"permanent"`
	Temporary int64                  `json:"temporary"`
	Unknown   int64                  `json:"unknown"`
	Share     float64                `json:"share"`
	ByOrg     []BIMIPermanentByOrg   `json:"by_org,omitempty"`
	ByElement []BIMIPermanentElement `json:"by_element,omitempty"`
}

// BIMIPermanentByOrg is B13 for one evaluator.
type BIMIPermanentByOrg struct {
	OrgName   string  `db:"org_name" json:"org_name"`
	Total     int64   `db:"total" json:"total"`
	Permanent int64   `db:"permanent" json:"permanent"`
	Share     float64 `db:"-" json:"share"`
}

// BIMIPermanentElement is B13 split by which element failed.
type BIMIPermanentElement struct {
	Element   string  `db:"element" json:"element"`
	Total     int64   `db:"total" json:"total"`
	Permanent int64   `db:"permanent" json:"permanent"`
	Share     float64 `db:"-" json:"share"`
}

// GetBIMIPermanentShare is B13.
func GetBIMIPermanentShare(db *sqlx.DB, f StatsFilter) (*BIMIPermanentShare, error) {
	where, args := bimiWhere(f)
	out := &BIMIPermanentShare{}

	var totals struct {
		Total     int64 `db:"total"`
		Permanent int64 `db:"permanent"`
		Temporary int64 `db:"temporary"`
	}
	if err := db.Get(&totals, `
		SELECT COALESCE(SUM(e.count), 0) AS total,
		       COALESCE(SUM(CASE WHEN e.class = 'perm' THEN e.count ELSE 0 END), 0) AS permanent,
		       COALESCE(SUM(CASE WHEN e.class = 'temp' THEN e.count ELSE 0 END), 0) AS temporary
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where, args...); err != nil {
		return nil, err
	}
	out.Total, out.Permanent, out.Temporary = totals.Total, totals.Permanent, totals.Temporary
	// A class outside the registry is neither, and is kept visible rather
	// than folded into one of them.
	out.Unknown = out.Total - out.Permanent - out.Temporary
	if out.Total > 0 {
		out.Share = float64(out.Permanent) / float64(out.Total) * 100
	}

	if err := db.Select(&out.ByOrg, `
		SELECT r.org_name,
		       COALESCE(SUM(e.count), 0) AS total,
		       COALESCE(SUM(CASE WHEN e.class = 'perm' THEN e.count ELSE 0 END), 0) AS permanent
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY r.org_name ORDER BY total DESC`, args...); err != nil {
		return nil, err
	}
	for i := range out.ByOrg {
		if out.ByOrg[i].Total > 0 {
			out.ByOrg[i].Share = float64(out.ByOrg[i].Permanent) / float64(out.ByOrg[i].Total) * 100
		}
	}

	if err := db.Select(&out.ByElement, `
		SELECT e.element,
		       COALESCE(SUM(e.count), 0) AS total,
		       COALESCE(SUM(CASE WHEN e.class = 'perm' THEN e.count ELSE 0 END), 0) AS permanent
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY e.element ORDER BY total DESC`, args...); err != nil {
		return nil, err
	}
	for i := range out.ByElement {
		if out.ByElement[i].Total > 0 {
			out.ByElement[i].Share = float64(out.ByElement[i].Permanent) / float64(out.ByElement[i].Total) * 100
		}
	}
	return out, nil
}

// BIMIReportedConfig is one row of B14: the configuration one evaluator echoed
// back for one domain and selector.
type BIMIReportedConfig struct {
	OrgName   string `db:"org_name" json:"org_name"`
	Domain    string `db:"aligned_domain" json:"domain"`
	Selector  string `db:"selector" json:"selector"`
	LValue    string `db:"l_value" json:"l"`
	AValue    string `db:"a_value" json:"a"`
	Reports   int64  `db:"reports" json:"reports"`
	FirstSeen int64  `db:"first_seen" json:"first_seen"`
	LastSeen  int64  `db:"last_seen" json:"last_seen"`
	// Matches is filled by the caller against the current DNS snapshot; it is
	// not a fact the report carries.
	Matches bool `db:"-" json:"matches"`
}

// GetBIMIReportedConfigs is B14: what each evaluator says it saw.
//
// Two different disagreements hide in this table and they have opposite
// causes. Evaluators disagreeing with *each other* inside one window means the
// DNS answered differently to different resolvers. Evaluators agreeing with
// each other but disagreeing with what is published now means the record
// changed and the reports predate it.
func GetBIMIReportedConfigs(db *sqlx.DB, f StatsFilter) ([]BIMIReportedConfig, error) {
	where, args := bimiWhere(f)
	out := []BIMIReportedConfig{}
	err := db.Select(&out, `
		SELECT r.org_name, a.aligned_domain, a.selector, a.l_value, a.a_value,
		       COUNT(DISTINCT r.id) AS reports,
		       MIN(r.date_range_begin) AS first_seen,
		       MAX(r.date_range_begin) AS last_seen
		  FROM bimi_assertions a
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY r.org_name, a.aligned_domain, a.selector, a.l_value, a.a_value
		 ORDER BY a.aligned_domain, a.selector, last_seen DESC`, args...)
	return out, err
}

// BIMIEvidenceFreshness is one row of B15: how stale one evaluator's cached
// evaluation of an evidence document is.
type BIMIEvidenceFreshness struct {
	OrgName   string `db:"org_name" json:"org_name"`
	Domain    string `db:"aligned_domain" json:"domain"`
	Selector  string `db:"selector" json:"selector"`
	Issuer    string `db:"evidence_issuer" json:"issuer"`
	Type      string `db:"evidence_type" json:"type"`
	Evaluated int64  `db:"evidence_date" json:"evaluated"`
	// WindowEnd is the end of the report's own window, which is what the
	// evaluation age is measured against: measuring against "now" would make
	// every old report look stale regardless of how current it was.
	WindowEnd int64 `db:"window_end" json:"window_end"`
	AgeDays   int   `db:"-" json:"age_days"`
	Reports   int64 `db:"reports" json:"reports"`
}

// GetBIMIEvidenceFreshness is B15.
//
// A stale evaluation explains a class of failure that is otherwise baffling:
// the operator rotates a certificate, every local check goes green, and one
// receiver keeps refusing the logo because it is still holding a judgement it
// made a fortnight ago.
func GetBIMIEvidenceFreshness(db *sqlx.DB, f StatsFilter) ([]BIMIEvidenceFreshness, error) {
	where, args := bimiWhere(f)
	if where == "" {
		where = " WHERE a.evidence_date > 0"
	} else {
		where += " AND a.evidence_date > 0"
	}
	out := []BIMIEvidenceFreshness{}
	if err := db.Select(&out, `
		SELECT r.org_name, a.aligned_domain, a.selector,
		       MAX(a.evidence_issuer) AS evidence_issuer,
		       MAX(a.evidence_type) AS evidence_type,
		       MAX(a.evidence_date) AS evidence_date,
		       MAX(r.date_range_end) AS window_end,
		       COUNT(DISTINCT r.id) AS reports
		  FROM bimi_assertions a
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY r.org_name, a.aligned_domain, a.selector
		 ORDER BY evidence_date`, args...); err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].WindowEnd > out[i].Evaluated {
			out[i].AgeDays = int((out[i].WindowEnd - out[i].Evaluated) / 86400)
		}
	}
	return out, nil
}

// GetBIMIPolicyRejections is B16: evidence errors of type "policy".
//
// §3.4.2 defines that type as the evaluator having "additional information
// that may impact the evaluation" — it does not recognise the issuing
// authority, or considers the evidence type insufficient. The document
// validated; the receiver declined it anyway. No change the operator makes to
// their own configuration will move this number, which is precisely why it is
// counted apart from the defects that will.
func GetBIMIPolicyRejections(db *sqlx.DB, f StatsFilter) ([]BIMIErrorStat, error) {
	where, args := bimiWhere(f)
	if where == "" {
		where = " WHERE e.element = 'evidence' AND e.type = 'policy'"
	} else {
		where += " AND e.element = 'evidence' AND e.type = 'policy'"
	}
	out := []BIMIErrorStat{}
	err := db.Select(&out, `
		SELECT r.org_name, a.aligned_domain, a.selector,
		       e.element, e.class, e.type,
		       MAX(e.description) AS description,
		       SUM(e.count) AS count,
		       COUNT(DISTINCT r.id) AS reports,
		       MIN(r.date_range_begin) AS first_seen,
		       MAX(r.date_range_begin) AS last_seen
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where+`
		 GROUP BY r.org_name, a.aligned_domain, a.selector, e.element, e.class, e.type
		 ORDER BY count DESC`, args...)
	return out, err
}

// BIMIDivergence is one row of B17: one configuration, judged differently by
// different evaluators in the same window.
type BIMIDivergence struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	LValue   string `json:"l"`
	AValue   string `json:"a"`
	// Verdicts is each evaluator's error set for that configuration, ordered
	// by evaluator name. An evaluator with no errors is listed with an empty
	// set, which is the report schema's only way of saying "this worked".
	Verdicts []BIMIEvaluatorVerdict `json:"verdicts"`
	// Disagree is true when the verdicts are not all the same.
	Disagree bool `json:"disagree"`
	// Clean and Failing count the evaluators on each side.
	Clean   int `json:"clean"`
	Failing int `json:"failing"`
}

// BIMIEvaluatorVerdict is one evaluator's judgement of one configuration, as
// reported in an aggregate report.
//
// Not to be confused with BIMIVerdict, which is what a receiver stamped on a
// real message (B21). The two say different things: this one is an evaluator's
// aggregate account of a configuration, that one is a single message's fate.
type BIMIEvaluatorVerdict struct {
	OrgName string   `json:"org_name"`
	Errors  []string `json:"errors"` // "element:class:type", sorted
	Count   int64    `json:"count"`
}

// GetBIMIDivergence is B17.
//
// The distinction it draws is the useful one: where every evaluator reports
// the same errors, the configuration is broken and the operator can fix it.
// Where one refuses what the others accept, the difference is that receiver's
// strictness, and no amount of fixing will change its mind.
func GetBIMIDivergence(db *sqlx.DB, f StatsFilter) ([]BIMIDivergence, error) {
	where, args := bimiWhere(f)
	type row struct {
		Domain   string `db:"aligned_domain"`
		Selector string `db:"selector"`
		LValue   string `db:"l_value"`
		AValue   string `db:"a_value"`
		OrgName  string `db:"org_name"`
		Element  string `db:"element"`
		Class    string `db:"class"`
		Type     string `db:"type"`
		Count    int64  `db:"count"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT a.aligned_domain, a.selector, a.l_value, a.a_value, r.org_name,
		       COALESCE(e.element, '') AS element,
		       COALESCE(e.class, '') AS class,
		       COALESCE(e.type, '') AS type,
		       COALESCE(SUM(e.count), 0) AS count
		  FROM bimi_assertions a
		  JOIN reports r ON r.id = a.report_id
		  LEFT JOIN bimi_errors e ON e.assertion_id = a.id`+where+`
		 GROUP BY a.aligned_domain, a.selector, a.l_value, a.a_value, r.org_name,
		          e.element, e.class, e.type
		 ORDER BY a.aligned_domain, a.selector, r.org_name`, args...); err != nil {
		return nil, err
	}

	type key struct{ domain, selector, l, a string }
	group := map[key]map[string]*BIMIEvaluatorVerdict{}
	order := []key{}
	for _, r := range rows {
		k := key{r.Domain, r.Selector, r.LValue, r.AValue}
		byOrg, ok := group[k]
		if !ok {
			byOrg = map[string]*BIMIEvaluatorVerdict{}
			group[k] = byOrg
			order = append(order, k)
		}
		v, ok := byOrg[r.OrgName]
		if !ok {
			v = &BIMIEvaluatorVerdict{OrgName: r.OrgName, Errors: []string{}}
			byOrg[r.OrgName] = v
		}
		if r.Element != "" {
			v.Errors = append(v.Errors, r.Element+":"+r.Class+":"+r.Type)
			v.Count += r.Count
		}
	}

	out := []BIMIDivergence{}
	for _, k := range order {
		d := BIMIDivergence{Domain: k.domain, Selector: k.selector, LValue: k.l, AValue: k.a}
		for _, v := range group[k] {
			sort.Strings(v.Errors)
			if len(v.Errors) == 0 {
				d.Clean++
			} else {
				d.Failing++
			}
			d.Verdicts = append(d.Verdicts, *v)
		}
		sort.Slice(d.Verdicts, func(i, j int) bool { return d.Verdicts[i].OrgName < d.Verdicts[j].OrgName })
		// Only one evaluator means nothing to diverge from.
		if len(d.Verdicts) > 1 {
			first := strings.Join(d.Verdicts[0].Errors, "|")
			for _, v := range d.Verdicts[1:] {
				if strings.Join(v.Errors, "|") != first {
					d.Disagree = true
					break
				}
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Disagree != out[j].Disagree {
			return out[i].Disagree // disagreements first: they are the finding
		}
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Selector < out[j].Selector
	})
	return out, nil
}

// BIMICoverage is B18: how much of the volume came from reporters that emit
// BIMI data at all.
//
// This is the number that makes the rest of the B series readable. With
// coverage near zero — which is where adoption is today — an empty B12 says
// nothing whatever about whether logos are being shown.
type BIMICoverage struct {
	CoveredMessages int64   `json:"covered_messages"`
	TotalMessages   int64   `json:"total_messages"`
	Share           float64 `json:"share"`
	ReportersWith   int64   `json:"reporters_with"`
	Reporters       int64   `json:"reporters"`
	ReportsWith     int64   `json:"reports_with"`
	Reports         int64   `json:"reports"`
	// Orgs names the reporters that emit BIMI data, so "who tells us" is
	// answerable rather than just "how many".
	Orgs []string `json:"orgs,omitempty"`
}

// GetBIMICoverage is B18.
func GetBIMICoverage(db *sqlx.DB, f StatsFilter) (*BIMICoverage, error) {
	where, args := f.where()
	out := &BIMICoverage{}
	var agg struct {
		Covered       int64 `db:"covered"`
		Total         int64 `db:"total"`
		ReportersWith int64 `db:"reporters_with"`
		Reporters     int64 `db:"reporters"`
		ReportsWith   int64 `db:"reports_with"`
		Reports       int64 `db:"reports"`
	}
	if err := db.Get(&agg, `
		SELECT COALESCE(SUM(CASE WHEN bimi_present = 1 THEN messages ELSE 0 END), 0) AS covered,
		       COALESCE(SUM(messages), 0) AS total,
		       COUNT(DISTINCT CASE WHEN bimi_present = 1 THEN org_name END) AS reporters_with,
		       COUNT(DISTINCT org_name) AS reporters,
		       COALESCE(SUM(bimi_present), 0) AS reports_with,
		       COUNT(*) AS reports
		  FROM (
			SELECT r.id, r.org_name, r.bimi_present, COALESCE(SUM(rr.count), 0) AS messages
			  FROM reports r
			  JOIN record_rows rr ON rr.report_id = r.id`+where+`
			 GROUP BY r.id
		  )`, args...); err != nil {
		return nil, err
	}
	out.CoveredMessages, out.TotalMessages = agg.Covered, agg.Total
	out.ReportersWith, out.Reporters = agg.ReportersWith, agg.Reporters
	out.ReportsWith, out.Reports = agg.ReportsWith, agg.Reports
	if out.TotalMessages > 0 {
		out.Share = float64(out.CoveredMessages) / float64(out.TotalMessages) * 100
	}

	if err := db.Select(&out.Orgs, `
		SELECT DISTINCT r.org_name FROM reports r
		  JOIN record_rows rr ON rr.report_id = r.id`+whereAnd(where, "r.bimi_present = 1")+`
		 ORDER BY r.org_name`, args...); err != nil {
		return nil, err
	}
	return out, nil
}

// BIMIHygieneStat is B19: everything that makes the BIMI numbers less
// trustworthy.
type BIMIHygieneStat struct {
	Reports         int64 `db:"reports" json:"reports"`
	ReportsWithBIMI int64 `db:"reports_with_bimi" json:"reports_with_bimi"`
	DupTuples       int64 `db:"dup_tuples" json:"dup_tuples"`
	BadCounts       int64 `db:"bad_counts" json:"bad_counts"`
	UnknownTypes    int64 `db:"unknown_types" json:"unknown_types"`
	MissingAttrs    int64 `db:"missing_attrs" json:"missing_attrs"`
	MalformedFields int64 `db:"malformed_fields" json:"malformed_fields"`
	// Assertions and Errors are the rows those reports produced.
	Assertions int64 `db:"assertions" json:"assertions"`
	Errors     int64 `db:"errors" json:"errors"`
	// UnparsedDates counts evidence dates that were supplied but could not be
	// read as the RFC 5322 date §3.3 specifies.
	UnparsedDates int64 `db:"unparsed_dates" json:"unparsed_dates"`
	// ReportsAffected is how many reports contributed at least one of the
	// counts above.
	ReportsAffected int64 `db:"reports_affected" json:"reports_affected"`
}

// GetBIMIHygiene is B19.
func GetBIMIHygiene(db *sqlx.DB, f StatsFilter) (*BIMIHygieneStat, error) {
	where, args := bimiWhere(f)
	out := &BIMIHygieneStat{}
	if err := db.Get(out, `
		SELECT COUNT(*) AS reports,
		       COALESCE(SUM(r.bimi_present), 0) AS reports_with_bimi,
		       COALESCE(SUM(r.bimi_dup_tuples), 0) AS dup_tuples,
		       COALESCE(SUM(r.bimi_bad_counts), 0) AS bad_counts,
		       COALESCE(SUM(r.bimi_unknown_types), 0) AS unknown_types,
		       COALESCE(SUM(r.bimi_missing_attrs), 0) AS missing_attrs,
		       COALESCE(SUM(r.malformed_fields), 0) AS malformed_fields,
		       COALESCE(SUM(CASE WHEN r.bimi_dup_tuples + r.bimi_bad_counts + r.bimi_unknown_types
		                            + r.bimi_missing_attrs + r.malformed_fields > 0
		                         THEN 1 ELSE 0 END), 0) AS reports_affected,
		       0 AS assertions, 0 AS errors, 0 AS unparsed_dates
		  FROM reports r`+where, args...); err != nil {
		return nil, err
	}

	var counts struct {
		Assertions    int64 `db:"assertions"`
		Errors        int64 `db:"errors"`
		UnparsedDates int64 `db:"unparsed_dates"`
	}
	if err := db.Get(&counts, `
		SELECT COUNT(*) AS assertions,
		       COALESCE(SUM((SELECT COUNT(*) FROM bimi_errors e WHERE e.assertion_id = a.id)), 0) AS errors,
		       COALESCE(SUM(CASE WHEN a.evidence_date_raw != '' AND a.evidence_date = 0 THEN 1 ELSE 0 END), 0) AS unparsed_dates
		  FROM bimi_assertions a
		  JOIN reports r ON r.id = a.report_id`+where, args...); err != nil {
		return nil, err
	}
	out.Assertions, out.Errors, out.UnparsedDates = counts.Assertions, counts.Errors, counts.UnparsedDates
	return out, nil
}

// BIMIImpressions is B20: eligible volume set against observed failure.
//
// Every figure here is an estimate and the UI must say so. The error counts
// come from a different part of the report from the message counts and cannot
// be joined to them: §3.4 aggregates errors for the whole period, while the
// volume comes from the record rows. One message can also produce several
// errors — core spec §3.2's selector-plus-default double failure is the
// obvious case — so Lost can exceed Eligible and the rate can exceed 100%.
// That is not clamped: a rate over 100% is itself the finding, and hiding it
// would turn a visible absurdity into an invisible one.
type BIMIImpressions struct {
	Eligible int64   `json:"eligible"`
	Errors   int64   `json:"errors"`
	Shown    int64   `json:"shown"`
	Rate     float64 `json:"rate"`
	// Over100 is true when the reported errors outnumber the eligible
	// messages, which means the counts cannot be read as one-per-message.
	Over100 bool `json:"over_100"`
	// Coverage is B18 alongside, because an impression estimate built on 2%
	// coverage is a different claim from one built on 90%.
	Coverage float64 `json:"coverage"`
}

// GetBIMIImpressions is B20.
func GetBIMIImpressions(db *sqlx.DB, f StatsFilter) (*BIMIImpressions, error) {
	eligible, err := GetBIMIEligibleVolume(db, f)
	if err != nil {
		return nil, err
	}
	coverage, err := GetBIMICoverage(db, f)
	if err != nil {
		return nil, err
	}
	where, args := bimiWhere(f)
	var errors int64
	if err := db.Get(&errors, `
		SELECT COALESCE(SUM(e.count), 0)
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id`+where, args...); err != nil {
		return nil, err
	}

	out := &BIMIImpressions{
		Eligible: eligible.Eligible,
		Errors:   errors,
		Shown:    eligible.Eligible - errors,
		Coverage: coverage.Share,
	}
	if out.Shown < 0 {
		out.Shown = 0
	}
	if eligible.Eligible > 0 {
		out.Rate = float64(errors) / float64(eligible.Eligible) * 100
		out.Over100 = errors > eligible.Eligible
	}
	return out, nil
}

// BIMIReportingSummary is everything the B11–B20 series needs for one page.
type BIMIReportingSummary struct {
	Eligibility *BIMIEligibility        `json:"eligibility"`
	Coverage    *BIMICoverage           `json:"coverage"`
	Errors      []BIMIErrorStat         `json:"errors"`
	Permanent   *BIMIPermanentShare     `json:"permanent"`
	Configs     []BIMIReportedConfig    `json:"configs"`
	Freshness   []BIMIEvidenceFreshness `json:"freshness"`
	Rejections  []BIMIErrorStat         `json:"rejections"`
	Divergence  []BIMIDivergence        `json:"divergence"`
	Hygiene     *BIMIHygieneStat        `json:"hygiene"`
	Impressions *BIMIImpressions        `json:"impressions"`
	// GeneratedAt is when the summary was computed, for the API.
	GeneratedAt int64 `json:"generated_at"`
}

// GetBIMIReportingSummary computes B11 to B20 in one pass.
func GetBIMIReportingSummary(db *sqlx.DB, f StatsFilter) (*BIMIReportingSummary, error) {
	out := &BIMIReportingSummary{GeneratedAt: time.Now().Unix()}
	var err error
	if out.Eligibility, err = GetBIMIEligibleVolume(db, f); err != nil {
		return nil, err
	}
	if out.Coverage, err = GetBIMICoverage(db, f); err != nil {
		return nil, err
	}
	if out.Errors, err = GetBIMIErrors(db, f); err != nil {
		return nil, err
	}
	if out.Permanent, err = GetBIMIPermanentShare(db, f); err != nil {
		return nil, err
	}
	if out.Configs, err = GetBIMIReportedConfigs(db, f); err != nil {
		return nil, err
	}
	if out.Freshness, err = GetBIMIEvidenceFreshness(db, f); err != nil {
		return nil, err
	}
	if out.Rejections, err = GetBIMIPolicyRejections(db, f); err != nil {
		return nil, err
	}
	if out.Divergence, err = GetBIMIDivergence(db, f); err != nil {
		return nil, err
	}
	if out.Hygiene, err = GetBIMIHygiene(db, f); err != nil {
		return nil, err
	}
	if out.Impressions, err = GetBIMIImpressions(db, f); err != nil {
		return nil, err
	}
	return out, nil
}

// BIMINewErrorTuple is an error tuple reported for a domain for the first
// time, which is what X28 fires on.
type BIMINewErrorTuple struct {
	Domain      string `db:"domain" json:"domain"`
	Element     string `db:"element" json:"element"`
	Class       string `db:"class" json:"class"`
	Type        string `db:"type" json:"type"`
	Description string `db:"description" json:"description,omitempty"`
	Count       int64  `db:"count" json:"count"`
	Orgs        string `db:"orgs" json:"orgs"`
	FirstSeen   int64  `db:"first_seen" json:"first_seen"`
}

// ListNewBIMIErrorTuples returns error tuples whose first appearance anywhere
// in the stored reports falls at or after since.
//
// "First seen anywhere" is deliberate: a tuple that was reported months ago,
// stopped, and came back is not news, and an alert that fired every time a
// long-standing error was re-reported would be noise from the first week.
func ListNewBIMIErrorTuples(db *sqlx.DB, since int64) ([]BIMINewErrorTuple, error) {
	out := []BIMINewErrorTuple{}
	err := db.Select(&out, `
		SELECT a.aligned_domain AS domain, e.element, e.class, e.type,
		       MAX(e.description) AS description,
		       SUM(e.count) AS count,
		       GROUP_CONCAT(DISTINCT r.org_name) AS orgs,
		       MIN(r.date_range_begin) AS first_seen
		  FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		  JOIN reports r ON r.id = a.report_id
		 GROUP BY a.aligned_domain, e.element, e.class, e.type
		HAVING MIN(r.date_range_begin) >= ?
		 ORDER BY count DESC`, since)
	return out, err
}
