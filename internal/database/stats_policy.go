package database

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// PolicyTuple is the full published-policy record as reporters saw it (P1).
type PolicyTuple struct {
	P               string `db:"policy" json:"p"`
	SP              string `db:"subdomain_policy" json:"sp"`
	SPPresent       int    `db:"sp_present" json:"sp_present"`
	NP              string `db:"np" json:"np"`
	ADKIM           string `db:"adkim" json:"adkim"`
	ASPF            string `db:"aspf" json:"aspf"`
	Pct             int    `db:"pct" json:"pct"`
	PctPresent      int    `db:"pct_present" json:"pct_present"`
	FO              string `db:"failure_options" json:"fo"`
	FOPresent       int    `db:"fo_present" json:"fo_present"`
	DiscoveryMethod string `db:"discovery_method" json:"discovery_method"`
	Testing         string `db:"testing" json:"testing"`
}

// Key returns a stable identity string for grouping and change detection.
func (t PolicyTuple) Key() string {
	return fmt.Sprintf("p=%s|sp=%s/%d|np=%s|adkim=%s|aspf=%s|pct=%d/%d|fo=%s/%d|dm=%s|t=%s",
		t.P, t.SP, t.SPPresent, t.NP, t.ADKIM, t.ASPF, t.Pct, t.PctPresent, t.FO, t.FOPresent, t.DiscoveryMethod, t.Testing)
}

// Tags renders the tuple as "k=v" chips (absent optional tags are omitted).
func (t PolicyTuple) Tags() []string {
	tags := []string{"p=" + orNone(t.P)}
	if t.SPPresent == 1 {
		tags = append(tags, "sp="+orNone(t.SP))
	}
	if t.NP != "" {
		tags = append(tags, "np="+t.NP)
	}
	tags = append(tags, "adkim="+orDefault(t.ADKIM, "r"), "aspf="+orDefault(t.ASPF, "r"))
	if t.PctPresent == 1 {
		tags = append(tags, fmt.Sprintf("pct=%d", t.Pct))
	}
	if t.FOPresent == 1 {
		tags = append(tags, "fo="+t.FO)
	}
	if t.DiscoveryMethod != "" {
		tags = append(tags, "via "+t.DiscoveryMethod)
	}
	if t.Testing != "" {
		if t.Testing == "y" {
			tags = append(tags, "testing")
		} else {
			tags = append(tags, "enforced")
		}
	}
	return tags
}

// EffectiveSP returns sp when published, else p.
func (t PolicyTuple) EffectiveSP() string {
	if t.SPPresent == 1 && t.SP != "" {
		return t.SP
	}
	return t.P
}

// Diff lists the fields that differ between t and o as "field: a → b".
func (t PolicyTuple) Diff(o PolicyTuple) []FieldDiff {
	var d []FieldDiff
	add := func(field, a, b string) {
		if a != b {
			d = append(d, FieldDiff{Field: field, From: a, To: b})
		}
	}
	add("p", t.P, o.P)
	add("sp", presentOr(t.SP, t.SPPresent), presentOr(o.SP, o.SPPresent))
	add("np", t.NP, o.NP)
	add("adkim", orDefault(t.ADKIM, "r"), orDefault(o.ADKIM, "r"))
	add("aspf", orDefault(t.ASPF, "r"), orDefault(o.ASPF, "r"))
	add("pct", presentOr(fmt.Sprint(t.Pct), t.PctPresent), presentOr(fmt.Sprint(o.Pct), o.PctPresent))
	add("fo", presentOr(t.FO, t.FOPresent), presentOr(o.FO, o.FOPresent))
	add("discovery_method", t.DiscoveryMethod, o.DiscoveryMethod)
	add("testing", t.Testing, o.Testing)
	return d
}

// FieldDiff is one changed tag in a policy change-log entry.
type FieldDiff struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func presentOr(v string, present int) string {
	if present != 1 {
		return "(absent)"
	}
	return v
}

const policyTupleCols = `r.policy, r.subdomain_policy, r.sp_present, r.np, r.adkim, r.aspf, r.pct, r.pct_present,
	r.failure_options, r.fo_present, r.discovery_method, r.testing`

// EffectiveTuple is the enforcement-relevant subset of a policy record with
// RFC defaults applied: p, sp (falls back to p), adkim/aspf (default r) and
// pct (default 100). Reporter-specific extras (np, fo, discovery_method,
// testing) are deliberately excluded so that two reporters describing the
// same DNS record in different detail do not count as a disagreement.
type EffectiveTuple struct {
	P     string `db:"eff_p" json:"p"`
	SP    string `db:"eff_sp" json:"sp"`
	ADKIM string `db:"eff_adkim" json:"adkim"`
	ASPF  string `db:"eff_aspf" json:"aspf"`
	Pct   int    `db:"eff_pct" json:"pct"`
}

// Key returns a stable identity for grouping and change detection.
func (e EffectiveTuple) Key() string {
	return fmt.Sprintf("p=%s|sp=%s|adkim=%s|aspf=%s|pct=%d", e.P, e.SP, e.ADKIM, e.ASPF, e.Pct)
}

// Tags renders the effective tuple as chips.
func (e EffectiveTuple) Tags() []string {
	return []string{"p=" + orNone(e.P), "sp=" + orNone(e.SP), "adkim=" + e.ADKIM, "aspf=" + e.ASPF, fmt.Sprintf("pct=%d", e.Pct)}
}

// Diff lists the fields that differ between e and o.
func (e EffectiveTuple) Diff(o EffectiveTuple) []FieldDiff {
	var d []FieldDiff
	add := func(field, a, b string) {
		if a != b {
			d = append(d, FieldDiff{Field: field, From: a, To: b})
		}
	}
	add("p", orNone(e.P), orNone(o.P))
	add("sp", orNone(e.SP), orNone(o.SP))
	add("adkim", e.ADKIM, o.ADKIM)
	add("aspf", e.ASPF, o.ASPF)
	add("pct", fmt.Sprint(e.Pct), fmt.Sprint(o.Pct))
	return d
}

// Effective derives the effective tuple from a raw one.
func (t PolicyTuple) Effective() EffectiveTuple {
	return EffectiveTuple{P: t.P, SP: t.EffectiveSP(), ADKIM: orDefault(t.ADKIM, "r"), ASPF: orDefault(t.ASPF, "r"), Pct: effPct(t.Pct, t.PctPresent)}
}

func effPct(pct, present int) int {
	if present != 1 {
		return 100
	}
	return pct
}

// effectiveTupleCols are the SQL expressions matching PolicyTuple.Effective.
const effectiveTupleCols = `
	r.policy AS eff_p,
	CASE WHEN r.sp_present = 1 AND r.subdomain_policy != '' THEN r.subdomain_policy ELSE r.policy END AS eff_sp,
	CASE WHEN r.adkim = '' THEN 'r' ELSE r.adkim END AS eff_adkim,
	CASE WHEN r.aspf = '' THEN 'r' ELSE r.aspf END AS eff_aspf,
	CASE WHEN r.pct_present = 1 THEN r.pct ELSE 100 END AS eff_pct`

const effectiveTupleGroup = `eff_p, eff_sp, eff_adkim, eff_aspf, eff_pct`

// PolicyTupleSeen is one effective tuple with the reporters that saw it (P2).
type PolicyTupleSeen struct {
	EffectiveTuple
	Reporters    string   `db:"reporters" json:"-"` // comma-separated (from SQL)
	ReporterList []string `db:"-" json:"reporters"`
	Reports      int64    `db:"reports" json:"reports"`
	Messages     int64    `db:"messages" json:"messages"`
	Variants     int64    `db:"variants" json:"variants"` // distinct raw tuples folded into this effective one
	Key          string   `db:"-" json:"key"`
	Tags         []string `db:"-" json:"tags"`
}

func (s *PolicyTupleSeen) finish() {
	s.Key = s.EffectiveTuple.Key()
	s.Tags = s.EffectiveTuple.Tags()
	if s.Reporters != "" {
		s.ReporterList = strings.Split(s.Reporters, ",")
		sort.Strings(s.ReporterList)
	}
}

// GetPolicyConsistency is P2: every distinct effective tuple in the window with
// the reporters, report count and message volume behind it, largest first.
// One row means the reporters agree on the enforcement-relevant tags.
func GetPolicyConsistency(db *sqlx.DB, f StatsFilter) ([]PolicyTupleSeen, error) {
	var out []PolicyTupleSeen
	where, args := f.where()
	err := db.Select(&out, `
		SELECT `+effectiveTupleGroup+`,
			GROUP_CONCAT(DISTINCT org_name) AS reporters,
			COUNT(DISTINCT id) AS reports,
			SUM(messages) AS messages,
			COUNT(DISTINCT raw_key) AS variants
		FROM (
			SELECT `+effectiveTupleCols+`, r.org_name, r.id,
				r.policy || '|' || r.subdomain_policy || '|' || r.sp_present || '|' || r.np || '|' || r.adkim || '|' || r.aspf || '|' ||
					r.pct || '|' || r.pct_present || '|' || r.failure_options || '|' || r.fo_present || '|' || r.discovery_method || '|' || r.testing AS raw_key,
				COALESCE(SUM(rr.count), 0) AS messages
			FROM reports r
			JOIN record_rows rr ON rr.report_id = r.id`+where+`
			GROUP BY r.id
		)
		GROUP BY `+effectiveTupleGroup+`
		ORDER BY messages DESC, reports DESC`, args...)
	for i := range out {
		out[i].finish()
	}
	return out, err
}

// GetPolicyVariants returns every distinct raw tuple in the window (all tags as
// reported), largest first. Used for the P1 display of the dominant record.
func GetPolicyVariants(db *sqlx.DB, f StatsFilter) ([]PolicyTuple, error) {
	var out []PolicyTuple
	where, args := f.where()
	err := db.Select(&out, `
		SELECT `+policyTupleCols+`
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY `+policyTupleCols+`
		ORDER BY COALESCE(SUM(rr.count), 0) DESC, COUNT(DISTINCT r.id) DESC`, args...)
	return out, err
}

// ReporterPolicyView is one reporter's dominant tuple (P1 per-reporter view).
type ReporterPolicyView struct {
	PolicyTuple
	OrgName  string   `db:"org_name" json:"org_name"`
	Reports  int64    `db:"reports" json:"reports"`
	Messages int64    `db:"messages" json:"messages"`
	Key      string   `db:"-" json:"key"`
	Tags     []string `db:"-" json:"tags"`
	Agrees   bool     `db:"-" json:"agrees"` // effective tuple matches the dominant one
}

// ActivePolicy is P1: the dominant tuple plus the per-reporter view.
type ActivePolicy struct {
	Tuple      *PolicyTuple         `json:"tuple"` // dominant raw tuple (all tags as reported); nil when no data
	Effective  *EffectiveTuple      `json:"effective"`
	Tags       []string             `json:"tags"`
	Reporters  []ReporterPolicyView `json:"reporters"`
	Consistent bool                 `json:"consistent"` // every reporter's dominant effective tuple equals Effective
}

// GetActivePolicyTuple returns the raw tuple covering the most messages in the
// window and each reporter's dominant tuple. Consistency is judged on the
// effective tuples (see EffectiveTuple).
func GetActivePolicyTuple(db *sqlx.DB, f StatsFilter) (*ActivePolicy, error) {
	variants, err := GetPolicyVariants(db, f)
	if err != nil {
		return nil, err
	}
	out := &ActivePolicy{Consistent: true}
	if len(variants) == 0 {
		return out, nil
	}
	t := variants[0]
	eff := t.Effective()
	out.Tuple = &t
	out.Effective = &eff
	out.Tags = t.Tags()

	var rows []ReporterPolicyView
	where, args := f.where()
	if err := db.Select(&rows, `
		SELECT `+policyTupleCols+`, r.org_name,
			COUNT(DISTINCT r.id) AS reports, COALESCE(SUM(rr.count), 0) AS messages
		FROM reports r
		JOIN record_rows rr ON rr.report_id = r.id`+where+`
		GROUP BY r.org_name, `+policyTupleCols+`
		ORDER BY r.org_name, messages DESC, reports DESC`, args...); err != nil {
		return nil, err
	}
	// Keep the first (largest) tuple per reporter.
	for _, r := range rows {
		if len(out.Reporters) > 0 && out.Reporters[len(out.Reporters)-1].OrgName == r.OrgName {
			continue
		}
		r.Key = r.PolicyTuple.Key()
		r.Tags = r.PolicyTuple.Tags()
		r.Agrees = r.PolicyTuple.Effective().Key() == eff.Key()
		if !r.Agrees {
			out.Consistent = false
		}
		out.Reporters = append(out.Reporters, r)
	}
	return out, nil
}

// PolicyChange is one P3 change-log entry.
type PolicyChange struct {
	At             int64          `json:"at"` // start of the report window in which the new tuple was first seen
	From           EffectiveTuple `json:"from"`
	To             EffectiveTuple `json:"to"`
	Diff           []FieldDiff    `json:"diff"`
	Reporters      []string       `json:"reporters"`        // reporters that observed this change (same day, same diff)
	PassRateBefore float64        `json:"pass_rate_before"` // 7 days before; -1 when no data
	PassRateAfter  float64        `json:"pass_rate_after"`  // 7 days after; -1 when no data
	MessagesBefore int64          `json:"messages_before"`
	MessagesAfter  int64          `json:"messages_after"`
}

// GetPolicyChangeLog is P3 for one domain. Each reporter's reports are walked
// in date_range_begin order and a change is recorded whenever that reporter's
// effective tuple differs from its previous report; changes observed by
// several reporters on the same day with the same diff are merged into one
// entry. Comparing per reporter avoids the false changes that the differing
// level of detail between reporters would otherwise produce. Newest first;
// limit ≤ 0 means no limit.
func GetPolicyChangeLog(db *sqlx.DB, domain string, limit int) ([]PolicyChange, error) {
	type row struct {
		EffectiveTuple
		OrgName string `db:"org_name"`
		Begin   int64  `db:"date_range_begin"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT `+effectiveTupleCols+`, r.org_name, r.date_range_begin
		FROM reports r
		WHERE r.domain = ?
		ORDER BY r.org_name, r.date_range_begin ASC, r.id ASC`, domain); err != nil {
		return nil, err
	}
	type key struct {
		day  string
		diff string
	}
	merged := map[key]*PolicyChange{}
	var order []key
	var prev *row
	for i := range rows {
		cur := &rows[i]
		if prev != nil && prev.OrgName == cur.OrgName && prev.Key() != cur.Key() {
			day := time.Unix(cur.Begin, 0).UTC().Format("2006-01-02")
			diff := prev.EffectiveTuple.Diff(cur.EffectiveTuple)
			var sig strings.Builder
			for _, d := range diff {
				sig.WriteString(d.Field + ":" + d.From + ">" + d.To + ";")
			}
			k := key{day, sig.String()}
			ch, ok := merged[k]
			if !ok {
				dayStart, _ := time.Parse("2006-01-02", day)
				ch = &PolicyChange{At: dayStart.Unix(), From: prev.EffectiveTuple, To: cur.EffectiveTuple, Diff: diff, PassRateBefore: -1, PassRateAfter: -1}
				merged[k] = ch
				order = append(order, k)
			}
			ch.Reporters = append(ch.Reporters, cur.OrgName)
		}
		prev = cur
	}
	changes := make([]PolicyChange, 0, len(order))
	for _, k := range order {
		ch := *merged[k]
		sort.Strings(ch.Reporters)
		at := time.Unix(ch.At, 0).UTC()
		before, err := GetDashboardStats(db, StatsFilter{Domain: domain, From: at.AddDate(0, 0, -7).Unix(), To: at.Unix() - 1})
		if err != nil {
			return nil, err
		}
		if before.TotalMessages > 0 {
			ch.PassRateBefore = before.PassRate
			ch.MessagesBefore = before.TotalMessages
		}
		after, err := GetDashboardStats(db, StatsFilter{Domain: domain, From: at.Unix(), To: at.AddDate(0, 0, 7).Unix() - 1})
		if err != nil {
			return nil, err
		}
		if after.TotalMessages > 0 {
			ch.PassRateAfter = after.PassRate
			ch.MessagesAfter = after.TotalMessages
		}
		changes = append(changes, ch)
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].At > changes[j].At })
	if limit > 0 && len(changes) > limit {
		changes = changes[:limit]
	}
	return changes, nil
}

// SubdomainTrafficRow is P4: mail whose header_from is a subdomain of the
// policy domain.
type SubdomainTrafficRow struct {
	HeaderFrom    string  `db:"header_from" json:"header_from"`
	Domain        string  `db:"domain" json:"domain"`
	TotalMessages int64   `db:"total_messages" json:"messages"`
	Passed        int64   `db:"passed" json:"passed"`
	Failed        int64   `db:"failed" json:"failed"`
	PassRate      float64 `db:"pass_rate" json:"pass_rate"`
	SPPresent     int64   `db:"sp_present_msgs" json:"-"`
	EffectiveSP   string  `db:"effective_sp" json:"effective_sp"`
	GovernedBy    string  `db:"-" json:"governed_by"` // "sp" when sp was published, "p" otherwise
}

// GetSubdomainTraffic computes P4.
func GetSubdomainTraffic(db *sqlx.DB, f StatsFilter) ([]SubdomainTrafficRow, error) {
	var out []SubdomainTrafficRow
	and, args := f.andClauses()
	err := db.Select(&out, `
		SELECT
			rr.header_from, r.domain,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate,
			SUM(CASE WHEN r.sp_present = 1 THEN rr.count ELSE 0 END) AS sp_present_msgs,
			MAX(CASE WHEN r.sp_present = 1 AND r.subdomain_policy != '' THEN r.subdomain_policy ELSE r.policy END) AS effective_sp
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE rr.header_from != r.domain AND rr.header_from LIKE '%.' || r.domain`+and+`
		GROUP BY rr.header_from, r.domain
		ORDER BY total_messages DESC`, args...)
	for i := range out {
		if out[i].SPPresent*2 >= out[i].TotalMessages {
			out[i].GovernedBy = "sp"
		} else {
			out[i].GovernedBy = "p"
		}
	}
	return out, err
}

// PctSampling is P5.
type PctSampling struct {
	Applies            bool    `json:"applies"` // pct < 100 in the dominant tuple
	Pct                int     `json:"pct"`
	FailingMessages    int64   `json:"failing_messages"`
	ExpectedSampledOut float64 `json:"expected_sampled_out"` // (100-pct)% of failing
	ObservedSampledOut int64   `json:"observed_sampled_out"` // messages with a sampled_out override
	ExpectedShare      float64 `json:"expected_share"`       // percent
	ObservedShare      float64 `json:"observed_share"`       // percent of failing
}

// GetPctSampling computes P5 from the dominant tuple in the window.
func GetPctSampling(db *sqlx.DB, f StatsFilter) (*PctSampling, error) {
	ap, err := GetActivePolicyTuple(db, f)
	if err != nil {
		return nil, err
	}
	out := &PctSampling{Pct: 100}
	if ap.Tuple == nil {
		return out, nil
	}
	out.Pct = ap.Tuple.Pct
	if ap.Tuple.PctPresent != 1 || ap.Tuple.Pct >= 100 {
		return out, nil
	}
	out.Applies = true
	out.ExpectedShare = float64(100 - out.Pct)
	and, aargs := f.andClauses()
	var failing int64
	if err := db.Get(&failing, `
		SELECT COALESCE(SUM(rr.count), 0)
		FROM record_rows rr JOIN reports r ON r.id = rr.report_id
		WHERE rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'`+and, aargs...); err != nil {
		return nil, err
	}
	out.FailingMessages = failing
	out.ExpectedSampledOut = float64(failing) * out.ExpectedShare / 100
	if err := db.Get(&out.ObservedSampledOut, `
		SELECT COALESCE(SUM(rr.count), 0)
		FROM policy_overrides po
		JOIN record_rows rr ON rr.id = po.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE po.type = 'sampled_out'`+and, aargs...); err != nil {
		return nil, err
	}
	if failing > 0 {
		out.ObservedShare = float64(out.ObservedSampledOut) / float64(failing) * 100
	}
	return out, nil
}

// ReadinessSource is a known-good source that is currently failing (P6).
type ReadinessSource struct {
	SourceIP string `db:"source_ip" json:"ip"`
	Label    string `db:"label" json:"label"`
	Messages int64  `db:"messages" json:"messages"`
}

// EnforcementReadiness is P6.
type EnforcementReadiness struct {
	Policy           string            `json:"policy"`
	TotalMessages    int64             `json:"total_messages"`
	Neither          int64             `json:"neither"`
	NeitherShare     float64           `json:"neither_share"`      // percent — what p=reject would block
	KnownGoodNeither int64             `json:"known_good_neither"` // legitimate mail at risk (p≠none)
	KnownGoodSources []ReadinessSource `json:"known_good_sources"`
}

// GetEnforcementReadiness computes P6.
func GetEnforcementReadiness(db *sqlx.DB, f StatsFilter) (*EnforcementReadiness, error) {
	policy, err := GetActivePolicy(db, f)
	if err != nil {
		return nil, err
	}
	m, err := GetAuthMatrix(db, f)
	if err != nil {
		return nil, err
	}
	out := &EnforcementReadiness{Policy: policy, TotalMessages: m.Total(), Neither: m.BothFail, NeitherShare: m.Share(m.BothFail)}
	and, args := f.andClauses()
	if err := db.Select(&out.KnownGoodSources, `
		SELECT rr.source_ip, COALESCE(MAX(il.label), '') AS label, SUM(rr.count) AS messages
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		JOIN ip_labels il ON il.ip = rr.source_ip AND il.classification = 'known_good'
		WHERE rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'`+and+`
		GROUP BY rr.source_ip
		ORDER BY messages DESC
		LIMIT 20`, args...); err != nil {
		return nil, err
	}
	for _, s := range out.KnownGoodSources {
		out.KnownGoodNeither += s.Messages
	}
	return out, nil
}
