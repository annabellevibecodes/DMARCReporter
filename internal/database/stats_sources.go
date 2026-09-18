package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

// SourceInventoryRow is one source IP in the S1 table: the aligned-result
// matrix, raw-result counts, disposition split, reporter/header_from breadth,
// all-time first/last seen, enrichment and user label.
type SourceInventoryRow struct {
	SourceIP       string `db:"source_ip" json:"ip"`
	TotalMessages  int64  `db:"total_messages" json:"messages"`
	BothPass       int64  `db:"both_pass" json:"both_pass"`
	DKIMOnly       int64  `db:"dkim_only" json:"dkim_only"`
	SPFOnly        int64  `db:"spf_only" json:"spf_only"`
	Neither        int64  `db:"neither" json:"neither"`
	RawDKIMPass    int64  `db:"raw_dkim_pass" json:"raw_dkim_pass"` // messages with ≥1 raw DKIM pass
	RawSPFPass     int64  `db:"raw_spf_pass" json:"raw_spf_pass"`   // messages with ≥1 raw SPF pass
	DispNone       int64  `db:"disp_none" json:"disp_none"`
	DispQuarantine int64  `db:"disp_quarantine" json:"disp_quarantine"`
	DispReject     int64  `db:"disp_reject" json:"disp_reject"`
	Reporters      int64  `db:"reporters" json:"reporters"`
	HeaderFroms    int64  `db:"header_froms" json:"header_froms"`
	HeaderFromList string `db:"header_from_list" json:"header_from_list"`
	FirstSeen      int64  `db:"first_seen" json:"first_seen"` // all-time (scope: domain/ef), report date_range_begin
	LastSeen       int64  `db:"last_seen" json:"last_seen"`
	RDNS           string `db:"rdns" json:"rdns"`
	Country        string `db:"country" json:"country"`
	WhoisOrg       string `db:"whois_org" json:"whois_org"`
	ASN            string `db:"whois_asn" json:"asn"`
	Label          string `db:"label" json:"label"`
	Classification string `db:"classification" json:"classification"`
	Notes          string `db:"notes" json:"notes"`
	Pattern        string `db:"pattern" json:"pattern"` // S3, user override applied
	// Derived in Go:
	Provider     string  `db:"-" json:"provider"`
	PassRate     float64 `db:"-" json:"pass_rate"`
	DKIMPassRate float64 `db:"-" json:"dkim_pass_rate"`
	SPFPassRate  float64 `db:"-" json:"spf_pass_rate"`
	IsNew        bool    `db:"-" json:"is_new"` // first_seen within the filter window (S2)
}

// Passed returns messages with at least one aligned pass.
func (r SourceInventoryRow) Passed() int64 { return r.BothPass + r.DKIMOnly + r.SPFOnly }

// Failed returns messages with no aligned pass.
func (r SourceInventoryRow) Failed() int64 { return r.Neither }

// Matrix returns the row's buckets as an ipinfo.Matrix.
func (r SourceInventoryRow) Matrix() ipinfo.Matrix {
	return ipinfo.Matrix{BothPass: r.BothPass, DKIMOnly: r.DKIMOnly, SPFOnly: r.SPFOnly, Neither: r.Neither}
}

// SourceQuery holds the S1 table options.
type SourceQuery struct {
	Sort        string // messages | failed | pass_rate | first_seen | last_seen | ip | neither | dkim_only | spf_only | both_pass
	Dir         string // asc | desc
	Pattern     string // filter by pattern ("" = all)
	Matrix      string // both | dkim | spf | neither → rows with > 0 in that bucket, sorted by it
	NewOnly     bool   // only sources first seen inside the window
	Min         int    // minimum messages in window
	Search      string // substring match on ip / label / rdns
	Disposition string // only aggregate rows with this disposition (legacy sources-page filter)
	Country     string // ip_info.whois_country ("??" = unknown)
	Limit       int
	Offset      int
}

// sourceInventorySelect builds the aggregate query. thresholds drive the SQL
// pattern CASE so filtering/sorting by pattern happens in the database.
func sourceInventorySelect(f StatsFilter, q SourceQuery, th ipinfo.PatternThresholds) (string, []any) {
	clauses, args := f.clauses(true)
	if q.Disposition != "" {
		clauses = append(clauses, "rr.disposition = ?")
		args = append(args, q.Disposition)
	}
	if q.Country == "??" {
		clauses = append(clauses, "(ii.whois_country IS NULL OR ii.whois_country = '')")
	} else if q.Country != "" {
		clauses = append(clauses, "ii.whois_country = ?")
		args = append(args, q.Country)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	spanWhere, spanArgs := f.whereNoTime()
	const (
		bothPass = "SUM(CASE WHEN rr.eval_dkim = 'pass' AND rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)"
		dkimOnly = "SUM(CASE WHEN rr.eval_dkim = 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END)"
		spfOnly  = "SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf = 'pass' THEN rr.count ELSE 0 END)"
		neither  = "SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END)"
	)
	pattern := ipinfo.PatternCaseSQL(th, bothPass, dkimOnly, spfOnly, neither, "COALESCE(MAX(il.classification), '')")
	sqlText := `
		WITH span AS (
			SELECT rr.source_ip, MIN(r.date_range_begin) AS first_seen, MAX(r.date_range_begin) AS last_seen
			FROM record_rows rr JOIN reports r ON r.id = rr.report_id` + spanWhere + `
			GROUP BY rr.source_ip
		)
		SELECT
			rr.source_ip,
			SUM(rr.count) AS total_messages,
			` + bothPass + ` AS both_pass,
			` + dkimOnly + ` AS dkim_only,
			` + spfOnly + ` AS spf_only,
			` + neither + ` AS neither,
			SUM(CASE WHEN EXISTS (SELECT 1 FROM dkim_results dk WHERE dk.record_row_id = rr.id AND dk.result = 'pass') THEN rr.count ELSE 0 END) AS raw_dkim_pass,
			SUM(CASE WHEN EXISTS (SELECT 1 FROM spf_results sp WHERE sp.record_row_id = rr.id AND sp.result = 'pass') THEN rr.count ELSE 0 END) AS raw_spf_pass,
			SUM(CASE WHEN rr.disposition NOT IN ('quarantine','reject') THEN rr.count ELSE 0 END) AS disp_none,
			SUM(CASE WHEN rr.disposition = 'quarantine' THEN rr.count ELSE 0 END) AS disp_quarantine,
			SUM(CASE WHEN rr.disposition = 'reject' THEN rr.count ELSE 0 END) AS disp_reject,
			COUNT(DISTINCT r.org_name) AS reporters,
			COUNT(DISTINCT rr.header_from) AS header_froms,
			COALESCE(GROUP_CONCAT(DISTINCT rr.header_from), '') AS header_from_list,
			COALESCE(MAX(s.first_seen), 0) AS first_seen,
			COALESCE(MAX(s.last_seen), 0) AS last_seen,
			COALESCE(MAX(ii.rdns), '') AS rdns,
			COALESCE(MAX(ii.whois_country), '') AS country,
			COALESCE(MAX(ii.whois_org), '') AS whois_org,
			COALESCE(MAX(ii.whois_asn), '') AS whois_asn,
			COALESCE(MAX(il.label), '') AS label,
			COALESCE(MAX(il.classification), '') AS classification,
			COALESCE(MAX(il.notes), '') AS notes,
			` + pattern + ` AS pattern
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		LEFT JOIN span s ON s.source_ip = rr.source_ip
		LEFT JOIN ip_info ii ON ii.ip = rr.source_ip
		LEFT JOIN ip_labels il ON il.ip = rr.source_ip` + where + `
		GROUP BY rr.source_ip`
	return sqlText, append(append([]any{}, spanArgs...), args...)
}

// escapeLike escapes LIKE wildcards in a user-supplied substring so that
// "%" and "_" match literally (used with ESCAPE '\').
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// GetSourceInventory returns the S1 table for f, applying q's filters and
// sort in SQL, plus the total row count before Limit/Offset.
func GetSourceInventory(db *sqlx.DB, f StatsFilter, q SourceQuery, th ipinfo.PatternThresholds) ([]SourceInventoryRow, int, error) {
	base, args := sourceInventorySelect(f, q, th)

	var having []string
	if q.Min > 1 {
		having = append(having, fmt.Sprintf("SUM(rr.count) >= %d", q.Min))
	}
	switch q.Matrix {
	case "both":
		having = append(having, "both_pass > 0")
	case "dkim":
		having = append(having, "dkim_only > 0")
	case "spf":
		having = append(having, "spf_only > 0")
	case "neither":
		having = append(having, "neither > 0")
	}
	if q.NewOnly && f.From > 0 {
		having = append(having, fmt.Sprintf("first_seen >= %d", f.From))
		if f.To > 0 {
			having = append(having, fmt.Sprintf("first_seen <= %d", f.To))
		}
	}
	if q.Pattern != "" {
		having = append(having, "pattern = ?")
		args = append(args, q.Pattern)
	}
	if q.Search != "" {
		having = append(having, "(rr.source_ip LIKE ? ESCAPE '\\' OR label LIKE ? ESCAPE '\\' OR rdns LIKE ? ESCAPE '\\')")
		like := "%" + escapeLike(q.Search) + "%"
		args = append(args, like, like, like)
	}
	if len(having) > 0 {
		base += " HAVING " + strings.Join(having, " AND ")
	}

	dir := "DESC"
	if q.Dir == "asc" {
		dir = "ASC"
	}
	var order string
	switch q.Sort {
	case "ip":
		order = "rr.source_ip " + dir
	case "failed", "neither":
		order = "neither " + dir + ", total_messages DESC"
	case "pass_rate":
		order = "CAST(both_pass + dkim_only + spf_only AS REAL) / total_messages " + dir + ", total_messages DESC"
	case "first_seen":
		order = "first_seen " + dir
	case "last_seen":
		order = "last_seen " + dir
	case "dkim_only":
		order = "dkim_only " + dir
	case "spf_only":
		order = "spf_only " + dir
	case "both_pass":
		order = "both_pass " + dir
	case "reporters":
		order = "reporters " + dir + ", total_messages DESC"
	default:
		switch q.Matrix {
		case "dkim":
			order = "dkim_only " + dir
		case "spf":
			order = "spf_only " + dir
		case "neither":
			order = "neither " + dir
		case "both":
			order = "both_pass " + dir
		default:
			order = "total_messages " + dir
		}
	}

	var total int
	if err := db.Get(&total, "SELECT COUNT(*) FROM ("+base+")", args...); err != nil {
		return nil, 0, err
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	pageArgs := append(append([]any{}, args...), limit, q.Offset)
	var rows []SourceInventoryRow
	if err := db.Select(&rows, base+" ORDER BY "+order+" LIMIT ? OFFSET ?", pageArgs...); err != nil {
		return nil, 0, err
	}
	for i := range rows {
		finishSourceRow(&rows[i], f)
	}
	return rows, total, nil
}

func finishSourceRow(r *SourceInventoryRow, f StatsFilter) {
	r.Provider = ipinfo.ProviderFromRDNS(r.RDNS)
	if r.TotalMessages > 0 {
		r.PassRate = float64(r.Passed()) / float64(r.TotalMessages) * 100
		r.DKIMPassRate = float64(r.BothPass+r.DKIMOnly) / float64(r.TotalMessages) * 100
		r.SPFPassRate = float64(r.BothPass+r.SPFOnly) / float64(r.TotalMessages) * 100
	}
	if f.From > 0 && r.FirstSeen >= f.From && (f.To == 0 || r.FirstSeen <= f.To) {
		r.IsNew = true
	}
}

// GetNewSources returns S2: sources whose earliest report (within the
// domain/envelope scope, all time) falls inside the filter window. With an
// unbounded window every source is "new", so an empty list is returned.
func GetNewSources(db *sqlx.DB, f StatsFilter, th ipinfo.PatternThresholds, limit int) ([]SourceInventoryRow, error) {
	if f.From <= 0 {
		return nil, nil
	}
	rows, _, err := GetSourceInventory(db, f, SourceQuery{NewOnly: true, Sort: "messages", Dir: "desc", Limit: limit}, th)
	return rows, err
}

// SourceTimelinePoint is one bucket in a source's history.
type SourceTimelinePoint = TrendPoint

// SourceSelectorUse is a selector observed from a source.
type SourceSelectorUse struct {
	Domain   string `db:"domain" json:"domain"`
	Selector string `db:"selector" json:"selector"`
	Messages int64  `db:"messages" json:"messages"`
	Passed   int64  `db:"passed" json:"passed"`
}

// SourceIdentifier is an envelope_from / header_from value seen from a source.
type SourceIdentifier struct {
	Value    string `db:"value" json:"value"`
	Messages int64  `db:"messages" json:"messages"`
}

// SourceReporterUse is a reporter that has seen the source.
type SourceReporterUse struct {
	OrgName  string `db:"org_name" json:"org_name"`
	Messages int64  `db:"messages" json:"messages"`
	Reports  int64  `db:"reports" json:"reports"`
}

// SourceDetail is /api/sources/:ip: the S1 row plus context.
type SourceDetail struct {
	Row           *SourceInventoryRow   `json:"source"`
	Timeline      []SourceTimelinePoint `json:"timeline"`
	TimelineDaily bool                  `json:"timeline_daily"`
	Selectors     []SourceSelectorUse   `json:"selectors"`
	HeaderFroms   []SourceIdentifier    `json:"header_froms"`
	EnvelopeFroms []SourceIdentifier    `json:"envelope_froms"`
	Reporters     []SourceReporterUse   `json:"reporters"`
	Domains       []SourceIdentifier    `json:"domains"` // policy domains the source appeared under
}

// GetSourceDetail returns the S1 detail for one IP, or nil when it has no
// records in the window.
func GetSourceDetail(db *sqlx.DB, ip string, f StatsFilter, th ipinfo.PatternThresholds) (*SourceDetail, error) {
	sf := f
	sf.SourceIP = ip
	rows, _, err := GetSourceInventory(db, sf, SourceQuery{Limit: 1}, th)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	d := &SourceDetail{Row: &rows[0]}

	d.TimelineDaily = TrendDaily(f.From)
	tl, err := GetTrendData(db, sf, d.TimelineDaily)
	if err != nil {
		return nil, err
	}
	d.Timeline = FillTrendGaps(tl, f.From, f.To, d.TimelineDaily)

	where, args := sf.where()
	if err := db.Select(&d.Selectors, `
		SELECT dk.domain, dk.selector, SUM(rr.count) AS messages,
			SUM(CASE WHEN dk.result = 'pass' THEN rr.count ELSE 0 END) AS passed
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY dk.domain, dk.selector
		ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	if err := db.Select(&d.HeaderFroms, `
		SELECT rr.header_from AS value, SUM(rr.count) AS messages
		FROM record_rows rr JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY rr.header_from ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	if err := db.Select(&d.EnvelopeFroms, `
		SELECT rr.envelope_from AS value, SUM(rr.count) AS messages
		FROM record_rows rr JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY rr.envelope_from ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	if err := db.Select(&d.Reporters, `
		SELECT r.org_name, SUM(rr.count) AS messages, COUNT(DISTINCT r.id) AS reports
		FROM record_rows rr JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY r.org_name ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	if err := db.Select(&d.Domains, `
		SELECT r.domain AS value, SUM(rr.count) AS messages
		FROM record_rows rr JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY r.domain ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	return d, nil
}

// SPFCacheEntry is one resolved SPF record (spf_authorized_cache).
type SPFCacheEntry struct {
	Domain    string `db:"domain"`
	CIDRs     string `db:"cidrs"` // JSON array
	Lookups   int    `db:"lookups"`
	OverLimit int    `db:"over_limit"`
	Error     string `db:"error"`
	CheckedAt int64  `db:"checked_at"`
}

// Prefixes parses the cached CIDR list.
func (e SPFCacheEntry) Prefixes() []netip.Prefix {
	var raw []string
	if err := json.Unmarshal([]byte(e.CIDRs), &raw); err != nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}

// Contains reports whether ip is inside any cached prefix.
func (e SPFCacheEntry) Contains(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, p := range e.Prefixes() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// GetSPFCache returns the cached SPF expansion for domain (nil when absent).
func GetSPFCache(db *sqlx.DB, domain string) (*SPFCacheEntry, error) {
	var e SPFCacheEntry
	err := db.Get(&e, `SELECT * FROM spf_authorized_cache WHERE domain = ?`, domain)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// ListSPFCache returns every cached SPF expansion keyed by domain.
func ListSPFCache(db *sqlx.DB) (map[string]SPFCacheEntry, error) {
	var rows []SPFCacheEntry
	if err := db.Select(&rows, `SELECT * FROM spf_authorized_cache`); err != nil {
		return nil, err
	}
	m := make(map[string]SPFCacheEntry, len(rows))
	for _, r := range rows {
		m[r.Domain] = r
	}
	return m, nil
}

// UpsertSPFCache stores a resolved SPF expansion.
func UpsertSPFCache(db *sqlx.DB, e SPFCacheEntry) error {
	if e.CIDRs == "" {
		e.CIDRs = "[]"
	}
	_, err := db.Exec(`
		INSERT INTO spf_authorized_cache (domain, cidrs, lookups, over_limit, error, checked_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			cidrs = excluded.cidrs, lookups = excluded.lookups, over_limit = excluded.over_limit,
			error = excluded.error, checked_at = excluded.checked_at`,
		e.Domain, e.CIDRs, e.Lookups, e.OverLimit, e.Error, e.CheckedAt)
	return err
}

// SpoofSource is one source contributing "neither" volume, classified by SPF membership.
type SpoofSource struct {
	SourceIP string `db:"source_ip" json:"ip"`
	Domain   string `db:"domain" json:"domain"`
	Messages int64  `db:"messages" json:"messages"`
	InSPF    bool   `db:"-" json:"in_spf"`
	Resolved bool   `db:"-" json:"resolved"`
}

// SpoofVolume is S4: messages with no aligned pass, split by whether the
// source IP is inside the domain's resolved SPF record.
type SpoofVolume struct {
	InSPF      int64         `json:"in_spf"`
	NotInSPF   int64         `json:"not_in_spf"`
	Unresolved int64         `json:"unresolved"` // neither-volume for domains with no SPF cache yet
	Total      int64         `json:"total"`
	Resolved   bool          `json:"resolved"` // false when no domain in scope has a cache entry
	Domains    []string      `json:"domains_pending"`
	Sources    []SpoofSource `json:"sources"`
}

// NotInSPFShare returns NotInSPF as a percentage of the resolved neither volume.
func (s SpoofVolume) NotInSPFShare() float64 {
	resolved := s.InSPF + s.NotInSPF
	if resolved == 0 {
		return 0
	}
	return float64(s.NotInSPF) / float64(resolved) * 100
}

// GetSpoofVolume computes S4 from record_rows and spf_authorized_cache. It never
// resolves DNS; domains without a cache entry are reported as pending.
func GetSpoofVolume(db *sqlx.DB, f StatsFilter, limit int) (*SpoofVolume, error) {
	if limit <= 0 {
		limit = 20
	}
	and, args := f.andClauses()
	var rows []SpoofSource
	if err := db.Select(&rows, `
		SELECT rr.source_ip, r.domain, SUM(rr.count) AS messages
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'`+and+`
		GROUP BY rr.source_ip, r.domain
		ORDER BY messages DESC`, args...); err != nil {
		return nil, err
	}
	cache, err := ListSPFCache(db)
	if err != nil {
		return nil, err
	}
	out := &SpoofVolume{}
	pending := map[string]bool{}
	for i := range rows {
		r := &rows[i]
		out.Total += r.Messages
		entry, ok := cache[r.Domain]
		if !ok || entry.CheckedAt == 0 {
			out.Unresolved += r.Messages
			pending[r.Domain] = true
			continue
		}
		r.Resolved = true
		out.Resolved = true
		if entry.Contains(r.SourceIP) {
			r.InSPF = true
			out.InSPF += r.Messages
		} else {
			out.NotInSPF += r.Messages
		}
	}
	for d := range pending {
		out.Domains = append(out.Domains, d)
	}
	if len(rows) > limit {
		rows = rows[:limit]
	}
	out.Sources = rows
	return out, nil
}
