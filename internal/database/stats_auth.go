package database

import (
	"sort"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/psl"
)

// DKIMSelectorStat holds aggregate stats for a DKIM selector observed in
// reports (A1). Counts are weighted by the record row's message count.
type DKIMSelectorStat struct {
	Selector      string  `db:"selector" json:"selector"`
	SigningDomain string  `db:"signing_domain" json:"signing_domain"`
	Total         int64   `db:"total" json:"messages"`
	Passed        int64   `db:"passed" json:"passed"`
	Failed        int64   `db:"failed" json:"failed"`
	PassRate      float64 `db:"pass_rate" json:"pass_rate"`
	Sources       int64   `db:"sources" json:"sources"`       // distinct source IPs
	FirstSeen     int64   `db:"first_seen" json:"first_seen"` // from the selectors inventory (all time)
	LastSeen      int64   `db:"last_seen" json:"last_seen"`
	Expected      int     `db:"expected" json:"expected"` // -1 unset, 0 no, 1 yes
	IsNew         bool    `db:"-" json:"is_new"`          // first seen inside the filter window
}

// GetDKIMSelectorStats returns per-selector aggregate stats for all DKIM
// results tied to record rows in reports for the given DMARC policy domain.
// Kept for existing callers; see GetSelectorInventory for the filtered form.
func GetDKIMSelectorStats(db *sqlx.DB, domain string) ([]DKIMSelectorStat, error) {
	return GetSelectorInventory(db, StatsFilter{Domain: domain})
}

// GetSelectorInventory is A1: selector stats scoped by f, joined with the
// selectors inventory for first/last seen and the expected flag.
func GetSelectorInventory(db *sqlx.DB, f StatsFilter) ([]DKIMSelectorStat, error) {
	var stats []DKIMSelectorStat
	and, args := f.andClauses()
	err := db.Select(&stats, `
		SELECT
			dk.selector,
			dk.domain AS signing_domain,
			SUM(rr.count) AS total,
			SUM(CASE WHEN dk.result = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN dk.result != 'pass' THEN rr.count ELSE 0 END) AS failed,
			ROUND(100.0 * SUM(CASE WHEN dk.result = 'pass' THEN rr.count ELSE 0 END)
				/ NULLIF(SUM(rr.count), 0), 1) AS pass_rate,
			COUNT(DISTINCT rr.source_ip) AS sources,
			COALESCE(MAX(s.first_seen), 0) AS first_seen,
			COALESCE(MAX(s.last_seen), 0) AS last_seen,
			COALESCE(MAX(s.expected), -1) AS expected
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		JOIN reports r ON r.id = rr.report_id
		LEFT JOIN selectors s ON s.domain = dk.domain AND s.selector = dk.selector
		WHERE dk.selector != ''`+and+`
		GROUP BY dk.selector, dk.domain
		ORDER BY total DESC`, args...)
	if err != nil {
		return nil, err
	}
	for i := range stats {
		if f.From > 0 && stats[i].FirstSeen >= f.From && (f.To == 0 || stats[i].FirstSeen <= f.To) {
			stats[i].IsNew = true
		}
	}
	return stats, nil
}

// ResultCount is one raw result value with its weighted volume (A2, A4, A5).
type ResultCount struct {
	Value    string  `db:"value" json:"value"`
	Messages int64   `db:"messages" json:"messages"`
	Rows     int64   `db:"rows" json:"rows"`
	Share    float64 `db:"-" json:"share"` // percent of the total in the list
}

func fillShares(list []ResultCount) {
	var total int64
	for _, r := range list {
		total += r.Messages
	}
	if total == 0 {
		return
	}
	for i := range list {
		list[i].Share = float64(list[i].Messages) / float64(total) * 100
	}
}

// GetDKIMRawResults is A2: distribution of dkim_results.result weighted by
// record_rows.count (each signature counts the row's messages once).
func GetDKIMRawResults(db *sqlx.DB, f StatsFilter) ([]ResultCount, error) {
	var out []ResultCount
	and, args := f.andClauses()
	err := db.Select(&out, `
		SELECT COALESCE(NULLIF(dk.result, ''), 'none') AS value, SUM(rr.count) AS messages, COUNT(*) AS rows
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE 1=1`+and+`
		GROUP BY 1 ORDER BY messages DESC`, args...)
	fillShares(out)
	return out, err
}

// GetSPFRawResults is A4: distribution of spf_results.result.
func GetSPFRawResults(db *sqlx.DB, f StatsFilter) ([]ResultCount, error) {
	var out []ResultCount
	and, args := f.andClauses()
	err := db.Select(&out, `
		SELECT COALESCE(NULLIF(sp.result, ''), 'none') AS value, SUM(rr.count) AS messages, COUNT(*) AS rows
		FROM spf_results sp
		JOIN record_rows rr ON rr.id = sp.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE 1=1`+and+`
		GROUP BY 1 ORDER BY messages DESC`, args...)
	fillShares(out)
	return out, err
}

// GetSPFScopeSplit is A5: mfrom vs helo (absent scope counts as mfrom, the
// RFC default).
func GetSPFScopeSplit(db *sqlx.DB, f StatsFilter) ([]ResultCount, error) {
	var out []ResultCount
	and, args := f.andClauses()
	err := db.Select(&out, `
		SELECT CASE WHEN sp.scope = '' THEN 'mfrom' ELSE sp.scope END AS value, SUM(rr.count) AS messages, COUNT(*) AS rows
		FROM spf_results sp
		JOIN record_rows rr ON rr.id = sp.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE 1=1`+and+`
		GROUP BY 1 ORDER BY messages DESC`, args...)
	fillShares(out)
	return out, err
}

// DomainCount is a domain with its message volume.
type DomainCount struct {
	Domain   string `db:"domain" json:"domain"`
	Messages int64  `db:"messages" json:"messages"`
}

// SignatureHistogramBucket is "records carrying N DKIM signatures".
type SignatureHistogramBucket struct {
	Signatures int   `db:"signatures" json:"signatures"`
	Records    int64 `db:"records" json:"records"`
	Messages   int64 `db:"messages" json:"messages"`
}

// SigningAlignment is A3: how DKIM signing domains relate to header_from.
type SigningAlignment struct {
	Exact             int64                      `json:"exact"`       // d= equals header_from
	Relaxed           int64                      `json:"relaxed"`     // same organisational domain
	ThirdParty        int64                      `json:"third_party"` // different organisational domain
	Total             int64                      `json:"total"`
	ExactPct          float64                    `json:"exact_pct"`
	RelaxedPct        float64                    `json:"relaxed_pct"`
	ThirdPartyPct     float64                    `json:"third_party_pct"`
	ThirdPartyDomains []DomainCount              `json:"third_party_domains"`
	Histogram         []SignatureHistogramBucket `json:"signatures_per_record"`
}

// GetDKIMSigningAlignment computes A3. Alignment is classified in Go via the
// PSL (exact / relaxed / third_party), weighted by record message counts.
func GetDKIMSigningAlignment(db *sqlx.DB, f StatsFilter) (*SigningAlignment, error) {
	type pair struct {
		Signing    string `db:"signing"`
		HeaderFrom string `db:"header_from"`
		Messages   int64  `db:"messages"`
	}
	var pairs []pair
	and, args := f.andClauses()
	if err := db.Select(&pairs, `
		SELECT dk.domain AS signing, rr.header_from, SUM(rr.count) AS messages
		FROM dkim_results dk
		JOIN record_rows rr ON rr.id = dk.record_row_id
		JOIN reports r ON r.id = rr.report_id
		WHERE dk.domain != ''`+and+`
		GROUP BY dk.domain, rr.header_from`, args...); err != nil {
		return nil, err
	}
	out := &SigningAlignment{}
	third := map[string]int64{}
	for _, p := range pairs {
		out.Total += p.Messages
		switch psl.Align(p.Signing, p.HeaderFrom) {
		case psl.AlignExact:
			out.Exact += p.Messages
		case psl.AlignRelaxed:
			out.Relaxed += p.Messages
		default:
			out.ThirdParty += p.Messages
			third[psl.Normalize(p.Signing)] += p.Messages
		}
	}
	if out.Total > 0 {
		out.ExactPct = float64(out.Exact) / float64(out.Total) * 100
		out.RelaxedPct = float64(out.Relaxed) / float64(out.Total) * 100
		out.ThirdPartyPct = float64(out.ThirdParty) / float64(out.Total) * 100
	}
	for d, n := range third {
		out.ThirdPartyDomains = append(out.ThirdPartyDomains, DomainCount{Domain: d, Messages: n})
	}
	sort.Slice(out.ThirdPartyDomains, func(i, j int) bool {
		if out.ThirdPartyDomains[i].Messages != out.ThirdPartyDomains[j].Messages {
			return out.ThirdPartyDomains[i].Messages > out.ThirdPartyDomains[j].Messages
		}
		return out.ThirdPartyDomains[i].Domain < out.ThirdPartyDomains[j].Domain
	})
	if len(out.ThirdPartyDomains) > 10 {
		out.ThirdPartyDomains = out.ThirdPartyDomains[:10]
	}

	where, wargs := f.where()
	if err := db.Select(&out.Histogram, `
		SELECT n AS signatures, COUNT(*) AS records, SUM(cnt) AS messages FROM (
			SELECT rr.id, rr.count AS cnt,
				(SELECT COUNT(*) FROM dkim_results dk WHERE dk.record_row_id = rr.id) AS n
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id`+where+`
		)
		GROUP BY n ORDER BY n`, wargs...); err != nil {
		return nil, err
	}
	return out, nil
}

// EnvelopeFromAlignmentRow is A6: an envelope_from value with its alignment
// class against the header_from it was paired with most.
type EnvelopeFromAlignmentRow struct {
	EnvelopeFrom  string  `db:"envelope_from" json:"envelope_from"`
	HeaderFrom    string  `db:"header_from" json:"header_from"`
	TotalMessages int64   `db:"total_messages" json:"messages"`
	Passed        int64   `db:"passed" json:"passed"`
	Failed        int64   `db:"failed" json:"failed"`
	PassRate      float64 `db:"pass_rate" json:"pass_rate"`
	Alignment     string  `db:"-" json:"alignment"` // exact | relaxed | misaligned | null_sender | none
}

// GetEnvelopeFromAlignment returns per-envelope_from stats with the alignment
// class (A6). Rows are grouped by (envelope_from, header_from) pairs and then
// merged per envelope_from, keeping the dominant header_from's class.
func GetEnvelopeFromAlignment(db *sqlx.DB, f StatsFilter) ([]EnvelopeFromAlignmentRow, error) {
	var pairs []EnvelopeFromAlignmentRow
	where, args := f.where()
	if err := db.Select(&pairs, `
		SELECT
			rr.envelope_from, rr.header_from,
			SUM(rr.count) AS total_messages,
			SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass' THEN rr.count ELSE 0 END) AS passed,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			0.0 AS pass_rate
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where+`
		GROUP BY rr.envelope_from, rr.header_from
		ORDER BY total_messages DESC`, args...); err != nil {
		return nil, err
	}
	merged := map[string]*EnvelopeFromAlignmentRow{}
	var order []string
	for _, p := range pairs {
		key := p.EnvelopeFrom
		row, ok := merged[key]
		if !ok {
			cp := p // first (largest) pair defines the dominant header_from + class
			if cp.EnvelopeFrom == "" {
				cp.Alignment = "none"
			} else {
				cp.Alignment = psl.AlignEnvelope(cp.EnvelopeFrom, cp.HeaderFrom)
			}
			merged[key] = &cp
			order = append(order, key)
			continue
		}
		row.TotalMessages += p.TotalMessages
		row.Passed += p.Passed
		row.Failed += p.Failed
	}
	out := make([]EnvelopeFromAlignmentRow, 0, len(order))
	for _, k := range order {
		r := *merged[k]
		if r.TotalMessages > 0 {
			r.PassRate = float64(r.Passed) / float64(r.TotalMessages) * 100
		}
		if r.EnvelopeFrom == "" {
			r.EnvelopeFrom = "(none)"
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TotalMessages > out[j].TotalMessages })
	return out, nil
}

// AlignmentGapPair is one (auth domain, header_from) combination that
// authenticated but did not align.
type AlignmentGapPair struct {
	Kind       string `db:"kind" json:"kind"` // dkim | spf
	AuthDomain string `db:"auth_domain" json:"auth_domain"`
	HeaderFrom string `db:"header_from" json:"header_from"`
	Messages   int64  `db:"messages" json:"messages"`
	Records    int64  `db:"records" json:"records"`
}

// AlignmentGap is A7: records where a raw check passed but the aligned
// evaluation did not.
type AlignmentGap struct {
	Messages     int64              `json:"messages"` // distinct records (either kind)
	Records      int64              `json:"records"`
	DKIMMessages int64              `json:"dkim_messages"`
	SPFMessages  int64              `json:"spf_messages"`
	Pairs        []AlignmentGapPair `json:"pairs"`
}

// GetAlignmentGap computes A7.
func GetAlignmentGap(db *sqlx.DB, f StatsFilter, limit int) (*AlignmentGap, error) {
	if limit <= 0 {
		limit = 20
	}
	const dkimGap = `rr.eval_dkim != 'pass' AND EXISTS (SELECT 1 FROM dkim_results dk WHERE dk.record_row_id = rr.id AND dk.result = 'pass')`
	const spfGap = `rr.eval_spf != 'pass' AND EXISTS (SELECT 1 FROM spf_results sp WHERE sp.record_row_id = rr.id AND sp.result = 'pass')`
	and, args := f.andClauses()
	var totals struct {
		Messages     int64 `db:"messages"`
		Records      int64 `db:"records"`
		DKIMMessages int64 `db:"dkim_messages"`
		SPFMessages  int64 `db:"spf_messages"`
	}
	if err := db.Get(&totals, `
		SELECT
			COALESCE(SUM(rr.count), 0) AS messages,
			COUNT(*) AS records,
			COALESCE(SUM(CASE WHEN `+dkimGap+` THEN rr.count ELSE 0 END), 0) AS dkim_messages,
			COALESCE(SUM(CASE WHEN `+spfGap+` THEN rr.count ELSE 0 END), 0) AS spf_messages
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE ((`+dkimGap+`) OR (`+spfGap+`))`+and, args...); err != nil {
		return nil, err
	}
	out := &AlignmentGap{Messages: totals.Messages, Records: totals.Records, DKIMMessages: totals.DKIMMessages, SPFMessages: totals.SPFMessages}
	if out.Records == 0 {
		return out, nil
	}
	pairArgs := append(append(append([]any{}, args...), args...), limit)
	if err := db.Select(&out.Pairs, `
		SELECT kind, auth_domain, header_from, SUM(messages) AS messages, SUM(records) AS records FROM (
			SELECT 'dkim' AS kind, dk.domain AS auth_domain, rr.header_from, SUM(rr.count) AS messages, COUNT(DISTINCT rr.id) AS records
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			JOIN dkim_results dk ON dk.record_row_id = rr.id AND dk.result = 'pass'
			WHERE rr.eval_dkim != 'pass'`+and+`
			GROUP BY dk.domain, rr.header_from
			UNION ALL
			SELECT 'spf', sp.domain, rr.header_from, SUM(rr.count), COUNT(DISTINCT rr.id)
			FROM record_rows rr
			JOIN reports r ON r.id = rr.report_id
			JOIN spf_results sp ON sp.record_row_id = rr.id AND sp.result = 'pass'
			WHERE rr.eval_spf != 'pass'`+and+`
			GROUP BY sp.domain, rr.header_from
		)
		GROUP BY kind, auth_domain, header_from
		ORDER BY messages DESC
		LIMIT ?`, pairArgs...); err != nil {
		return nil, err
	}
	return out, nil
}

// ReporterErrorRate is A8: DNS-error share of raw results per reporter.
type ReporterErrorRate struct {
	OrgName  string  `db:"org_name" json:"org_name"`
	Results  int64   `db:"results" json:"results"` // raw results weighted by messages
	Errors   int64   `db:"errors" json:"errors"`   // temperror + permerror
	Rate     float64 `db:"-" json:"rate"`          // percent
	Messages int64   `db:"messages" json:"messages"`
}

// GetDNSErrorRate computes A8 over both dkim_results and spf_results.
func GetDNSErrorRate(db *sqlx.DB, f StatsFilter) ([]ReporterErrorRate, error) {
	var out []ReporterErrorRate
	and, args := f.andClauses()
	allArgs := append(append([]any{}, args...), args...)
	err := db.Select(&out, `
		SELECT org_name, SUM(results) AS results, SUM(errors) AS errors, SUM(messages) AS messages FROM (
			SELECT r.org_name,
				SUM(rr.count) AS results,
				SUM(CASE WHEN dk.result IN ('temperror','permerror') THEN rr.count ELSE 0 END) AS errors,
				0 AS messages
			FROM dkim_results dk
			JOIN record_rows rr ON rr.id = dk.record_row_id
			JOIN reports r ON r.id = rr.report_id
			WHERE 1=1`+and+`
			GROUP BY r.org_name
			UNION ALL
			SELECT r.org_name,
				SUM(rr.count),
				SUM(CASE WHEN sp.result IN ('temperror','permerror') THEN rr.count ELSE 0 END),
				SUM(rr.count)
			FROM spf_results sp
			JOIN record_rows rr ON rr.id = sp.record_row_id
			JOIN reports r ON r.id = rr.report_id
			WHERE 1=1`+and+`
			GROUP BY r.org_name
		)
		GROUP BY org_name
		ORDER BY errors DESC, results DESC`, allArgs...)
	for i := range out {
		if out[i].Results > 0 {
			out[i].Rate = float64(out[i].Errors) / float64(out[i].Results) * 100
		}
	}
	return out, err
}
