package database

import (
	"github.com/jmoiron/sqlx"
)

// EnforcementStats is C7: how much of the failing mail the receivers actually
// blocked under the published policy.
type EnforcementStats struct {
	Policy   string   `db:"-"`        // dominant published p in the window ("" when no data)
	Enforced int64    `db:"enforced"` // messages with disposition quarantine or reject
	Failing  int64    `db:"failing"`  // messages with neither DKIM nor SPF aligned pass
	Rate     *float64 // Enforced/Failing in percent; nil when p = none or Failing = 0
}

// GetEnforcementEffectiveness returns Σ count where disposition ∈ {quarantine,
// reject} over Σ count where neither aligned check passed. Rate is nil when the
// dominant published policy is none (nothing is expected to be enforced) or
// when there is no failing mail to enforce against.
func GetEnforcementEffectiveness(db *sqlx.DB, f StatsFilter) (*EnforcementStats, error) {
	var s EnforcementStats
	where, args := f.where()
	if err := db.Get(&s, `
		SELECT
			COALESCE(SUM(CASE WHEN rr.disposition IN ('quarantine','reject') THEN rr.count ELSE 0 END), 0) AS enforced,
			COALESCE(SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END), 0) AS failing
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where, args...); err != nil {
		return nil, err
	}
	policy, err := GetActivePolicy(db, f)
	if err != nil {
		return nil, err
	}
	s.Policy = policy
	if policy != "" && policy != "none" && s.Failing > 0 {
		rate := float64(s.Enforced) / float64(s.Failing) * 100
		if rate > 100 {
			rate = 100
		}
		s.Rate = &rate
	}
	return &s, nil
}

// UnexplainedOverrideSource is one source contributing unexplained overrides.
type UnexplainedOverrideSource struct {
	SourceIP string `db:"source_ip"`
	Messages int64  `db:"messages"`
	Records  int64  `db:"records"`
	Policy   string `db:"policy"`
	OrgName  string `db:"org_name"`
}

// UnexplainedOverrideStats is C8: failing rows whose disposition is weaker than
// the report's published p with no <reason> explaining why.
type UnexplainedOverrideStats struct {
	Messages int64                       `db:"messages"`
	Records  int64                       `db:"records"`
	Sources  []UnexplainedOverrideSource `db:"-"`
}

// unexplainedWhere is the row predicate: neither aligned check passed, the
// disposition is weaker than p, and no policy_overrides row exists.
const unexplainedWhere = `
	rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass'
	AND (
		(r.policy = 'reject' AND rr.disposition IN ('none','quarantine'))
		OR (r.policy = 'quarantine' AND rr.disposition = 'none')
	)
	AND NOT EXISTS (SELECT 1 FROM policy_overrides po WHERE po.record_row_id = rr.id)`

// GetUnexplainedOverrides returns totals and the top contributing sources.
func GetUnexplainedOverrides(db *sqlx.DB, f StatsFilter, limit int) (*UnexplainedOverrideStats, error) {
	if limit <= 0 {
		limit = 10
	}
	var s UnexplainedOverrideStats
	and, args := f.andClauses()
	if err := db.Get(&s, `
		SELECT COALESCE(SUM(rr.count), 0) AS messages, COUNT(*) AS records
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE `+unexplainedWhere+and, args...); err != nil {
		return nil, err
	}
	if s.Records == 0 {
		return &s, nil
	}
	srcArgs := append(append([]any{}, args...), limit)
	if err := db.Select(&s.Sources, `
		SELECT
			rr.source_ip,
			SUM(rr.count) AS messages,
			COUNT(*) AS records,
			MAX(r.policy) AS policy,
			MAX(r.org_name) AS org_name
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE `+unexplainedWhere+and+`
		GROUP BY rr.source_ip
		ORDER BY messages DESC
		LIMIT ?`, srcArgs...); err != nil {
		return nil, err
	}
	return &s, nil
}

// DispositionStats is the C6 split by what receivers actually did.
type DispositionStats struct {
	None       int64 `db:"none"`
	Quarantine int64 `db:"quarantine"`
	Reject     int64 `db:"reject"`
}

// Total returns the sum of the three buckets.
func (d DispositionStats) Total() int64 { return d.None + d.Quarantine + d.Reject }

// GetDispositionStats returns message volume by disposition, scoped by f.
func GetDispositionStats(db *sqlx.DB, f StatsFilter) (*DispositionStats, error) {
	var d DispositionStats
	where, args := f.where()
	err := db.Get(&d, `
		SELECT
			COALESCE(SUM(CASE WHEN rr.disposition NOT IN ('quarantine','reject') THEN rr.count ELSE 0 END), 0) AS none,
			COALESCE(SUM(CASE WHEN rr.disposition = 'quarantine' THEN rr.count ELSE 0 END), 0) AS quarantine,
			COALESCE(SUM(CASE WHEN rr.disposition = 'reject' THEN rr.count ELSE 0 END), 0) AS reject
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id`+where, args...)
	return &d, err
}
