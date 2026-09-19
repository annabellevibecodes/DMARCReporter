package database

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/jmoiron/sqlx"
)

// BIMIReadiness is B10 for one domain: whether its DMARC policy would let a
// receiver do BIMI at all, judged before anything about logos is considered.
//
// The verdict is taken from the dominant policy tuple in the window — the one
// covering the most messages — rather than from the strictest or the most
// recent, so it describes what most mail was actually evaluated against.
type BIMIReadiness struct {
	Domain   string      `json:"domain"`
	Eligible bool        `json:"eligible"`
	Known    bool        `json:"known"` // false when no report in the window names this domain
	Policy   PolicyTuple `json:"policy"`
	Tags     []string    `json:"tags"`
	// Blockers are the independent reasons BIMI cannot work. Each is phrased
	// as the change that would fix it.
	Blockers []string `json:"blockers,omitempty"`
	// Notes are things worth knowing that do not by themselves block BIMI.
	Notes    []string `json:"notes,omitempty"`
	Reports  int64    `db:"reports" json:"reports"`
	Messages int64    `db:"messages" json:"messages"`
}

// BIMIEligible applies core spec §7.1 steps 7 to 9 to one policy tuple.
//
// Note what is *not* tested here: steps 4 to 6 ask whether an individual
// message passed DMARC, which is a per-message question no published record
// can answer. This is the domain-level precondition — a domain that fails it
// shows no logo however well its record, logo and certificate are set up.
func BIMIEligible(t PolicyTuple) (eligible bool, blockers, notes []string) {
	switch t.P {
	case "quarantine", "reject":
	case "", "none":
		blockers = append(blockers, "p=none — BIMI needs p=quarantine or p=reject (§7.1 step 7)")
	default:
		blockers = append(blockers, fmt.Sprintf("p=%s is not a policy any receiver applies", t.P))
	}

	// Step 8: a published sp=none exempts every subdomain, and the spec treats
	// that as disqualifying rather than as "the parent is still fine".
	if t.SPPresent == 1 && t.SP == "none" {
		blockers = append(blockers, "sp=none — a published subdomain policy of none blocks BIMI (§7.1 step 8)")
	}

	// Step 9 constrains quarantine only: a sampled quarantine policy is not at
	// full effect. pct is absent from DMARCbis records entirely, which is why
	// this reads pct_present rather than assuming the RFC 7489 default of 100.
	if t.P == "quarantine" && t.PctPresent == 1 && t.Pct != 100 {
		blockers = append(blockers, fmt.Sprintf("p=quarantine with pct=%d — quarantine must be at full effect (§7.1 step 9)", t.Pct))
	}
	if t.P == "reject" && t.PctPresent == 1 && t.Pct != 100 {
		notes = append(notes, fmt.Sprintf("pct=%d is published with p=reject; §7.1 constrains pct only for quarantine, but receivers vary", t.Pct))
	}
	if t.Testing == "y" {
		notes = append(notes, "the record declares t=y (testing), which a receiver may treat as p=none")
	}
	if t.NP == "none" {
		notes = append(notes, "np=none exempts non-existent subdomains only; it does not affect this domain's own mail")
	}
	return len(blockers) == 0, blockers, notes
}

// GetBIMIReadiness is B10 for every domain in the window, alphabetically.
func GetBIMIReadiness(db *sqlx.DB, f StatsFilter) ([]BIMIReadiness, error) {
	type row struct {
		Domain string `db:"domain"`
		PolicyTuple
		Reports  int64 `db:"reports"`
		Messages int64 `db:"messages"`
	}
	var rows []row
	where, args := f.where()
	if err := db.Select(&rows, `
		SELECT r.domain, `+policyTupleCols+`,
		       COUNT(DISTINCT r.id) AS reports, COALESCE(SUM(rr.count), 0) AS messages
		  FROM reports r
		  JOIN record_rows rr ON rr.report_id = r.id`+where+`
		 GROUP BY r.domain, `+policyTupleCols+`
		 ORDER BY r.domain, messages DESC, reports DESC`, args...); err != nil {
		return nil, err
	}

	out := []BIMIReadiness{}
	for _, r := range rows {
		// Rows are ordered by volume within each domain; the first is the one
		// most mail was judged against.
		if len(out) > 0 && out[len(out)-1].Domain == r.Domain {
			out[len(out)-1].Reports += r.Reports
			out[len(out)-1].Messages += r.Messages
			continue
		}
		eligible, blockers, notes := BIMIEligible(r.PolicyTuple)
		out = append(out, BIMIReadiness{
			Domain: r.Domain, Eligible: eligible, Known: true,
			Policy: r.PolicyTuple, Tags: r.PolicyTuple.Tags(),
			Blockers: blockers, Notes: notes,
			Reports: r.Reports, Messages: r.Messages,
		})
	}
	return out, nil
}

// GetBIMIReadinessFor is B10 for one domain. The result is never nil: a domain
// with no reports in the window is returned with Known false, because "we have
// not been told" must not render as "this domain fails".
func GetBIMIReadinessFor(db *sqlx.DB, domain string, f StatsFilter) (*BIMIReadiness, error) {
	f.Domain = domain
	all, err := GetBIMIReadiness(db, f)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Domain == domain {
			return &all[i], nil
		}
	}
	return &BIMIReadiness{Domain: domain}, nil
}

// GetDiscoveryMethod returns the policy-discovery method reporters declared
// most often for a domain ("psl" or "treewalk"), or "" when none ever said.
//
// It decides how the BIMI organizational-domain fallback resolves the parent
// domain: guessing wrong there means looking for the record in a place no
// receiver would look.
func GetDiscoveryMethod(db *sqlx.DB, domain string) (string, error) {
	var out []string
	err := db.Select(&out, `
		SELECT discovery_method FROM reports
		 WHERE domain = ? AND discovery_method != ''
		 GROUP BY discovery_method
		 ORDER BY COUNT(*) DESC, discovery_method
		 LIMIT 1`, strings.ToLower(strings.TrimSpace(domain)))
	if err != nil || len(out) == 0 {
		return "", err
	}
	return out[0], nil
}

// BIMIDomainState is one domain and selector's current assertion record as
// last observed — the inventory behind B1, B2 and B4.
type BIMIDomainState struct {
	Domain   string `json:"domain"`
	Selector string `json:"selector"`
	State    string `json:"state"`
	// Result is the parsed lookup as the Enrich run recorded it. It is decoded
	// from the snapshot's detail JSON, so a row written by an older version
	// degrades to an empty result rather than failing the page.
	Result    bimi.Result `json:"result"`
	Raw       string      `json:"raw"`
	Error     string      `json:"error,omitempty"`
	FirstSeen int64       `json:"first_seen"`
	LastSeen  int64       `json:"last_seen"`
	Checks    int64       `json:"checks"`
}

// Declined reports an explicit declination to publish (B4).
func (s BIMIDomainState) Declined() bool { return s.State == bimi.StateDeclined }

// Published reports a usable record.
func (s BIMIDomainState) Published() bool { return s.State == bimi.StatePublished }

// ListBIMIDomainStates returns the current assertion record of every domain
// and selector, decoded. An empty domain means every domain.
func ListBIMIDomainStates(db *sqlx.DB, domain string) ([]BIMIDomainState, error) {
	var snaps []BIMISnapshot
	var err error
	if domain == "" {
		snaps, err = ListCurrentBIMISnapshots(db, BIMISnapshotRecord)
	} else {
		snaps, err = currentBIMIRecordsFor(db, domain)
	}
	if err != nil {
		return nil, err
	}
	out := make([]BIMIDomainState, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, bimiStateFromSnapshot(s))
	}
	return out, nil
}

// GetBIMIDomainState returns one domain's default-selector record, or nil when
// the domain has never been looked up.
func GetBIMIDomainState(db *sqlx.DB, domain string) (*BIMIDomainState, error) {
	snap, err := GetCurrentBIMISnapshot(db, domain, bimi.DefaultSelector, BIMISnapshotRecord)
	if err != nil || snap == nil {
		return nil, err
	}
	state := bimiStateFromSnapshot(*snap)
	return &state, nil
}

// HasBIMIRecord reports whether the last observed lookup for a domain found an
// assertion record of any kind — published, declining, or published and
// broken. It is the boolean behind domain_checks.has_bimi, derived from the
// snapshots rather than from a lookup on the request path.
//
// A lookup that failed reports false and is indistinguishable here from a
// domain that publishes nothing; callers that care about the difference read
// the state instead.
func HasBIMIRecord(db *sqlx.DB, domain string) (bool, error) {
	state, err := GetBIMIDomainState(db, domain)
	if err != nil || state == nil {
		return false, err
	}
	return state.State != bimi.StateAbsent && state.State != bimi.StateError, nil
}

// currentBIMIRecordsFor returns the newest record snapshot per selector of one
// domain.
func currentBIMIRecordsFor(db *sqlx.DB, domain string) ([]BIMISnapshot, error) {
	return currentBIMISnapshotsFor(db, domain, BIMISnapshotRecord)
}

// currentBIMISnapshotsFor returns the newest snapshot of one kind per selector
// of one domain.
func currentBIMISnapshotsFor(db *sqlx.DB, domain, kind string) ([]BIMISnapshot, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	out := []BIMISnapshot{}
	err := db.Select(&out, `
		SELECT s.id, s.domain, s.selector, s.kind, s.content, s.detail, s.error,
		       s.first_seen, s.last_seen, s.checks
		  FROM bimi_snapshots s
		  JOIN (
		        SELECT selector, MAX(last_seen) AS last_seen
		          FROM bimi_snapshots WHERE domain = ? AND kind = ?
		         GROUP BY selector
		  ) latest ON latest.selector = s.selector AND latest.last_seen = s.last_seen
		 WHERE s.domain = ? AND s.kind = ?
		 ORDER BY CASE WHEN s.selector = 'default' THEN 0 ELSE 1 END, s.selector`,
		d, kind, d, kind)
	return out, err
}

// BIMIValidationState is the current result of the active checks (B6–B9) for
// one domain and selector, decoded from the indicator and evidence snapshots.
//
// Agreement is recomputed here rather than stored: it is a comparison of the
// two hashes beside it, and a stored copy could disagree with its own inputs.
type BIMIValidationState struct {
	Domain        string                `json:"domain"`
	Selector      string                `json:"selector"`
	Indicator     *bimi.IndicatorResult `json:"indicator,omitempty"`
	Evidence      *bimi.EvidenceResult  `json:"evidence,omitempty"`
	Agreement     bimi.AgreementResult  `json:"agreement"`
	IndicatorSeen int64                 `json:"indicator_seen,omitempty"`
	EvidenceSeen  int64                 `json:"evidence_seen,omitempty"`
}

// Checked reports whether the active checks have ever run for this selector.
// They are skipped for a domain that publishes no indicator, and switched off
// entirely by BIMI_VALIDATE=false, so absence here is not a failure.
func (v BIMIValidationState) Checked() bool { return v.Indicator != nil }

// Findings is every finding from both documents plus the agreement between
// them, which is what the domain page lists and the alert rules read.
func (v BIMIValidationState) Findings() []bimi.Finding {
	return bimi.Validation{Indicator: v.Indicator, Evidence: v.Evidence, Agreement: v.Agreement}.Findings()
}

// Valid reports that the active checks found nothing disqualifying.
func (v BIMIValidationState) Valid() bool {
	return bimi.Validation{Indicator: v.Indicator, Evidence: v.Evidence, Agreement: v.Agreement}.Valid()
}

// ListBIMIValidations returns the current active-check state per selector. An
// empty domain covers every domain.
func ListBIMIValidations(db *sqlx.DB, domain string) ([]BIMIValidationState, error) {
	indicators, err := bimiSnapshotsOfKind(db, domain, BIMISnapshotIndicator)
	if err != nil {
		return nil, err
	}
	evidence, err := bimiSnapshotsOfKind(db, domain, BIMISnapshotEvidence)
	if err != nil {
		return nil, err
	}

	byKey := map[string]*BIMIValidationState{}
	order := []string{}
	get := func(domain, selector string) *BIMIValidationState {
		key := domain + "\x00" + selector
		if v, ok := byKey[key]; ok {
			return v
		}
		v := &BIMIValidationState{Domain: domain, Selector: selector}
		byKey[key] = v
		order = append(order, key)
		return v
	}

	for _, s := range indicators {
		v := get(s.Domain, s.Selector)
		var res bimi.IndicatorResult
		if err := json.Unmarshal([]byte(s.Detail), &res); err != nil {
			continue // a blob written by an older build: skip rather than fail
		}
		v.Indicator = &res
		v.IndicatorSeen = s.LastSeen
	}
	for _, s := range evidence {
		v := get(s.Domain, s.Selector)
		var res bimi.EvidenceResult
		if err := json.Unmarshal([]byte(s.Detail), &res); err != nil {
			continue
		}
		v.Evidence = &res
		v.EvidenceSeen = s.LastSeen
	}

	out := make([]BIMIValidationState, 0, len(order))
	for _, key := range order {
		v := byKey[key]
		v.Agreement = bimi.CompareMarks(v.Indicator, v.Evidence)
		out = append(out, *v)
	}
	return out, nil
}

func bimiSnapshotsOfKind(db *sqlx.DB, domain, kind string) ([]BIMISnapshot, error) {
	if domain == "" {
		return ListCurrentBIMISnapshots(db, kind)
	}
	return currentBIMISnapshotsFor(db, domain, kind)
}

func bimiStateFromSnapshot(s BIMISnapshot) BIMIDomainState {
	out := BIMIDomainState{
		Domain: s.Domain, Selector: s.Selector, Raw: s.Content, Error: s.Error,
		FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Checks: s.Checks,
	}
	if s.Detail != "" {
		// A detail blob written by an older build may not decode; the snapshot
		// is still a fact worth showing, so the error is swallowed rather than
		// failing the caller.
		_ = json.Unmarshal([]byte(s.Detail), &out.Result)
	}
	out.State = out.Result.State
	if out.State == "" {
		switch {
		case s.Error != "":
			out.State = bimi.StateError
		case s.Content == "":
			out.State = bimi.StateAbsent
		default:
			out.State = bimi.ParseRRset([]string{s.Content}).State()
		}
	}
	return out
}

// BIMIRecordChange is one observed change of a domain's assertion record (B5,
// and the X20 alert). From is the state that was replaced.
type BIMIRecordChange struct {
	Domain   string `db:"domain" json:"domain"`
	Selector string `db:"selector" json:"selector"`
	At       int64  `db:"at" json:"at"`
	To       string `db:"content" json:"to"`
	ToError  string `db:"error" json:"to_error"`
	From     string `db:"prev_content" json:"from"`
	// PrevError is empty unless the previous observation was a failed lookup.
	FromError string `db:"prev_error" json:"from_error"`
}

// ListBIMIRecordChanges returns record changes first observed at or after
// since, newest first.
//
// The first observation of a domain is not a change and never appears here:
// there was no earlier state to move away from, and reporting one would make
// every newly added domain look like an incident.
func ListBIMIRecordChanges(db *sqlx.DB, since int64) ([]BIMIRecordChange, error) {
	out := []BIMIRecordChange{}
	err := db.Select(&out, `
		SELECT domain, selector, at, content, error, prev_content, prev_error FROM (
			SELECT domain, selector, first_seen AS at, content, error,
			       LAG(content) OVER w AS prev_content,
			       LAG(error)   OVER w AS prev_error
			  FROM bimi_snapshots
			 WHERE kind = ?
			WINDOW w AS (PARTITION BY domain, selector ORDER BY first_seen, id)
		)
		 WHERE at >= ? AND prev_content IS NOT NULL
		 ORDER BY at DESC, domain, selector`, BIMISnapshotRecord, since)
	return out, err
}

// BIMIReadinessBreakdown is the dashboard's BIMI card: every domain in one of
// four states, which is a different question from the "BIMI coverage" figure
// it replaces.
//
// That figure counted whether a record exists. A domain can publish a
// syntactically perfect record and never show a logo — because the policy does
// not qualify, or because the logo or certificate it points at is broken — and
// counting it as "configured" told the operator they were done when they were
// not.
type BIMIReadinessBreakdown struct {
	// NoRecord is domains publishing nothing, including those that decline.
	NoRecord int64 `json:"no_record"`
	// BlockedByPolicy is domains with a record whose DMARC policy stops any
	// receiver acting on it.
	BlockedByPolicy int64 `json:"blocked_by_policy"`
	// Valid is domains with a usable record whose documents, where they have
	// been checked, are healthy.
	Valid int64 `json:"valid"`
	// Broken is domains with a usable record whose indicator or evidence
	// document fails a check.
	Broken int64 `json:"broken"`
	// Declined counts the subset of NoRecord that declines deliberately, so
	// the UI can say so without giving it a slice of its own.
	Declined int64 `json:"declined"`
	// Unchecked counts domains whose record has never been looked up; they are
	// in NoRecord and must not be read as "publishes nothing".
	Unchecked int64 `json:"unchecked"`
	Total     int64 `json:"total"`
}

// GetBIMIReadinessBreakdown classifies every domain for the dashboard card.
func GetBIMIReadinessBreakdown(db *sqlx.DB, f StatsFilter) (*BIMIReadinessBreakdown, error) {
	domains, err := ListBIMIScopeDomains(db, f)
	if err != nil {
		return nil, err
	}
	readiness, err := GetBIMIReadiness(db, f)
	if err != nil {
		return nil, err
	}
	eligible := make(map[string]bool, len(readiness))
	known := make(map[string]bool, len(readiness))
	for _, r := range readiness {
		eligible[r.Domain] = r.Eligible
		known[r.Domain] = r.Known
	}

	states, err := ListBIMIDomainStates(db, "")
	if err != nil {
		return nil, err
	}
	// Only the default selector decides the dashboard's verdict: it governs
	// every message that does not name another, which is nearly all of them.
	byDomain := make(map[string]BIMIDomainState, len(states))
	for _, s := range states {
		if s.Selector == bimi.DefaultSelector {
			byDomain[s.Domain] = s
		}
	}

	validations, err := ListBIMIValidations(db, "")
	if err != nil {
		return nil, err
	}
	validByDomain := map[string]bool{}
	checkedByDomain := map[string]bool{}
	for _, v := range validations {
		if v.Selector != bimi.DefaultSelector || !v.Checked() {
			continue
		}
		checkedByDomain[v.Domain] = true
		validByDomain[v.Domain] = v.Valid()
	}

	out := &BIMIReadinessBreakdown{}
	for _, d := range domains {
		out.Total++
		state, looked := byDomain[d.Domain]
		switch {
		case !looked:
			out.NoRecord++
			out.Unchecked++
			continue
		case state.State == bimi.StateDeclined:
			out.NoRecord++
			out.Declined++
			continue
		case state.State != bimi.StatePublished:
			// Absent, unusable, or a lookup that failed: no logo either way.
			out.NoRecord++
			continue
		}
		// A record that publishes a logo, judged against its policy first —
		// a domain the policy disqualifies shows nothing however good the
		// logo is, so that is the more useful thing to say about it.
		if known[d.Domain] && !eligible[d.Domain] {
			out.BlockedByPolicy++
			continue
		}
		if checkedByDomain[d.Domain] && !validByDomain[d.Domain] {
			out.Broken++
			continue
		}
		out.Valid++
	}
	return out, nil
}

// BIMIScopeDomain is one domain the BIMI views cover, with the message volume
// it has in the window (0 for a managed domain nobody has reported on).
type BIMIScopeDomain struct {
	Domain   string `db:"domain" json:"domain"`
	Messages int64  `db:"messages" json:"messages"`
}

// ListBIMIScopeDomains returns every domain the BIMI views should cover: the
// domains reports name, plus every managed domain.
//
// The union matters here in a way it does not for the DMARC views. BIMI is
// about what a domain publishes, not about who has written to you about it: a
// managed domain that sends no mail yet can still have a logo and a
// certificate configured, and leaving it out would hide exactly the setup an
// operator is most likely to be checking.
func ListBIMIScopeDomains(db *sqlx.DB, f StatsFilter) ([]BIMIScopeDomain, error) {
	where, args := f.where()
	out := []BIMIScopeDomain{}
	err := db.Select(&out, `
		WITH reported AS (
			SELECT r.domain AS domain, COALESCE(SUM(rr.count), 0) AS messages
			  FROM reports r
			  JOIN record_rows rr ON rr.report_id = r.id`+where+`
			 GROUP BY r.domain
		)
		SELECT d.domain, COALESCE(rep.messages, 0) AS messages
		  FROM (
			SELECT domain FROM reported
			UNION
			SELECT domain FROM managed_domains
		  ) d
		  LEFT JOIN reported rep ON rep.domain = d.domain
		 WHERE d.domain != ''
		 ORDER BY messages DESC, d.domain`, args...)
	return out, err
}
