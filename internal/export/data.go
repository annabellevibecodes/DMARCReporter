package export

import (
	"fmt"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
	"github.com/jmoiron/sqlx"
)

// recordLimit caps the per-domain record listing in exports.
const recordLimit = 1000

// ReportData holds everything needed to render a management report.
type ReportData struct {
	GeneratedAt time.Time
	Domain      string // empty = all-domains report
	PeriodLabel string // human-readable reporting period ("1 Year", "All Time", …)
	Summary     Summary
	Domains     []database.DomainStat      // all domains, or one entry for per-domain
	TopSources  []database.FailureRateStat // top 10 failing source IPs
	Records     []database.DomainRecord    // per-domain only: recent records
	RecordLimit int                        // cap applied to Records

	// Analytics extension (appended sections; existing sections are unchanged).
	Matrix         *database.AuthMatrix          // C5
	Enforcement    *database.EnforcementStats    // C7
	PolicyTags     []string                      // P1 dominant record (per-domain report)
	DomainPolicies []DomainPolicy                // all-domains report: dominant effective record per domain
	ChangeLog      []database.PolicyChange       // P3 (per-domain report)
	NewSources     []database.SourceInventoryRow // S2 top 10
	OpenAlerts     []database.Alert
}

// DomainPolicy is one domain's dominant effective policy for the all-domains report.
type DomainPolicy struct {
	Domain string
	Tags   []string
}

// Summary holds top-level aggregate numbers.
type Summary struct {
	TotalMessages int64
	TotalPassed   int64
	TotalFailed   int64
	PassRate      float64
	DomainCount   int
}

// Options tunes the analytics sections.
type Options struct {
	PatternThresholds ipinfo.PatternThresholds
}

// Fetch loads report data from the database, scoped to the same period and
// domain filters the UI uses so the exported report matches what is on screen.
func Fetch(db *sqlx.DB, domain string, from, to int64, periodLabel string) (*ReportData, error) {
	return FetchWithOptions(db, domain, from, to, periodLabel, Options{PatternThresholds: ipinfo.DefaultPatternThresholds})
}

// FetchWithOptions is Fetch with explicit analytics options.
func FetchWithOptions(db *sqlx.DB, domain string, from, to int64, periodLabel string, opt Options) (*ReportData, error) {
	rd := &ReportData{
		GeneratedAt: time.Now().UTC(),
		Domain:      domain,
		PeriodLabel: periodLabel,
		RecordLimit: recordLimit,
	}

	f := database.StatsFilter{Domain: domain, From: from, To: to}
	domains, err := database.ListDomainsFiltered(db, f)
	if err != nil {
		return nil, err
	}
	rd.Domains = domains
	rd.Summary.DomainCount = len(domains)
	for _, d := range domains {
		rd.Summary.TotalMessages += d.TotalMessages
		rd.Summary.TotalPassed += d.Passed
		rd.Summary.TotalFailed += d.Failed
	}

	if domain != "" {
		records, err := database.GetDomainRecords(db, domain, from, recordLimit)
		if err != nil {
			return nil, err
		}
		rd.Records = records
	}

	if rd.Summary.TotalMessages > 0 {
		rd.Summary.PassRate = float64(rd.Summary.TotalPassed) / float64(rd.Summary.TotalMessages) * 100
	}

	sources, err := database.GetTopFailingSources(db, 1, 10, f)
	if err != nil {
		return nil, err
	}
	rd.TopSources = sources

	// Analytics sections.
	if rd.Matrix, err = database.GetAuthMatrix(db, f); err != nil {
		return nil, err
	}
	if rd.Enforcement, err = database.GetEnforcementEffectiveness(db, f); err != nil {
		return nil, err
	}
	if domain != "" {
		ap, err := database.GetActivePolicyTuple(db, f)
		if err != nil {
			return nil, err
		}
		rd.PolicyTags = ap.Tags
		if rd.ChangeLog, err = database.GetPolicyChangeLog(db, domain, 20); err != nil {
			return nil, err
		}
	} else {
		for _, d := range domains {
			ap, err := database.GetActivePolicyTuple(db, database.StatsFilter{Domain: d.Domain, From: from, To: to})
			if err != nil {
				return nil, err
			}
			if ap.Effective != nil {
				rd.DomainPolicies = append(rd.DomainPolicies, DomainPolicy{Domain: d.Domain, Tags: ap.Effective.Tags()})
			}
		}
	}
	th := opt.PatternThresholds
	if th.HealthyMin == 0 {
		th = ipinfo.DefaultPatternThresholds
	}
	if rd.NewSources, err = database.GetNewSources(db, f, th, 10); err != nil {
		return nil, err
	}
	if rd.OpenAlerts, err = database.ListAlerts(db, "open", domain, 50); err != nil {
		return nil, err
	}
	return rd, nil
}

// analyticsKV renders the matrix and enforcement blocks as label/value rows,
// shared by every export format.
func analyticsKV(rd *ReportData) (matrix, enforcement [][2]string) {
	if rd.Matrix != nil {
		m := rd.Matrix
		matrix = [][2]string{
			{"Both aligned (DKIM + SPF)", fmt.Sprintf("%d (%.1f%%)", m.BothPass, m.Share(m.BothPass))},
			{"DKIM only", fmt.Sprintf("%d (%.1f%%)", m.DKIMOnlyPass, m.Share(m.DKIMOnlyPass))},
			{"SPF only", fmt.Sprintf("%d (%.1f%%)", m.SPFOnlyPass, m.Share(m.SPFOnlyPass))},
			{"Neither", fmt.Sprintf("%d (%.1f%%)", m.BothFail, m.Share(m.BothFail))},
		}
	}
	if rd.Enforcement != nil {
		e := rd.Enforcement
		policy := e.Policy
		if policy == "" {
			policy = "n/a"
		}
		rate := "n/a (policy is none)"
		if e.Rate != nil {
			rate = fmt.Sprintf("%.1f%%", *e.Rate)
		} else if e.Policy != "" && e.Policy != "none" {
			rate = "n/a (no failing mail)"
		}
		enforcement = [][2]string{
			{"Published policy (dominant)", policy},
			{"Failing messages", fmt.Sprintf("%d", e.Failing)},
			{"Enforced (quarantine + reject)", fmt.Sprintf("%d", e.Enforced)},
			{"Enforcement effectiveness", rate},
		}
	}
	return matrix, enforcement
}

// changeLogRows renders the policy change log as table rows.
func changeLogRows(rd *ReportData) [][]string {
	rows := make([][]string, 0, len(rd.ChangeLog))
	for _, ch := range rd.ChangeLog {
		diff := ""
		for i, d := range ch.Diff {
			if i > 0 {
				diff += "; "
			}
			diff += d.Field + ": " + d.From + " -> " + d.To
		}
		before, after := "n/a", "n/a"
		if ch.PassRateBefore >= 0 {
			before = fmt.Sprintf("%.1f%%", ch.PassRateBefore)
		}
		if ch.PassRateAfter >= 0 {
			after = fmt.Sprintf("%.1f%%", ch.PassRateAfter)
		}
		rows = append(rows, []string{
			time.Unix(ch.At, 0).UTC().Format("2006-01-02"), diff, joinStrings(ch.Reporters, ", "), before, after,
		})
	}
	return rows
}

// newSourceRows renders the top new sources.
func newSourceRows(rd *ReportData) [][]string {
	rows := make([][]string, 0, len(rd.NewSources))
	for _, s := range rd.NewSources {
		label := s.Label
		if label == "" {
			label = s.Provider
		}
		rows = append(rows, []string{
			s.SourceIP, label, ipinfo.PatternLabel(s.Pattern),
			fmt.Sprintf("%d", s.TotalMessages), fmt.Sprintf("%.1f%%", s.PassRate),
			time.Unix(s.FirstSeen, 0).UTC().Format("2006-01-02"),
		})
	}
	return rows
}

// alertRows renders open alerts.
func alertRows(rd *ReportData) [][]string {
	rows := make([][]string, 0, len(rd.OpenAlerts))
	for _, a := range rd.OpenAlerts {
		rows = append(rows, []string{
			a.Severity, a.Rule, a.Domain, a.Message,
			time.Unix(a.FirstFired, 0).UTC().Format("2006-01-02"),
			time.Unix(a.LastFired, 0).UTC().Format("2006-01-02"),
			fmt.Sprintf("%d", a.Count),
		})
	}
	return rows
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

var (
	changeLogHeaders = []string{"Date", "Change", "Reporters", "Pass rate 7d before", "Pass rate 7d after"}
	newSourceHeaders = []string{"Source IP", "Label / Provider", "Pattern", "Messages", "Pass Rate", "First Seen"}
	alertHeaders     = []string{"Severity", "Rule", "Domain", "Message", "First Fired", "Last Fired", "Count"}
)
