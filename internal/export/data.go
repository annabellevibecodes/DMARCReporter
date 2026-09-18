package export

import (
	"fmt"
	"strings"
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

	// SMTP TLS reporting (RFC 8460). TLSRate is nil when the period holds no
	// TLS sessions, which the renderers show as "no reports" rather than as
	// a zero rate — the same distinction the health score draws.
	TLSRate      *database.TLSRate
	TLSPrevRate  *database.TLSRate
	TLSPolicyMix *database.TLSPolicyMix
	TLSFailures  *database.TLSFailureBreakdown
	TLSReceivers *database.TLSReceivers
	TLSReadiness *database.TLSEnforcementReadiness
	TLSHygiene   *database.TLSHygiene
	TLSAlerts    []database.Alert // open alerts raised by the TLS rules
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
	// TLSRequireDKIM mirrors TLSRPT_REQUIRE_DKIM so the exported TLS figures
	// match the ones on screen. Fetch defaults it to true, as the setting does.
	TLSRequireDKIM bool
}

// Fetch loads report data from the database, scoped to the same period and
// domain filters the UI uses so the exported report matches what is on screen.
func Fetch(db *sqlx.DB, domain string, from, to int64, periodLabel string) (*ReportData, error) {
	return FetchWithOptions(db, domain, from, to, periodLabel, Options{
		PatternThresholds: ipinfo.DefaultPatternThresholds,
		TLSRequireDKIM:    true,
	})
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
	for _, al := range rd.OpenAlerts {
		if strings.HasPrefix(al.Rule, "tls_") {
			rd.TLSAlerts = append(rd.TLSAlerts, al)
		}
	}

	if err := fetchTLS(db, rd, domain, from, to, opt.TLSRequireDKIM); err != nil {
		return nil, err
	}
	return rd, nil
}

// fetchTLS loads the TLS section. A period with no TLS sessions leaves
// TLSRate nil, and every renderer then says so instead of printing zeros
// that would read as "all sessions failed".
func fetchTLS(db *sqlx.DB, rd *ReportData, domain string, from, to int64, requireDKIM bool) error {
	tf := database.TLSFilter{Domain: domain, From: from, To: to, RequireDKIM: requireDKIM}

	rate, err := database.GetTLSRate(db, tf)
	if err != nil {
		return err
	}
	if rate.Total == 0 {
		return nil
	}
	rd.TLSRate = rate

	if prev, ok := tf.PreviousWindow(); ok {
		prevRate, err := database.GetTLSRate(db, prev)
		if err != nil {
			return err
		}
		if prevRate.Total > 0 {
			rd.TLSPrevRate = prevRate
		}
	}
	if rd.TLSPolicyMix, err = database.GetTLSPolicyMix(db, tf); err != nil {
		return err
	}
	if rd.TLSFailures, err = database.GetTLSFailureBreakdown(db, tf); err != nil {
		return err
	}
	if rd.TLSReceivers, err = database.GetTLSReceivers(db, tf, 10); err != nil {
		return err
	}
	if rd.TLSReadiness, err = database.GetTLSEnforcementReadiness(db, tf); err != nil {
		return err
	}
	if rd.TLSHygiene, err = database.GetTLSHygiene(db, tf); err != nil {
		return err
	}
	return nil
}

// TLSDelta returns the change in TLS success rate against the preceding
// window, and whether there was one to compare against.
func (rd *ReportData) TLSDelta() (float64, bool) {
	if rd.TLSRate == nil || rd.TLSPrevRate == nil {
		return 0, false
	}
	return rd.TLSRate.Rate - rd.TLSPrevRate.Rate, true
}

// tlsSummaryKV renders the TLS headline as label/value rows (T1, T9, T13).
func tlsSummaryKV(rd *ReportData) [][2]string {
	if rd.TLSRate == nil {
		return nil
	}
	rows := [][2]string{
		{"TLS success rate (T1)", fmt.Sprintf("%.1f%%", rd.TLSRate.Rate)},
		{"Sessions", fmt.Sprintf("%d (%d successful, %d failed)", rd.TLSRate.Total, rd.TLSRate.Success, rd.TLSRate.Failure)},
	}
	if delta, ok := rd.TLSDelta(); ok {
		rows = append(rows, [2]string{"Change vs previous period",
			fmt.Sprintf("%+.1f points (was %.1f%%)", delta, rd.TLSPrevRate.Rate)})
	}
	if r := rd.TLSReadiness; r != nil && r.TestingSessions > 0 {
		rows = append(rows, [2]string{"MTA-STS enforcement readiness (T9)",
			fmt.Sprintf("%d session(s) would have been blocked in enforce, of %d in testing",
				r.WouldBlock, r.TestingSessions)})
	}
	if h := rd.TLSHygiene; h != nil && h.Excluded > 0 {
		rows = append(rows, [2]string{"Reports excluded (unsigned, RFC 8460 §3)",
			fmt.Sprintf("%d", h.Excluded)})
	}
	return rows
}

// Column headers for the TLS tables, shared by every format.
var (
	tlsPolicyHeaders   = []string{"Policy Type", "Sessions", "Share"}
	tlsFailureHeaders  = []string{"Result Type", "Group", "Sessions", "Share"}
	tlsReceiverHeaders = []string{"MX Host", "Nodes", "Failed Sessions", "Result Types"}
	tlsAlertHeaders    = []string{"Rule", "Severity", "Domain", "Message"}
)

// tlsPolicyRows renders the policy-type mix (T3).
func tlsPolicyRows(rd *ReportData) [][]string {
	if rd.TLSPolicyMix == nil {
		return nil
	}
	rows := make([][]string, 0, len(rd.TLSPolicyMix.Overall))
	for _, p := range rd.TLSPolicyMix.Overall {
		rows = append(rows, []string{
			escapeFormula(p.PolicyType),
			fmt.Sprintf("%d", p.Sessions),
			fmt.Sprintf("%.1f%%", p.Share),
		})
	}
	return rows
}

// tlsFailureRows renders failures by result type (T4).
func tlsFailureRows(rd *ReportData) [][]string {
	if rd.TLSFailures == nil {
		return nil
	}
	rows := make([][]string, 0, len(rd.TLSFailures.Types))
	for _, f := range rd.TLSFailures.Types {
		rows = append(rows, []string{
			escapeFormula(f.ResultType),
			escapeFormula(f.Group),
			fmt.Sprintf("%d", f.FailedSessions),
			fmt.Sprintf("%.1f%%", f.Share),
		})
	}
	return rows
}

// tlsReceiverRows renders the top failing receivers (T5).
func tlsReceiverRows(rd *ReportData) [][]string {
	if rd.TLSReceivers == nil {
		return nil
	}
	rows := make([][]string, 0, len(rd.TLSReceivers.ByHost))
	for _, r := range rd.TLSReceivers.ByHost {
		rows = append(rows, []string{
			escapeFormula(r.MXHostname),
			fmt.Sprintf("%d", r.DistinctIPs),
			fmt.Sprintf("%d", r.FailedSessions),
			escapeFormula(r.ResultTypes),
		})
	}
	return rows
}

// tlsAlertRows renders the open TLS alerts.
func tlsAlertRows(rd *ReportData) [][]string {
	rows := make([][]string, 0, len(rd.TLSAlerts))
	for _, al := range rd.TLSAlerts {
		rows = append(rows, []string{
			escapeFormula(al.Rule),
			escapeFormula(al.Severity),
			escapeFormula(al.Domain),
			escapeFormula(al.Message),
		})
	}
	return rows
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
