package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

// PeriodOption is one choice in the reporting-period selector.
type PeriodOption struct {
	Value string
	Label string
}

var periodOptions = []PeriodOption{
	{"all", "All Time"},
	{"2y", "2 Years"},
	{"1y", "1 Year"},
	{"6m", "6 Months"},
	{"3m", "3 Months"},
	{"lm", "Last Month"},
	{"30d", "Last 30 Days"},
	{"14d", "Last 14 Days"},
	{"7d", "Last 7 Days"},
	{"3d", "Last 3 Days"},
	{"2d", "Last 2 Days"},
	{"24h", "Last 24 Hours"},
}

// validPeriod reports whether p is one of the period selector keys.
func validPeriod(p string) bool {
	for _, o := range periodOptions {
		if o.Value == p {
			return true
		}
	}
	return false
}

// parsePeriod converts a period string into from/to Unix timestamps and a display label.
func parsePeriod(p string) (from, to int64, label string) {
	now := time.Now().UTC()
	switch p {
	case "all":
		return 0, 0, "All Time"
	case "2y":
		return now.AddDate(-2, 0, 0).Unix(), 0, "2 Years"
	case "1y":
		return now.AddDate(-1, 0, 0).Unix(), 0, "1 Year"
	case "6m":
		return now.AddDate(0, -6, 0).Unix(), 0, "6 Months"
	case "3m":
		return now.AddDate(0, -3, 0).Unix(), 0, "3 Months"
	case "lm":
		firstOfThisMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		firstOfLastMonth := firstOfThisMonth.AddDate(0, -1, 0)
		return firstOfLastMonth.Unix(), firstOfThisMonth.Unix() - 1, "Last Month"
	case "30d":
		return now.AddDate(0, 0, -30).Unix(), 0, "Last 30 Days"
	case "14d":
		return now.AddDate(0, 0, -14).Unix(), 0, "Last 14 Days"
	case "7d":
		return now.AddDate(0, 0, -7).Unix(), 0, "Last 7 Days"
	case "3d":
		return now.AddDate(0, 0, -3).Unix(), 0, "Last 3 Days"
	case "2d":
		return now.AddDate(0, 0, -2).Unix(), 0, "Last 2 Days"
	case "24h":
		return now.Add(-24 * time.Hour).Unix(), 0, "Last 24 Hours"
	default:
		return now.AddDate(-1, 0, 0).Unix(), 0, "1 Year"
	}
}

func (a *App) HandleDashboard(c *fiber.Ctx) error {
	envelopeFrom := c.Query("ef")
	period := c.Query("period", "1y")

	from, to, periodLabel := parsePeriod(period)
	f := database.StatsFilter{EnvelopeFrom: envelopeFrom, From: from, To: to, Compare: true}

	stats, err := database.GetDashboardStats(a.DB, f)
	if err != nil {
		return err
	}

	trendDaily := database.TrendDaily(from)
	trend, err := database.GetTrendData(a.DB, f, trendDaily)
	if err != nil {
		return err
	}
	trend = database.FillTrendGaps(trend, from, to, trendDaily)

	// Analytics blocks (C1–C8, S2): current window plus the preceding window
	// of equal length for the KPI deltas.
	ov, err := database.WithComparison(f, func(sf database.StatsFilter) (*overviewMetrics, error) {
		return a.computeOverview(sf)
	})
	if err != nil {
		return err
	}
	var prevOverview *overviewMetrics
	if ov.Previous != nil {
		prevOverview = *ov.Previous
	}
	delta := computeDelta(ov.Current, prevOverview)
	kpis := buildKPIs(ov.Current, delta, trend)
	compareLabel := ""
	if prevOverview != nil {
		compareLabel = "vs the preceding " + periodLength(from, to)
	}
	attention := a.buildAttention(ov.Current, f)
	sourcesQuery := "period=" + url.QueryEscape(period)
	if envelopeFrom != "" {
		sourcesQuery += "&envelope_from=" + url.QueryEscape(envelopeFrom)
	}

	failureModes, err := database.GetFailureModeBreakdown(a.DB, f)
	if err != nil {
		return err
	}

	topFailing, err := database.GetTopFailingSources(a.DB, 1, 10, f)
	if err != nil {
		return err
	}
	for i := range topFailing {
		topFailing[i].Provider = ipinfo.ProviderFromRDNS(topFailing[i].RDNS)
	}

	topByVolume, err := database.GetTopSourcesByVolume(a.DB, 10, f)
	if err != nil {
		return err
	}
	for i := range topByVolume {
		topByVolume[i].Provider = ipinfo.ProviderFromRDNS(topByVolume[i].RDNS)
	}

	geoDistribution, err := database.GetGeoDistribution(a.DB, 15, f)
	if err != nil {
		return err
	}

	policyBreakdown, err := database.GetDomainPolicyBreakdown(a.DB, f)
	if err != nil {
		return err
	}

	domainsAtRisk, err := database.GetDomainsAtRisk(a.DB, 95.0, f)
	if err != nil {
		return err
	}

	policyOverrides, err := database.GetPolicyOverrideBreakdown(a.DB, f)
	if err != nil {
		return err
	}

	recentReports, _, err := database.ListReports(a.DB, database.ReportFilter{Page: 1, PageSize: 5})
	if err != nil {
		return err
	}

	efDomains, err := database.ListEnvelopeFromDomains(a.DB)
	if err != nil {
		return err
	}

	// BIMI / MTA-STS coverage: use cached domain_checks; fall back to live lookup
	// (and cache the result) for any domain not yet checked.
	allDomains, err := database.ListDomains(a.DB)
	if err != nil {
		return err
	}
	domainCheckCache, err := database.GetAllDomainChecks(a.DB)
	if err != nil {
		return err
	}
	// Build top-5 domain list by message volume for the blue theme subtitle.
	sortedDomains := make([]database.DomainStat, len(allDomains))
	copy(sortedDomains, allDomains)
	sort.Slice(sortedDomains, func(i, j int) bool {
		return sortedDomains[i].TotalMessages > sortedDomains[j].TotalMessages
	})
	topDomains := make([]string, 0, 5)
	for i, d := range sortedDomains {
		if i >= 5 {
			break
		}
		topDomains = append(topDomains, d.Domain)
	}

	// Cache-only: the background refresher (StartDomainCheckRefresher) keeps
	// domain_checks fresh, so the dashboard never blocks on live DNS lookups.
	var domainTotal, mtaStsConfigured int
	for _, d := range allDomains {
		domainTotal++
		if dc, ok := domainCheckCache[d.Domain]; ok && dc.HasMTASTS == 1 {
			mtaStsConfigured++
		}
	}
	mtaStsNotConfigured := domainTotal - mtaStsConfigured

	type trendPayload struct {
		Labels []string `json:"labels"`
		Passed []int64  `json:"passed"`
		Failed []int64  `json:"failed"`
	}
	td := trendPayload{}
	for _, pt := range trend {
		td.Labels = append(td.Labels, pt.Week)
		td.Passed = append(td.Passed, pt.Passed)
		td.Failed = append(td.Failed, pt.Failed)
	}
	trendBytes, err := json.Marshal(td)
	if err != nil {
		return err
	}

	type fmPayload struct {
		Labels []string `json:"labels"`
		Values []int64  `json:"values"`
	}
	fmData := fmPayload{
		Labels: []string{"DKIM only pass", "SPF only pass", "Both fail"},
		Values: []int64{failureModes.DKIMOnlyPass, failureModes.SPFOnlyPass, failureModes.BothFail},
	}
	fmBytes, err := json.Marshal(fmData)
	if err != nil {
		return err
	}

	policy, err := database.GetActivePolicy(a.DB, f)
	if err != nil {
		return err
	}

	// Build policy pie chart payload (all three slices always present).
	type piePayload struct {
		Labels []string `json:"labels"`
		Values []int64  `json:"values"`
	}
	policyMap := map[string]int64{"none": 0, "quarantine": 0, "reject": 0}
	for _, pb := range policyBreakdown {
		policyMap[pb.Policy] = pb.DomainCount
	}
	policyPie := piePayload{
		Labels: []string{"none", "quarantine", "reject"},
		Values: []int64{policyMap["none"], policyMap["quarantine"], policyMap["reject"]},
	}
	policyPieBytes, err := json.Marshal(policyPie)
	if err != nil {
		return err
	}

	// BIMI readiness (B10 and B6–B9), not record existence: a domain can
	// publish a perfect record and still never show a logo, and the old
	// "configured" figure told the operator they were done when they were not.
	bimiBreakdown, err := database.GetBIMIReadinessBreakdown(a.DB, f)
	if err != nil {
		return err
	}
	bimiPie := piePayload{
		Labels: []string{"Logo shows", "Blocked by policy", "Logo or evidence broken", "No record"},
		Values: []int64{
			bimiBreakdown.Valid, bimiBreakdown.BlockedByPolicy,
			bimiBreakdown.Broken, bimiBreakdown.NoRecord,
		},
	}
	bimiPieBytes, err := json.Marshal(bimiPie)
	if err != nil {
		return err
	}

	mtaStsPie := piePayload{
		Labels: []string{"Configured", "Not configured"},
		Values: []int64{int64(mtaStsConfigured), int64(mtaStsNotConfigured)},
	}
	mtaStsPieBytes, err := json.Marshal(mtaStsPie)
	if err != nil {
		return err
	}

	theme := getTheme(c)

	flashKind, flashMsg := getFlash(c)
	layout := "layouts/base"
	if theme == "pink" || theme == "blue" || theme == "goth" {
		layout = "layouts/base_bare"
	}
	return c.Render("dashboard_"+theme, fiber.Map{
		"Title":             "Dashboard — DMARC Reporter",
		"Theme":             theme,
		"Stats":             stats,
		"Policy":            policy,
		"TopFailingSources": topFailing,
		"TopByVolume":       topByVolume,
		"GeoDistribution":   geoDistribution,
		"DomainsAtRisk":     domainsAtRisk,
		"PolicyOverrides":   policyOverrides,
		"RecentReports":     recentReports,
		"TrendData":         template.JS(trendBytes),
		"FailureModeData":   template.JS(fmBytes),
		"PolicyPieData":     template.JS(policyPieBytes),
		"BIMIPieData":       template.JS(bimiPieBytes),
		"BIMIReadiness":     bimiBreakdown,
		"MTASTSPieData":     template.JS(mtaStsPieBytes),
		"TopDomains":        topDomains,
		"MoreDomains":       len(allDomains) > 5,
		"EFDomains":         efDomains,
		"SelectedEF":        envelopeFrom,
		"PeriodOptions":     periodOptions,
		"SelectedPeriod":    period,
		"PeriodLabel":       periodLabel,
		"IMAPEnabled":       a.FetchEnabled(),
		"FlashKind":         flashKind,
		"FlashMsg":          flashMsg,
		"CSRFToken":         c.Locals("csrf"),
		// Analytics blocks
		"Overview":     ov.Current,
		"OverviewPrev": prevOverview,
		"Delta":        delta,
		"KPIs":         kpis,
		"CompareLabel": compareLabel,
		"Attention":    attention,
		"SourcesQuery": template.URL(sourcesQuery),
		"AlertsLink":   "/alerts?state=open",
		"HealthKPI":    a.healthKPIFor("", f),
	}, layout)
}

// periodLength describes the window length for the comparison label.
func periodLength(from, to int64) string {
	if from <= 0 {
		return "period"
	}
	end := to
	if end <= 0 {
		end = time.Now().Unix()
	}
	days := int((end - from + 43200) / 86400)
	switch {
	case days <= 1:
		return "24 hours"
	case days < 60:
		return fmt.Sprintf("%d days", days)
	case days < 400:
		return fmt.Sprintf("%d months", int(float64(days)/30.4+0.5))
	}
	return fmt.Sprintf("%d years", int(float64(days)/365+0.5))
}

// buildAttention assembles the "needs attention" items from the overview
// (new sources, unexplained overrides, override volume). Later phases prepend
// open alerts via attentionExtras.
func (a *App) buildAttention(ov *overviewMetrics, f database.StatsFilter) []attentionItem {
	var items []attentionItem
	if attentionExtras != nil {
		items = append(items, attentionExtras(a, f)...)
	}
	if ov.Matrix.Neither > 0 && ov.Matrix.NeitherPct >= 5 {
		items = append(items, attentionItem{
			Severity: "warning",
			Title:    fmt.Sprintf("%s messages (%.1f%%) failed both aligned checks", commaN(ov.Matrix.Neither), ov.Matrix.NeitherPct),
			Sub:      "Unauthenticated mail claiming your domains — misconfigured senders or spoofing",
			Tag:      "C5", Href: "/sources?matrix=neither&period=" + url.QueryEscape(periodFromFilter(f)),
		})
	}
	if ov.NewSources > 0 {
		sub := "sending IPs seen for the first time in this period"
		if n := len(ov.NewSourceList); n > 0 {
			top := ov.NewSourceList[0]
			label := top.SourceIP
			if top.Label != "" {
				label = top.Label
			} else if top.Provider != "" {
				label = top.SourceIP + " (" + top.Provider + ")"
			}
			sub = fmt.Sprintf("largest: %s with %s messages · %s", label, commaN(top.TotalMessages), ipinfo.PatternLabel(top.Pattern))
		}
		items = append(items, attentionItem{
			Severity: "info",
			Title:    fmt.Sprintf("%d new source%s this period", ov.NewSources, plural(ov.NewSources)),
			Sub:      sub,
			Tag:      "S2", Href: "/sources?new=1&period=" + url.QueryEscape(periodFromFilter(f)),
		})
	}
	if ov.UnexplainedOverrides != nil && ov.UnexplainedOverrides.Records > 0 {
		items = append(items, attentionItem{
			Severity: "warning",
			Title:    fmt.Sprintf("%s failing messages delivered against policy without a reason", commaN(ov.UnexplainedOverrides.Messages)),
			Sub:      "Receivers reported a disposition weaker than your published p= and gave no <reason>",
			Tag:      "C8",
		})
	}
	if ov.OverrideMessages > 0 {
		items = append(items, attentionItem{
			Severity: "info",
			Title:    fmt.Sprintf("%s policy overrides applied", commaN(ov.OverrideMessages)),
			Sub:      "\"Forgiven failures\" — messages a reporter delivered despite a DMARC fail",
			Tag:      "C8",
		})
	}
	if len(items) > 8 {
		items = items[:8]
	}
	return items
}

// attentionExtras is set by later phases to prepend open alerts.
var attentionExtras func(a *App, f database.StatsFilter) []attentionItem

// periodFromFilter recovers the closest period key for links (best effort).
func periodFromFilter(f database.StatsFilter) string {
	if f.From <= 0 {
		return "all"
	}
	days := int((time.Now().Unix() - f.From + 43200) / 86400)
	switch {
	case days <= 1:
		return "24h"
	case days <= 2:
		return "2d"
	case days <= 3:
		return "3d"
	case days <= 7:
		return "7d"
	case days <= 14:
		return "14d"
	case days <= 31:
		return "30d"
	case days <= 93:
		return "3m"
	case days <= 185:
		return "6m"
	case days <= 370:
		return "1y"
	}
	return "2y"
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
