package handlers

import (
	"encoding/json"
	"html/template"
	"sort"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
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
	default:
		return now.AddDate(-1, 0, 0).Unix(), 0, "1 Year"
	}
}

func (a *App) HandleDashboard(c *fiber.Ctx) error {
	envelopeFrom := c.Query("ef")
	period := c.Query("period", "1y")

	from, to, periodLabel := parsePeriod(period)
	f := database.StatsFilter{EnvelopeFrom: envelopeFrom, From: from, To: to}

	stats, err := database.GetDashboardStats(a.DB, f)
	if err != nil {
		return err
	}

	trend, err := database.GetTrendData(a.DB, f)
	if err != nil {
		return err
	}

	failureModes, err := database.GetFailureModeBreakdown(a.DB, f)
	if err != nil {
		return err
	}

	topFailing, err := database.GetTopFailingSources(a.DB, 1, 10, f)
	if err != nil {
		return err
	}

	topByVolume, err := database.GetTopSourcesByVolume(a.DB, 10, f)
	if err != nil {
		return err
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

	var bimiConfigured, bimiTotal, mtaStsConfigured int
	now := time.Now()
	for _, d := range allDomains {
		bimiTotal++
		dc, cached := domainCheckCache[d.Domain]
		if !cached || dc.CheckedAt == 0 || now.Sub(time.Unix(dc.CheckedAt, 0)) > domainCheckTTL {
			dc = database.DomainCheck{
				Domain:    d.Domain,
				HasDMARC:  boolToInt(lookupDMARCRecord(d.Domain).Found),
				HasBIMI:   boolToInt(lookupBIMI(d.Domain).Found),
				HasMTASTS: boolToInt(lookupMTASTS(d.Domain).Found),
				CheckedAt: now.Unix(),
			}
			_ = database.UpsertDomainCheck(a.DB, dc)
		}
		if dc.HasBIMI == 1 {
			bimiConfigured++
		}
		if dc.HasMTASTS == 1 {
			mtaStsConfigured++
		}
	}
	bimiNotConfigured := bimiTotal - bimiConfigured
	mtaStsNotConfigured := bimiTotal - mtaStsConfigured

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

	bimiPie := piePayload{
		Labels: []string{"Configured", "Not configured"},
		Values: []int64{int64(bimiConfigured), int64(bimiNotConfigured)},
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
		"RecentReports":     recentReports,
		"TrendData":         template.JS(trendBytes),
		"FailureModeData":   template.JS(fmBytes),
		"PolicyPieData":     template.JS(policyPieBytes),
		"BIMIPieData":       template.JS(bimiPieBytes),
		"MTASTSPieData":     template.JS(mtaStsPieBytes),
		"TopDomains":        topDomains,
		"MoreDomains":       len(allDomains) > 5,
		"EFDomains":         efDomains,
		"SelectedEF":        envelopeFrom,
		"PeriodOptions":     periodOptions,
		"SelectedPeriod":    period,
		"PeriodLabel":       periodLabel,
		"IMAPEnabled":       a.Cfg.IMAPHost != "",
		"FlashKind":         flashKind,
		"FlashMsg":          flashMsg,
		"CSRFToken":         c.Locals("csrf"),
	}, layout)
}
