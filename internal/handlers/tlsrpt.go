package handlers

import (
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// tlsPayload is T1–T15 in one response, computed once and shared by the page
// and (from phase 4) /api/tls.
type tlsPayload struct {
	Rate     *database.TLSRate        `json:"rate"`      // T1
	ByDomain []database.TLSDomainRate `json:"by_domain"` // T1 per domain
	// RateDelta is the change in percentage points against the preceding
	// window of equal length; nil when no comparison was requested or the
	// window is unbounded.
	RateDelta *float64          `json:"rate_delta"`
	PrevRate  *database.TLSRate `json:"previous_rate"`

	Volume     *database.TLSVolume               `json:"volume"`            // T2
	PolicyMix  *database.TLSPolicyMix            `json:"policy_mix"`        // T3
	Failures   *database.TLSFailureBreakdown     `json:"failures"`          // T4
	Receivers  *database.TLSReceivers            `json:"receivers"`         // T5
	Senders    *database.TLSSenders              `json:"senders"`           // T6
	Reasons    *database.TLSReasons              `json:"reasons"`           // T7
	Divergence []database.TLSPolicyDivergence    `json:"policy_divergence"` // T8
	Drift      []database.TLSDrift               `json:"policy_drift"`      // T8 vs published
	Readiness  *database.TLSEnforcementReadiness `json:"readiness"`         // T9
	Endpoint   *database.TLSEndpointHealth       `json:"endpoint_health"`   // T10
	Dane       []database.TLSDaneRow             `json:"dane"`              // T11
	Coverage   *database.TLSCoverage             `json:"coverage"`          // T12
	Hygiene    *database.TLSHygiene              `json:"hygiene"`           // T13
	Family     *database.TLSFamilySplit          `json:"family"`            // T14
	Incidents  []database.TLSIncident            `json:"incidents"`         // T15

	// Rollup is the session total with the multi-policy collapse applied,
	// alongside how many reports needed it.
	Rollup *database.TLSTotals `json:"rollup"`
}

// computeTLS gathers the whole T-series for f.
func (a *App) computeTLS(f database.TLSFilter) (*tlsPayload, error) {
	p := &tlsPayload{}
	var err error

	cmp, err := database.TLSWithComparison(f, func(sf database.TLSFilter) (*database.TLSRate, error) {
		return database.GetTLSRate(a.DB, sf)
	})
	if err != nil {
		return nil, err
	}
	p.Rate = cmp.Current
	if cmp.Previous != nil {
		p.PrevRate = *cmp.Previous
		// Only a previous window with traffic makes the delta meaningful:
		// "up 97 points" from an empty window says nothing.
		if p.PrevRate.Total > 0 && p.Rate.Total > 0 {
			d := p.Rate.Rate - p.PrevRate.Rate
			p.RateDelta = &d
		}
	}

	if p.ByDomain, err = database.GetTLSRateByDomain(a.DB, f); err != nil {
		return nil, err
	}
	if p.Volume, err = database.GetTLSVolume(a.DB, f); err != nil {
		return nil, err
	}
	if p.PolicyMix, err = database.GetTLSPolicyMix(a.DB, f); err != nil {
		return nil, err
	}
	if p.Failures, err = database.GetTLSFailureBreakdown(a.DB, f); err != nil {
		return nil, err
	}
	if p.Receivers, err = database.GetTLSReceivers(a.DB, f, 50); err != nil {
		return nil, err
	}
	if p.Senders, err = database.GetTLSSenders(a.DB, f, 50); err != nil {
		return nil, err
	}
	if p.Reasons, err = database.GetTLSReasons(a.DB, f, 25); err != nil {
		return nil, err
	}
	if p.Divergence, err = database.GetTLSPolicyDivergence(a.DB, f); err != nil {
		return nil, err
	}
	if p.Drift, err = database.GetTLSPolicyDrift(a.DB, f); err != nil {
		return nil, err
	}
	if p.Readiness, err = database.GetTLSEnforcementReadiness(a.DB, f); err != nil {
		return nil, err
	}
	if p.Endpoint, err = database.GetTLSEndpointHealth(a.DB, f); err != nil {
		return nil, err
	}
	if p.Dane, err = database.GetTLSDaneHealth(a.DB, f); err != nil {
		return nil, err
	}
	gapDays := a.Cfg.AlertReporterGapDays
	if gapDays <= 0 {
		gapDays = 3
	}
	if p.Coverage, err = database.GetTLSCoverage(a.DB, f, gapDays, time.Now().UTC()); err != nil {
		return nil, err
	}
	if p.Hygiene, err = database.GetTLSHygiene(a.DB, f); err != nil {
		return nil, err
	}
	if p.Family, err = database.GetTLSFamilySplit(a.DB, f); err != nil {
		return nil, err
	}
	if p.Incidents, err = database.GetTLSIncidents(a.DB, f, time.Now().UTC()); err != nil {
		return nil, err
	}
	if p.Rollup, err = database.TLSSessionTotals(a.DB, f.From); err != nil {
		return nil, err
	}

	if p.Divergence == nil {
		p.Divergence = []database.TLSPolicyDivergence{}
	}
	if p.Drift == nil {
		p.Drift = []database.TLSDrift{}
	}
	if p.Dane == nil {
		p.Dane = []database.TLSDaneRow{}
	}
	if p.Incidents == nil {
		p.Incidents = []database.TLSIncident{}
	}
	if p.ByDomain == nil {
		p.ByDomain = []database.TLSDomainRate{}
	}
	return p, nil
}

// tlsFilterFromQuery reads the period, domain and drill-down parameters.
func (a *App) tlsFilterFromQuery(c *fiber.Ctx) (database.TLSFilter, string, string, error) {
	period := c.Query("period", "30d")
	from, to, periodLabel := parsePeriod(period)

	f := database.TLSFilter{
		From: from, To: to, Compare: true,
		RequireDKIM: a.Cfg.TLSRPTRequireDKIM,
	}

	domain := strings.ToLower(strings.TrimSpace(c.Query("domain")))
	if domain != "" {
		if len(domain) > 253 || !domainRe.MatchString(domain) {
			return f, period, periodLabel, fiber.ErrBadRequest
		}
		f.Domain = domain
	}
	mx := strings.ToLower(strings.TrimSpace(c.Query("mx")))
	if mx != "" {
		if len(mx) > 253 || !domainRe.MatchString(mx) {
			return f, period, periodLabel, fiber.ErrBadRequest
		}
		f.MXHostname = mx
	}
	if rip := strings.TrimSpace(c.Query("rip")); rip != "" {
		if len(rip) > 45 {
			return f, period, periodLabel, fiber.ErrBadRequest
		}
		f.ReceivingIP = rip
	}
	return f, period, periodLabel, nil
}

// sortTLSDomains applies the table's sort parameters. Sorting here rather
// than in SQL keeps one query serving every column ordering.
func sortTLSDomains(rows []database.TLSDomainRate, by, dir string) {
	less := func(i, j int) bool { return rows[i].Failure > rows[j].Failure }
	switch by {
	case "domain":
		less = func(i, j int) bool { return rows[i].PolicyDomain < rows[j].PolicyDomain }
	case "sessions":
		less = func(i, j int) bool { return rows[i].Total > rows[j].Total }
	case "rate":
		less = func(i, j int) bool { return rows[i].Rate < rows[j].Rate }
	}
	sort.SliceStable(rows, less)
	if dir == "asc" {
		reverseAny(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	}
}

// sortTLSReceivers applies the receiver table's sort parameters.
func sortTLSReceivers(rows []database.TLSReceiverRow, by, dir string) {
	less := func(i, j int) bool { return rows[i].FailedSessions > rows[j].FailedSessions }
	switch by {
	case "host":
		less = func(i, j int) bool { return rows[i].MXHostname < rows[j].MXHostname }
	case "ips":
		less = func(i, j int) bool { return rows[i].DistinctIPs > rows[j].DistinctIPs }
	}
	sort.SliceStable(rows, less)
	if dir == "asc" {
		reverseAny(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	}
}

// reverseAny reverses n elements using the caller's swap.
func reverseAny(n int, swap func(i, j int)) {
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

// HandleTLSRPTList renders /tlsrpt: the T-series for the selected window.
func (a *App) HandleTLSRPTList(c *fiber.Ctx) error {
	f, period, periodLabel, err := a.tlsFilterFromQuery(c)
	if err != nil {
		return err
	}

	p, err := a.computeTLS(f)
	if err != nil {
		return err
	}

	sortBy, sortDir := c.Query("sort", ""), c.Query("dir", "desc")
	sortTLSDomains(p.ByDomain, sortBy, sortDir)
	sortTLSReceivers(p.Receivers.ByHost, sortBy, sortDir)

	// Newest first for the page: at a 3-month period the chronological
	// series buries the days anyone is looking for under weeks of quiet
	// ones. The payload itself stays chronological for the API and exports.
	daysDesc := make([]database.TLSDayPoint, len(p.Volume.ByDay))
	for i, d := range p.Volume.ByDay {
		daysDesc[len(daysDesc)-1-i] = d
	}

	// The report list stays on the page; the full list lives under /reports.
	reports, err := database.ListTLSRPT(a.DB, f.From, 25)
	if err != nil {
		return err
	}
	domains, err := database.ListTLSRPTDomains(a.DB)
	if err != nil {
		return err
	}

	base := url.Values{}
	base.Set("period", period)
	if f.Domain != "" {
		base.Set("domain", f.Domain)
	}
	if f.MXHostname != "" {
		base.Set("mx", f.MXHostname)
	}
	if f.ReceivingIP != "" {
		base.Set("rip", f.ReceivingIP)
	}

	var active []activeFilter
	addActive := func(key, value, label string) {
		if value == "" {
			return
		}
		active = append(active, activeFilter{Label: label, Href: chipHref("/tlsrpt", base, key, "")})
	}
	addActive("domain", f.Domain, "domain: "+f.Domain)
	addActive("mx", f.MXHostname, "MX host: "+f.MXHostname)
	addActive("rip", f.ReceivingIP, "receiving IP: "+f.ReceivingIP)

	flashKind, flashMsg := getFlash(c)
	return c.Render("tlsrpt", fiber.Map{
		"Title":          "TLS Reports — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "tlsrpt",
		"T":              p,
		"DaysDesc":       daysDesc,
		"Reports":        reports,
		"Domains":        domains,
		"SelectedDomain": f.Domain,
		"MXHost":         f.MXHostname,
		"ReceivingIP":    f.ReceivingIP,
		// DrillDown says whether a filter is in play that only failure-level
		// figures can honour, so the page can label what it did and did not
		// narrow instead of leaving the reader to guess.
		"DrillDown":      f.MXHostname != "" || f.ReceivingIP != "",
		"ActiveFilters":  active,
		"ClearAllHref":   template.URL("/tlsrpt?period=" + url.QueryEscape(period)),
		"BaseQuery":      template.URL(base.Encode()),
		"SortBy":         sortBy,
		"SortDir":        sortDir,
		"RequireDKIM":    a.Cfg.TLSRPTRequireDKIM,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"CurrentPath":    currentPath(c),
		"IMAPEnabled":    a.FetchEnabled(),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}

// tlsPolicyView is one policy of a report, with its failure rows attached.
type tlsPolicyView struct {
	database.TLSRPTPolicyRow
	MXPatterns []string
	Lines      []string
	Failures   []database.TLSRPTFailureRow
}

// HandleTLSRPTDetail renders one TLS report exactly as its reporter sent it:
// every policy entry (never the collapsed rollup), its parsed MTA-STS body,
// and the full failure-detail table.
func (a *App) HandleTLSRPTDetail(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	report, err := database.GetTLSRPT(a.DB, id)
	if err != nil {
		return err
	}
	if report == nil {
		return fiber.ErrNotFound
	}
	policies, err := database.ListTLSRPTPolicies(a.DB, id)
	if err != nil {
		return err
	}

	views := make([]tlsPolicyView, 0, len(policies))
	var totalFailures int64
	for _, p := range policies {
		v := tlsPolicyView{TLSRPTPolicyRow: p}
		if p.MXHostPattern != "" {
			v.MXPatterns = strings.Split(p.MXHostPattern, ",")
		}
		v.Lines = database.TLSPolicyStringLines(p.PolicyString)
		if v.Failures, err = database.ListTLSRPTFailures(a.DB, p.ID); err != nil {
			return err
		}
		for _, fr := range v.Failures {
			totalFailures += fr.FailedSessionCount
		}
		views = append(views, v)
	}

	flashKind, flashMsg := getFlash(c)
	return c.Render("tlsrpt_detail", fiber.Map{
		"Title":         "TLS report " + report.ReportID + " — DMARC Reporter",
		"Theme":         getTheme(c),
		"ActivePage":    "tlsrpt",
		"Report":        report,
		"Policies":      views,
		"DetailTotal":   totalFailures,
		"Transport":     database.TLSRPTTransportOrUnknown(report.Transport),
		"Counted":       database.TLSRPTCounted(report.Transport, report.DKIMStatus, a.Cfg.TLSRPTRequireDKIM),
		"RequireDKIM":   a.Cfg.TLSRPTRequireDKIM,
		"WindowSeconds": report.DateRangeEnd - report.DateRangeBegin,
		"IMAPEnabled":   a.FetchEnabled(),
		"FlashKind":     flashKind,
		"FlashMsg":      flashMsg,
		"CSRFToken":     c.Locals("csrf"),
	}, "layouts/base")
}

// HandleReportsTLSRPTList renders the TLS-RPT tab nested under /reports,
// listing TLS reports in their own table — never merged with DMARC reports.
//
// This is the raw report list, the counterpart of /reports/dmarc; /tlsrpt is
// the analysis. Both link to the same per-report detail view.
func (a *App) HandleReportsTLSRPTList(c *fiber.Ctx) error {
	period := c.Query("period", "3m")
	from, _, periodLabel := parsePeriod(period)

	reports, err := database.ListTLSRPT(a.DB, from, 200)
	if err != nil {
		return err
	}
	summary, err := database.GetTLSRPTSummary(a.DB, from)
	if err != nil {
		return err
	}
	rollup, err := database.TLSSessionTotals(a.DB, from)
	if err != nil {
		return err
	}

	flashKind, flashMsg := getFlash(c)
	return c.Render("reports_tlsrpt", fiber.Map{
		"Title":          "TLS-RPT Reports — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "reports",
		"ReportsTab":     "tlsrpt",
		"Reports":        reports,
		"Summary":        summary,
		"Rollup":         rollup,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"IMAPEnabled":    a.FetchEnabled(),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}

// HandleTLSRPTReportJSON serves a TLS-RPT report's original raw JSON, as stored.
func (a *App) HandleTLSRPTReportJSON(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	rawJSON, err := database.GetTLSRPTJSON(a.DB, id)
	if err != nil {
		return err
	}
	if rawJSON == "" {
		return fiber.ErrNotFound
	}
	c.Set("Content-Type", "application/json; charset=utf-8")
	c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="tlsrpt-%d.json"`, id))
	return c.SendString(rawJSON)
}
