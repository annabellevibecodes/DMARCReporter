package handlers

import (
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// reporterHygiene is the R4–R7 block.
type reporterHygiene struct {
	Anomalies    []database.DateRangeAnomaly      `json:"date_range_anomalies"`
	AnomalyCount int                              `json:"date_range_anomaly_count"`
	Duplicates   int64                            `json:"duplicates"`
	ParseErrors  int64                            `json:"parse_errors"`
	Rejected     int64                            `json:"rejected"`
	Imported     int64                            `json:"imported"`
	RecentErrors []database.IngestEvent           `json:"recent_errors"`
	Schema       []database.SchemaDistributionRow `json:"schema"`
	Unmanaged    []database.UnmanagedDomain       `json:"unmanaged_domains"`
	IngestSince  int64                            `json:"ingest_since"`
}

// reportersPayload is R1–R8 in one response.
type reportersPayload struct {
	Reporters    []database.ReporterInventoryRow `json:"reporters"` // R1 (+R2/R3 columns)
	Gaps         []database.ReporterGap          `json:"gaps"`      // R2
	Presence     []database.ReporterPresence     `json:"presence"`  // R2 heat map
	PresenceDays int                             `json:"presence_days"`
	Latency      []database.ReporterLatency      `json:"latency"`    // R3
	Hygiene      reporterHygiene                 `json:"hygiene"`    // R4–R7
	Recipients   []database.EnvelopeToStat       `json:"recipients"` // R8
	Managed      []database.ManagedDomain        `json:"managed_domains"`
	GapDays      int                             `json:"gap_days"`
}

// computeReporters gathers R1–R8 for f.
func (a *App) computeReporters(f database.StatsFilter) (*reportersPayload, error) {
	f.Compare = false
	p := &reportersPayload{GapDays: a.Cfg.AlertReporterGapDays}
	if p.GapDays <= 0 {
		p.GapDays = 3
	}
	var err error
	if p.Reporters, err = database.GetReporterInventory(a.DB, f); err != nil {
		return nil, err
	}
	if p.Gaps, err = database.GetReporterGaps(a.DB, 14, p.GapDays); err != nil {
		return nil, err
	}
	p.PresenceDays = 30
	if f.From > 0 {
		days := int((time.Now().Unix()-f.From)/86400) + 1
		if days < 7 {
			days = 7
		}
		if days > 60 {
			days = 60
		}
		p.PresenceDays = days
	}
	if p.Presence, err = database.GetReporterPresence(a.DB, p.PresenceDays); err != nil {
		return nil, err
	}
	if p.Latency, err = database.GetReportLatency(a.DB, f); err != nil {
		return nil, err
	}

	// Fold R2/R3 into the R1 rows for the table.
	gapByOrg := map[string]database.ReporterGap{}
	for _, g := range p.Gaps {
		gapByOrg[g.OrgName] = g
	}
	presByOrg := map[string][]int{}
	for _, pr := range p.Presence {
		presByOrg[pr.OrgName] = pr.Days
	}
	latByOrg := map[string]database.ReporterLatency{}
	for _, l := range p.Latency {
		latByOrg[l.OrgName] = l
	}
	now := time.Now().UTC()
	for i := range p.Reporters {
		r := &p.Reporters[i]
		if r.LastReport > 0 {
			r.DaysSilent = int(now.Sub(time.Unix(r.LastReport, 0)).Hours() / 24)
		}
		if _, ok := gapByOrg[r.OrgName]; ok {
			r.Gap = true
		}
		r.Presence = presByOrg[r.OrgName]
		if l, ok := latByOrg[r.OrgName]; ok {
			r.LatencyMedian, r.LatencyP95, r.LatencyN = l.MedianHours, l.P95Hours, l.Samples
		}
	}

	h := &p.Hygiene
	if h.Anomalies, h.AnomalyCount, err = database.GetDateRangeAnomalies(a.DB, f, 25); err != nil {
		return nil, err
	}
	h.IngestSince = f.From
	counts, err := database.CountIngestEvents(a.DB, f.From)
	if err != nil {
		return nil, err
	}
	for _, c := range counts {
		switch c.Status {
		case database.IngestStatusDuplicate:
			h.Duplicates += c.Count
		case database.IngestStatusParseError:
			h.ParseErrors += c.Count
		case database.IngestStatusRejected:
			h.Rejected += c.Count
		case database.IngestStatusOK:
			h.Imported += c.Count
		}
	}
	if h.RecentErrors, err = database.ListIngestEvents(a.DB, database.IngestStatusParseError, f.From, 10); err != nil {
		return nil, err
	}
	if h.Schema, err = database.GetSchemaDistribution(a.DB, f); err != nil {
		return nil, err
	}
	if h.Unmanaged, err = database.GetUnmanagedDomains(a.DB, f); err != nil {
		return nil, err
	}
	if p.Recipients, err = database.GetEnvelopeToStats(a.DB, f, 25); err != nil {
		return nil, err
	}
	if p.Managed, err = database.ListManagedDomains(a.DB); err != nil {
		return nil, err
	}
	if p.Reporters == nil {
		p.Reporters = []database.ReporterInventoryRow{}
	}
	if p.Gaps == nil {
		p.Gaps = []database.ReporterGap{}
	}
	if p.Latency == nil {
		p.Latency = []database.ReporterLatency{}
	}
	if p.Recipients == nil {
		p.Recipients = []database.EnvelopeToStat{}
	}
	if p.Hygiene.Unmanaged == nil {
		p.Hygiene.Unmanaged = []database.UnmanagedDomain{}
	}
	if p.Hygiene.Schema == nil {
		p.Hygiene.Schema = []database.SchemaDistributionRow{}
	}
	if p.Managed == nil {
		p.Managed = []database.ManagedDomain{}
	}
	return p, nil
}

// HandleReportersPage renders /reporters.
func (a *App) HandleReportersPage(c *fiber.Ctx) error {
	period := c.Query("period", "30d")
	from, to, periodLabel := parsePeriod(period)
	domain := c.Query("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	f := database.StatsFilter{From: from, To: to, Domain: domain}
	p, err := a.computeReporters(f)
	if err != nil {
		return err
	}
	domains, err := database.ListReportDomains(a.DB)
	if err != nil {
		return err
	}
	flashKind, flashMsg := getFlash(c)
	return c.Render("reporters", fiber.Map{
		"Title":          "Reporters — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "reporters",
		"R":              p,
		"Domains":        domains,
		"SelectedDomain": domain,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"CurrentPath":    c.OriginalURL(),
		"IMAPEnabled":    a.FetchEnabled(),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}

// HandleAPIReporters serves /api/reporters.
func (a *App) HandleAPIReporters(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	p, err := a.computeReporters(f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window":    windowFor(f, c.Query("period")),
		"reporters": p,
	})
}

func validManagedDomain(d string) (string, bool) {
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" || len(d) > 253 || !domainRe.MatchString(d) {
		return "", false
	}
	return d, true
}

func redirectOrJSON(a *App, c *fiber.Ctx, flash string, payload fiber.Map) error {
	if redirect := c.FormValue("redirect"); safeRedirect(redirect) {
		a.setFlash(c, "success", flash)
		return c.Redirect(redirect, fiber.StatusSeeOther)
	}
	return c.JSON(payload)
}

// HandleAPIManagedDomainAdd handles POST /api/managed-domains {domain}.
func (a *App) HandleAPIManagedDomainAdd(c *fiber.Ctx) error {
	d, ok := validManagedDomain(c.FormValue("domain"))
	if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "invalid domain")
	}
	if err := database.AddManagedDomain(a.DB, d); err != nil {
		return err
	}
	return redirectOrJSON(a, c, "Added "+d+" to managed domains.", fiber.Map{"domain": d, "managed": true})
}

// HandleAPIManagedDomainDelete handles DELETE /api/managed-domains {domain}
// and POST /api/managed-domains/delete (HTML forms cannot send DELETE).
func (a *App) HandleAPIManagedDomainDelete(c *fiber.Ctx) error {
	d, ok := validManagedDomain(c.FormValue("domain"))
	if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "invalid domain")
	}
	if err := database.RemoveManagedDomain(a.DB, d); err != nil {
		return err
	}
	return redirectOrJSON(a, c, "Removed "+d+" from managed domains.", fiber.Map{"domain": d, "managed": false})
}

// HandleAPIManagedDomainsList handles GET /api/managed-domains.
func (a *App) HandleAPIManagedDomainsList(c *fiber.Ctx) error {
	list, err := database.ListManagedDomains(a.DB)
	if err != nil {
		return err
	}
	if list == nil {
		list = []database.ManagedDomain{}
	}
	return c.JSON(fiber.Map{"managed_domains": list})
}
