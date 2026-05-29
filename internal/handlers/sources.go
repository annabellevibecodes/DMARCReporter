package handlers

import (
	"net"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

const sourcesPageSize = 100

type sourceSummary struct {
	SourceIP      string
	TotalMessages int64
	Passed        int64
	Failed        int64
	FailRatePct   float64
}

func (a *App) HandleSourcesList(c *fiber.Ctx) error {
	envelopeFrom := strings.TrimSpace(c.Query("envelope_from"))
	disposition := c.Query("disposition")
	if disposition != "quarantine" && disposition != "reject" {
		disposition = ""
	}
	country := strings.TrimSpace(c.Query("country"))
	sourceIP := strings.TrimSpace(c.Query("ip"))
	page, _ := strconv.Atoi(c.Query("page", "1"))
	period := c.Query("period", "1y")
	from, _, periodLabel := parsePeriod(period)
	minMessages, _ := strconv.Atoi(c.Query("min", "1"))
	if minMessages < 1 {
		minMessages = 1
	}
	if minMessages > 1_000_000 {
		minMessages = 1_000_000
	}

	sortBy := c.Query("sort", "fail_rate")
	sortDir := c.Query("dir", "desc")
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}

	sources, total, err := database.ListSources(a.DB, page, sourcesPageSize, envelopeFrom, disposition, country, sourceIP, from, minMessages, sortBy, sortDir)
	if err != nil {
		return err
	}

	envelopeFromDomains, err := database.ListEnvelopeFromDomains(a.DB)
	if err != nil {
		return err
	}
	rows := make([]sourceSummary, len(sources))
	for i, s := range sources {
		var fr float64
		if s.TotalMessages > 0 {
			fr = float64(s.Failed) / float64(s.TotalMessages) * 100
		}
		rows[i] = sourceSummary{
			SourceIP:      s.SourceIP,
			TotalMessages: s.TotalMessages,
			Passed:        s.Passed,
			Failed:        s.Failed,
			FailRatePct:   fr,
		}
	}
	totalPages := (total + sourcesPageSize - 1) / sourcesPageSize
	return c.Render("sources", fiber.Map{
		"PageNums":            pageWindow(page, totalPages),
		"Title":               "Sources — DMARC Reporter",
		"Theme":               getTheme(c),
		"ActivePage":          "sources",
		"Sources":             rows,
		"EnvelopeFrom":        envelopeFrom,
		"EnvelopeFromDomains": envelopeFromDomains,
		"Disposition":         disposition,
		"Country":             country,
		"SourceIP":            sourceIP,
		"Page":                page,
		"TotalPages":          totalPages,
		"Total":               total,
		"PeriodOptions":       periodOptions,
		"SelectedPeriod":      period,
		"PeriodLabel":         periodLabel,
		"MinMessages":         minMessages,
		"SortBy":              sortBy,
		"SortDir":             sortDir,
		"IMAPEnabled":         a.Cfg.IMAPHost != "",
		"CSRFToken":           c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleSourceDetail(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if net.ParseIP(ip) == nil {
		return fiber.ErrBadRequest
	}

	period := c.Query("period", "1y")
	from, _, periodLabel := parsePeriod(period)

	records, err := database.GetSourceRecords(a.DB, ip, from, 100)
	if err != nil {
		return err
	}

	agg, err := database.GetSourceAggStats(a.DB, ip, from)
	if err != nil {
		return err
	}

	// Resolve rDNS + WHOIS (served from cache; live lookup on first visit).
	ipInfo, _ := ipinfo.Get(a.DB, ip)

	return c.Render("source_detail", fiber.Map{
		"Title":          ip + " — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "sources",
		"IP":             ip,
		"IPInfo":         ipInfo,
		"Records":        records,
		"TotalMessages":  agg.TotalMessages,
		"TotalPassed":    agg.Passed,
		"TotalFailed":    agg.Failed,
		"PassRate":       agg.PassRate,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"IMAPEnabled":    a.Cfg.IMAPHost != "",
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}
