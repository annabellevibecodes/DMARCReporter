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

	sources, total, err := database.ListSources(a.DB, page, sourcesPageSize, envelopeFrom, disposition, country, sourceIP)
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
		"PageNums": pageWindow(page, totalPages),
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
		"IMAPEnabled":         a.Cfg.IMAPHost != "",
		"CSRFToken":           c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleSourceDetail(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if net.ParseIP(ip) == nil {
		return fiber.ErrBadRequest
	}

	records, err := database.GetSourceRecords(a.DB, ip, 100)
	if err != nil {
		return err
	}

	var totalMsgs, totalPassed, totalFailed int
	for _, r := range records {
		totalMsgs += r.Count
		if r.EvalDKIM == "pass" || r.EvalSPF == "pass" {
			totalPassed += r.Count
		} else {
			totalFailed += r.Count
		}
	}
	var passRate float64
	if totalMsgs > 0 {
		passRate = float64(totalPassed) / float64(totalMsgs) * 100
	}

	// Resolve rDNS + WHOIS (served from cache; live lookup on first visit).
	ipInfo, _ := ipinfo.Get(a.DB, ip)

	return c.Render("source_detail", fiber.Map{
		"Title":         ip + " — DMARC Reporter",
		"Theme":         getTheme(c),
		"ActivePage":    "sources",
		"IP":            ip,
		"IPInfo":        ipInfo,
		"Records":       records,
		"TotalMessages": totalMsgs,
		"TotalPassed":   totalPassed,
		"TotalFailed":   totalFailed,
		"PassRate":      passRate,
		"IMAPEnabled":   a.Cfg.IMAPHost != "",
		"CSRFToken":     c.Locals("csrf"),
	}, "layouts/base")
}
