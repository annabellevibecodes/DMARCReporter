package handlers

import (
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// HandleTLSRPTList renders the SMTP TLS reports (RFC 8460) page.
func (a *App) HandleTLSRPTList(c *fiber.Ctx) error {
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

	flashKind, flashMsg := getFlash(c)
	return c.Render("tlsrpt", fiber.Map{
		"Title":          "TLS Reports — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "tlsrpt",
		"Reports":        reports,
		"Summary":        summary,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"IMAPEnabled":    a.FetchEnabled(),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}

// HandleReportsTLSRPTList renders the TLS-RPT tab nested under /reports,
// listing TLS reports in their own table — never merged with DMARC reports.
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

	flashKind, flashMsg := getFlash(c)
	return c.Render("reports_tlsrpt", fiber.Map{
		"Title":          "TLS-RPT Reports — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "reports",
		"ReportsTab":     "tlsrpt",
		"Reports":        reports,
		"Summary":        summary,
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
