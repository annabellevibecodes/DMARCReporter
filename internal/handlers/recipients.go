package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

func (a *App) HandleRecipientDetail(c *fiber.Ctx) error {
	domain := c.Params("domain")
	if domain == "" || len(domain) > 253 || !domainRe.MatchString(domain) {
		return fiber.ErrBadRequest
	}

	records, err := database.GetRecipientRecords(a.DB, domain, 200)
	if err != nil {
		return err
	}

	senders, err := database.GetRecipientSenderBreakdown(a.DB, domain, 50)
	if err != nil {
		return err
	}

	// Compute summary from records.
	var totalMsgs, totalPassed, totalFailed int
	uniqueIPs := map[string]struct{}{}
	uniqueSenders := map[string]struct{}{}
	for _, r := range records {
		totalMsgs += r.Count
		if r.EvalDKIM == "pass" || r.EvalSPF == "pass" {
			totalPassed += r.Count
		} else {
			totalFailed += r.Count
		}
		uniqueIPs[r.SourceIP] = struct{}{}
		if r.HeaderFrom != "" {
			uniqueSenders[r.HeaderFrom] = struct{}{}
		}
	}
	var passRate float64
	if totalMsgs > 0 {
		passRate = float64(totalPassed) / float64(totalMsgs) * 100
	}

	return c.Render("recipient_detail", fiber.Map{
		"Title":          domain + " (recipient) — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "domains",
		"Domain":         domain,
		"Senders":        senders,
		"Records":        records,
		"TotalMessages":  totalMsgs,
		"TotalPassed":    totalPassed,
		"TotalFailed":    totalFailed,
		"PassRate":       passRate,
		"UniqueIPs":      len(uniqueIPs),
		"UniqueSenders":  len(uniqueSenders),
		"IMAPEnabled":    a.Cfg.IMAPHost != "",
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}
