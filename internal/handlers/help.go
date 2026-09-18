package handlers

import "github.com/gofiber/fiber/v2"

// helpSection is one Help sub-page. Slug is the URL segment ("" = /help) and
// Template is the view rendered for it.
type helpSection struct {
	Slug     string
	Title    string
	Template string
	Blurb    string
}

// helpSections lists the Help sub-pages in navigation order.
var helpSections = []helpSection{
	{
		Slug: "", Title: "Email authentication", Template: "help",
		Blurb: "How SPF, DKIM and DMARC work, what alignment means, and what receivers do with mail that fails.",
	},
	{
		Slug: "standards", Title: "Related standards", Template: "help_standards",
		Blurb: "The adjacent standards this application also reads: BIMI, MTA-STS and SMTP TLS reporting.",
	},
	{
		Slug: "metrics", Title: "Metric reference", Template: "help_metrics",
		Blurb: "Every metric identifier used in the interface: what it measures, how it is derived, and where to find it.",
	},
	{
		Slug: "alerts", Title: "Alerts & health", Template: "help_alerts",
		Blurb: "The alert rule table with its thresholds, and how the 0–100 health score is calculated.",
	},
	{
		Slug: "app", Title: "Using the app", Template: "help_app",
		Blurb: "Fetching reports from mailboxes, enriching source data, and how to read what the pages show.",
	},
}

func helpSectionBySlug(slug string) *helpSection {
	for i := range helpSections {
		if helpSections[i].Slug == slug {
			return &helpSections[i]
		}
	}
	return nil
}

// HandleHelpPage renders one Help sub-page. The section comes from the URL
// path; an unknown section is a 404 rather than a silent fallback.
func (a *App) HandleHelpPage(c *fiber.Ctx) error {
	sec := helpSectionBySlug(c.Params("section"))
	if sec == nil {
		return fiber.ErrNotFound
	}
	return c.Render(sec.Template, fiber.Map{
		"Title":        sec.Title + " — Help — DMARC Reporter",
		"Theme":        getTheme(c),
		"ActivePage":   "help",
		"HelpSections": helpSections,
		"HelpSection":  sec.Slug,
		"HelpTitle":    sec.Title,
		"HelpBlurb":    sec.Blurb,
		"IMAPEnabled":  a.FetchEnabled(),
		"CSRFToken":    c.Locals("csrf"),
	}, "layouts/base")
}
