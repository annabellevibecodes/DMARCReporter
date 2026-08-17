package handlers

import "github.com/gofiber/fiber/v2"

// HandleHelpPage renders the Help reference page.
func (a *App) HandleHelpPage(c *fiber.Ctx) error {
	return c.Render("help", fiber.Map{
		"Title":       "Help — DMARC Reporter",
		"Theme":       getTheme(c),
		"ActivePage":  "help",
		"IMAPEnabled": a.FetchEnabled(),
		"CSRFToken":   c.Locals("csrf"),
	}, "layouts/base")
}
