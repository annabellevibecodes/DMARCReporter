package handlers

import (
	"github.com/gofiber/fiber/v2"
)

// HandleFetch starts a background fetch run across all enabled accounts.
func (a *App) HandleFetch(c *fiber.Ctx) error {
	if !a.FetchEnabled() {
		a.setFlash(c, "error", "No mail accounts configured. Add one under Accounts.")
		return c.Redirect("/accounts")
	}

	if a.Worker.TriggerAll() {
		a.setFlash(c, "info", "Fetch started in the background — results appear under Accounts and Reports shortly.")
	} else {
		a.setFlash(c, "info", "A fetch is already running.")
	}
	return c.Redirect("/accounts")
}
