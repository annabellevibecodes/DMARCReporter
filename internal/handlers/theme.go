package handlers

import "github.com/gofiber/fiber/v2"

var validThemes = map[string]bool{"pink": true, "blue": true, "goth": true}

// getTheme reads the ui_theme cookie and returns a validated theme name.
func getTheme(c *fiber.Ctx) string {
	t := c.Cookies("ui_theme", "goth")
	if !validThemes[t] {
		return "goth"
	}
	return t
}

// HandleSetTheme sets the ui_theme cookie and redirects back to the referrer.
func (a *App) HandleSetTheme(c *fiber.Ctx) error {
	t := c.Query("t")
	if !validThemes[t] {
		t = "goth"
	}
	c.Cookie(&fiber.Cookie{
		Name:     "ui_theme",
		Value:    t,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HTTPOnly: false,
		SameSite: "Lax",
	})
	ref := c.Get("Referer", "/")
	return c.Redirect(ref, fiber.StatusSeeOther)
}
