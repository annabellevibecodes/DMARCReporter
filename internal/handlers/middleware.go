package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
)

// App holds shared dependencies for all handlers.
type App struct {
	DB  *sqlx.DB
	Cfg config.Config
}

// ErrorHandler renders the error page for unhandled errors.
func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "Internal Server Error"

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
		msg = e.Message
	}

	// Provide the minimum template context required by layouts/base so the
	// nav renders correctly (CSRF token blank is intentional on error pages).
	return c.Status(code).Render("error", fiber.Map{
		"Code":        code,
		"Message":     msg,
		"Theme":       getTheme(c),
		"ActivePage":  "",
		"IMAPEnabled": false,
		"CSRFToken":   c.Locals("csrf"),
	}, "layouts/base")
}

var validFlashKinds = map[string]bool{
	"success": true,
	"error":   true,
	"warning": true,
	"info":    true,
}

func validFlashKind(kind string) bool { return validFlashKinds[kind] }

// pageWindow returns a slice of page numbers centred on page, extending up to
// 5 pages in each direction, clamped to [1, totalPages].
func pageWindow(page, totalPages int) []int {
	const radius = 5
	start := page - radius
	if start < 1 {
		start = 1
	}
	end := page + radius
	if end > totalPages {
		end = totalPages
	}
	pages := make([]int, end-start+1)
	for i := range pages {
		pages[i] = start + i
	}
	return pages
}

// setFlash stores a flash message in response cookies.
func (a *App) setFlash(c *fiber.Ctx, kind, msg string) {
	if !validFlashKind(kind) {
		kind = "info"
	}
	base := fiber.Cookie{
		HTTPOnly: true,
		Secure:   a.Cfg.SecureCookies,
		SameSite: "Lax",
		Path:     "/",
	}
	kc := base
	kc.Name = "flash_kind"
	kc.Value = kind
	c.Cookie(&kc)

	mc := base
	mc.Name = "flash_msg"
	mc.Value = msg
	c.Cookie(&mc)
}

// getFlash reads and clears the flash cookies.
func getFlash(c *fiber.Ctx) (kind, msg string) {
	kind = c.Cookies("flash_kind")
	msg = c.Cookies("flash_msg")
	if !validFlashKind(kind) {
		kind = ""
		msg = ""
	}
	if kind != "" {
		// Explicitly expire cookies with matching attributes so browsers delete them.
		for _, name := range []string{"flash_kind", "flash_msg"} {
			c.Cookie(&fiber.Cookie{
				Name:     name,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HTTPOnly: true,
				SameSite: "Lax",
			})
		}
	}
	return
}
