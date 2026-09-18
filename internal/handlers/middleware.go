package handlers

import (
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ingest"
)

// App holds shared dependencies for all handlers.
type App struct {
	DB           *sqlx.DB
	Cfg          config.Config
	Worker       *ingest.Worker
	EnrichWorker *EnrichWorker
}

// FetchEnabled reports whether any enabled mail account exists, controlling
// visibility of the Fetch button.
func (a *App) FetchEnabled() bool {
	n, err := database.CountEnabledAccounts(a.DB)
	return err == nil && n > 0
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

// safeRedirect reports whether s is a local, path-only redirect target.
//
// A redirect target must start with "/" and must not continue with a second
// "/" or a "\": browsers read "//host" as an absolute URL and normalise
// "/\host" to "//host", so either would leave the site (CWE-601). Both
// characters are checked explicitly at position 1 so the guard is verifiable
// by eye — an earlier HasPrefix/ContainsAny spelling covered the same cases
// but read as a leading-slash check only.
//
// The remaining checks are defence in depth: no backslash anywhere, and
// nothing url.Parse sees as carrying a scheme, host or userinfo.
func safeRedirect(s string) bool {
	if s == "" || s[0] != '/' {
		return false
	}
	if len(s) > 1 && (s[1] == '/' || s[1] == '\\') {
		return false
	}
	if strings.ContainsAny(s, `\`) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	return true
}

// currentPath returns the request's path and query for use as a form's
// `redirect` field. It deliberately does not use c.OriginalURL(): that is the
// raw request URI, which is in absolute form ("http://host/alerts") whenever a
// proxy forwards it that way. Planting an absolute URL in the redirect field
// makes safeRedirect reject it on the POST, so the inline forms silently fall
// through to their JSON response and the user lands on a JSON blob instead of
// back on the page. An unusable path degrades to "/" rather than to nothing.
func currentPath(c *fiber.Ctx) string {
	p := string(c.Request().URI().PathOriginal())
	if qs := c.Request().URI().QueryString(); len(qs) > 0 {
		p += "?" + string(qs)
	}
	if !safeRedirect(p) {
		return "/"
	}
	return p
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
