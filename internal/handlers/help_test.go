package handlers

import (
	"html"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	htmlengine "github.com/gofiber/template/html/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/metrics"
)

func helpTestApp(t *testing.T) *fiber.App {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	engine := htmlengine.New("../../views", ".html")
	engine.AddFuncMap(TemplateFuncs())
	if err := engine.Load(); err != nil {
		t.Fatalf("load views: %v", err)
	}
	app := fiber.New(fiber.Config{Views: engine, ErrorHandler: ErrorHandler})
	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db)}
	app.Get("/help", a.HandleHelpPage)
	app.Get("/help/:section", a.HandleHelpPage)
	return app
}

func getHelp(t *testing.T, app *fiber.App, path string) (int, string) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// Every section renders, and each one carries the sub-navigation so no page is
// a dead end.
func TestHelpSectionsRender(t *testing.T) {
	app := helpTestApp(t)
	for _, sec := range helpSections {
		path := "/help"
		if sec.Slug != "" {
			path += "/" + sec.Slug
		}
		code, body := getHelp(t, app, path)
		if code != fiber.StatusOK {
			t.Errorf("%s: status = %d, want 200", path, code)
			continue
		}
		if !strings.Contains(body, html.EscapeString(sec.Title)) {
			t.Errorf("%s: page does not name its own section %q", path, sec.Title)
		}
		for _, other := range helpSections {
			if !strings.Contains(body, ">"+html.EscapeString(other.Title)+"</a>") {
				t.Errorf("%s: sub-nav is missing a link to %q", path, other.Title)
			}
		}
	}
}

func TestHelpUnknownSectionIs404(t *testing.T) {
	app := helpTestApp(t)
	if code, _ := getHelp(t, app, "/help/nope"); code != fiber.StatusNotFound {
		t.Errorf("unknown section status = %d, want 404", code)
	}
}

// Every identifier in the catalogue must be documented on the Help page its
// tooltip links to, so a tooltip can never point at a section that does not
// mention it.
func TestHelpDocumentsEveryCatalogueID(t *testing.T) {
	app := helpTestApp(t)
	pages := map[string]string{}
	for _, id := range metrics.IDs() {
		m, _ := metrics.Get(id)
		path, anchor, _ := strings.Cut(m.Href, "#")
		body, ok := pages[path]
		if !ok {
			code, b := getHelp(t, app, path)
			if code != fiber.StatusOK {
				t.Fatalf("%s: status = %d", path, code)
			}
			pages[path] = b
			body = b
		}
		if anchor != "" && !strings.Contains(body, `id="`+anchor+`"`) {
			t.Errorf("%s: anchor #%s referenced by %s does not exist", path, anchor, id)
		}
		if !strings.Contains(body, id) {
			t.Errorf("%s does not document %s", m.Href, id)
		}
	}
}

// The alert rules live on their own page and must all be listed.
func TestHelpAlertsDocumentsEveryRule(t *testing.T) {
	app := helpTestApp(t)
	code, body := getHelp(t, app, "/help/alerts")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, rule := range []string{
		"new_failing_source", "pass_rate_drop", "known_source_degraded", "new_selector",
		"selector_missing", "reporter_silent", "policy_changed", "policy_inconsistent",
		"dns_error_spike", "override_spike", "spoof_spike",
	} {
		if !strings.Contains(body, rule) {
			t.Errorf("alerts page does not document rule %s", rule)
		}
	}
	if !strings.Contains(body, "Health Score") {
		t.Error("alerts page is missing the health score section")
	}
}
