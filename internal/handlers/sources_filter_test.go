package handlers

import (
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// sourcesReport builds a one-record report so each domain/IP pair is distinct.
func sourcesReport(reportID, domain, ip string, count int, dkim, spf, disposition string) *models.Feedback {
	begin := time.Now().AddDate(0, 0, -2).Unix()
	return &models.Feedback{
		ReportMetadata: models.ReportMetadata{
			OrgName:   "google.com",
			ReportID:  reportID,
			DateRange: models.DateRange{Begin: begin, End: begin + 86399},
		},
		PolicyPublished: models.PolicyPublished{Domain: domain, Policy: "none", Pct: 100},
		Records: []models.Record{{
			Row: models.Row{
				SourceIP: ip, Count: count,
				PolicyEvaluated: models.PolicyEvaluated{Disposition: disposition, DKIM: dkim, SPF: spf},
			},
			Identifiers: models.Identifiers{EnvelopeTo: "gmail.com", EnvelopeFrom: domain, HeaderFrom: domain},
		}},
	}
}

func sourcesTestApp(t *testing.T) *fiber.App {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	reports := []*models.Feedback{
		sourcesReport("r1", "alpha.example", "192.0.2.10", 100, "pass", "pass", "none"),
		sourcesReport("r2", "alpha.example", "192.0.2.20", 50, "fail", "fail", "quarantine"),
		sourcesReport("r3", "beta.example", "198.51.100.5", 70, "fail", "fail", "none"),
	}
	for _, fb := range reports {
		if _, err := database.SaveReport(db, fb, "t.xml", nil); err != nil {
			t.Fatalf("save report %s: %v", fb.ReportMetadata.ReportID, err)
		}
	}

	engine := html.New("../../views", ".html")
	engine.AddFuncMap(TemplateFuncs())
	if err := engine.Load(); err != nil {
		t.Fatalf("load views: %v", err)
	}
	app := fiber.New(fiber.Config{Views: engine, ErrorHandler: ErrorHandler})
	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db, config.Config{})}
	app.Get("/sources", a.HandleSourcesList)
	return app
}

func getSources(t *testing.T, app *fiber.App, query string) (int, string) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", "/sources?"+query, nil), -1)
	if err != nil {
		t.Fatalf("request %q: %v", query, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// The matrix boxes on a domain detail page link to /sources with a domain
// parameter; before this was supported the scope was silently dropped.
func TestSourcesDomainFilterScopesResults(t *testing.T) {
	app := sourcesTestApp(t)

	code, all := getSources(t, app, "period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, ip := range []string{"192.0.2.10", "192.0.2.20", "198.51.100.5"} {
		if !strings.Contains(all, ip) {
			t.Errorf("unfiltered page missing %s", ip)
		}
	}

	code, scoped := getSources(t, app, "period=30d&domain=alpha.example")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(scoped, "192.0.2.10") || !strings.Contains(scoped, "192.0.2.20") {
		t.Error("domain-scoped page dropped a source belonging to that domain")
	}
	if strings.Contains(scoped, "198.51.100.5") {
		t.Error("domain-scoped page still lists a source from another domain")
	}
	// The filter must be visible and removable, not silently applied.
	if !strings.Contains(scoped, "domain: alpha.example") {
		t.Error("active-filter chip for the domain is missing")
	}

	if code, _ := getSources(t, app, "domain=not%20a%20domain"); code != fiber.StatusBadRequest {
		t.Errorf("invalid domain status = %d, want 400", code)
	}
}

func TestSourcesMatrixFilterHasControls(t *testing.T) {
	app := sourcesTestApp(t)
	code, body := getSources(t, app, "matrix=neither&period=1y")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	// Every matrix cell is reachable from the page itself.
	for _, want := range []string{"matrix=both", "matrix=dkim", "matrix=spf", "All results"} {
		if !strings.Contains(body, want) {
			t.Errorf("matrix chip row missing %q", want)
		}
	}
	if !strings.Contains(body, "matrix: neither") {
		t.Error("active-filter chip for the matrix cell is missing")
	}
	// Only failing sources remain.
	if strings.Contains(body, "192.0.2.10") {
		t.Error("matrix=neither still lists a fully passing source")
	}
	if !strings.Contains(body, "192.0.2.20") {
		t.Error("matrix=neither dropped a failing source")
	}
}

// Filters must survive a sort or page change.
func TestSourcesFiltersSurviveSortLinks(t *testing.T) {
	app := sourcesTestApp(t)
	_, body := getSources(t, app, "period=30d&domain=alpha.example&matrix=neither")
	if !strings.Contains(body, "domain=alpha.example") {
		t.Error("sort/page links dropped the domain filter")
	}
	if !strings.Contains(body, "matrix=neither") {
		t.Error("sort/page links dropped the matrix filter")
	}
}

func TestChipHrefSetsAndClears(t *testing.T) {
	base := url.Values{"period": {"1y"}, "matrix": {"neither"}, "page": {"3"}}
	got := string(chipHref("/sources", base, "matrix", "both"))
	if !strings.Contains(got, "matrix=both") || strings.Contains(got, "page=3") {
		t.Errorf("set chip href = %q, want matrix=both and no page", got)
	}
	got = string(chipHref("/sources", base, "matrix", ""))
	if strings.Contains(got, "matrix=") {
		t.Errorf("clear chip href = %q, want no matrix", got)
	}
	if !strings.Contains(got, "period=1y") {
		t.Errorf("clear chip href = %q, want other filters kept", got)
	}
	// The caller's map must not be mutated.
	if base.Get("matrix") != "neither" || base.Get("page") != "3" {
		t.Error("chipHref mutated the base query values")
	}
}

// Metric references in real pages render as tooltip-carrying links, not bare
// text, so hovering one explains it.
func TestSourcesPageRendersMetricTooltips(t *testing.T) {
	app := sourcesTestApp(t)
	_, body := getSources(t, app, "period=30d&matrix=neither")
	if !strings.Contains(body, `class="metric-id"`) {
		t.Fatal("no metric reference was rendered as a tooltip link")
	}
	// The S3 reference in the pattern footnote carries its summary and links
	// to the matching Help anchor.
	if !strings.Contains(body, "/help/metrics#sources") {
		t.Error("metric reference does not link to its Help section")
	}
	if !strings.Contains(body, "S3 · Source pattern") {
		t.Error("metric tooltip text is missing")
	}
	// Bare IDs must not survive next to a tooltip link.
	if strings.Contains(body, ">Patterns (S3)") {
		t.Error("an ID was left as plain text")
	}
}
