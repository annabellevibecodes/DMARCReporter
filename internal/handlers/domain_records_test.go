package handlers

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// domainPageApp serves /domains/:domain against an in-memory database holding
// one report for example.com, and hands back the database so a test can seed
// the domain-check cache the page reads.
func domainPageApp(t *testing.T) (*fiber.App, *sqlx.DB) {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	fb := &models.Feedback{
		ReportMetadata: models.ReportMetadata{
			OrgName: "google.com", ReportID: "r1",
			DateRange: models.DateRange{Begin: begin, End: begin + 86399},
		},
		PolicyPublished: models.PolicyPublished{Domain: "example.com", Policy: "reject", ADKIM: "r", ASPF: "r"},
		Records: []models.Record{{
			Row: models.Row{SourceIP: "192.0.2.10", Count: 10, PolicyEvaluated: models.PolicyEvaluated{
				Disposition: "none", DKIM: "pass", SPF: "pass",
			}},
			Identifiers: models.Identifiers{HeaderFrom: "example.com", EnvelopeFrom: "example.com"},
		}},
	}
	if _, err := database.SaveReport(db, fb, "r1.xml", nil); err != nil {
		t.Fatalf("save report: %v", err)
	}

	engine := html.New("../../views", ".html")
	engine.AddFuncMap(TemplateFuncs())
	if err := engine.Load(); err != nil {
		t.Fatalf("load views: %v", err)
	}
	app := fiber.New(fiber.Config{Views: engine, ErrorHandler: ErrorHandler})
	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db, config.Config{})}
	app.Get("/domains/:domain", a.HandleDomainDetail)
	return app, db
}

func getDomainPage(t *testing.T, app *fiber.App, path string) (int, string) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("request %q: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// The domain page renders the published records out of the domain-check cache.
//
// Nothing on this path resolves DNS: the Enrich worker and the background
// refresher own every lookup, so a page render cannot be held open by a slow
// or hostile resolver. The test proves it by the only means available from
// outside — the page shows records that exist nowhere but the database, and
// says "not looked up yet" when the database has none.
func TestDomainPageRendersRecordsFromTheCache(t *testing.T) {
	app, db := domainPageApp(t)

	// Nothing cached: the page must say so rather than implying the domain
	// publishes nothing.
	code, body := getDomainPage(t, app, "/domains/example.com")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "Not looked up yet") {
		t.Error("an unchecked domain did not say so")
	}
	if strings.Contains(body, "No DMARC record found") {
		t.Error("an unchecked domain was rendered as publishing nothing")
	}

	// A cached record is rendered, parsed, without any lookup. The record
	// below is not what example.com publishes in the real DNS, so a page that
	// showed it can only have read it from here.
	if err := database.UpsertDomainCheck(db, database.DomainCheck{
		Domain: "example.com", HasDMARC: 1, HasMTASTS: 1, CheckedAt: time.Now().Unix(),
		DMARCRecord:  "v=DMARC1; p=reject; pct=42; rua=mailto:cached@example.invalid",
		MTASTSRecord: "v=STSv1; id=cachedvalue;",
	}); err != nil {
		t.Fatal(err)
	}
	if code, body = getDomainPage(t, app, "/domains/example.com"); code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, want := range []string{"cached@example.invalid", "cachedvalue", "42"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not show the cached value %q", want)
		}
	}
	if strings.Contains(body, "Not looked up yet") {
		t.Error("a cached record still rendered as unchecked")
	}
}

// A lookup that failed is its own state: neither "publishes nothing" nor a
// silent gap.
func TestDomainPageShowsLookupFailures(t *testing.T) {
	app, db := domainPageApp(t)
	if err := database.UpsertDomainCheck(db, database.DomainCheck{
		Domain: "example.com", CheckedAt: time.Now().Unix(),
		DMARCError: "read udp 127.0.0.1:53: i/o timeout",
	}); err != nil {
		t.Fatal(err)
	}
	code, body := getDomainPage(t, app, "/domains/example.com")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "i/o timeout") {
		t.Error("the resolver failure was not shown")
	}
}
