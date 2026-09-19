package handlers

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// The l= and a= values are URLs taken from a third party's DNS record and are
// rendered as links. A record naming a javascript: URL must not produce a live
// one, and a record carrying markup must not produce markup.
func TestBIMIRecordValuesCannotInjectMarkupOrScript(t *testing.T) {
	app, db := domainPageApp(t)

	hostile := `v=BIMI1; l=javascript:alert(document.domain); a="><script>alert(1)</script>`
	res := bimi.Result{
		Domain: "example.com", Selector: "default", State: bimi.StateInvalid,
		FoundAt: "example.com", RRset: bimi.ParseRRset([]string{hostile}),
	}
	detail, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: "example.com", Selector: "default", Kind: database.BIMISnapshotRecord,
		Content: hostile, Detail: string(detail), LastSeen: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	code, body := getDomainPage(t, app, "/domains/example.com")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	// The record has to actually be on the page, or the test proves nothing.
	if !strings.Contains(body, "BIMI") {
		t.Fatal("the BIMI card did not render")
	}
	if strings.Contains(body, "href=\"javascript:") {
		t.Error("a javascript: URL was rendered as a live link")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("markup from the record reached the page unescaped")
	}
}

// The same values reach the cross-domain page, which renders them in text
// rather than in an href — but through a different template.
func TestBIMIPageEscapesRecordValues(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.AddManagedDomain(db, "example.com"); err != nil {
		t.Fatal(err)
	}
	hostile := `v=BIMI1; l=https://example.com/"><script>alert(1)</script>.svg`
	res := bimi.Result{
		Domain: "example.com", Selector: "default", State: bimi.StatePublished,
		FoundAt: "example.com", RRset: bimi.ParseRRset([]string{hostile}),
	}
	detail, _ := json.Marshal(res)
	if _, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: "example.com", Selector: "default", Kind: database.BIMISnapshotRecord,
		Content: hostile, Detail: string(detail), LastSeen: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	app, _ := bimiPageApp(t, db)
	code, body := getBIMIPage(t, app, "/bimi")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("markup from the record reached the BIMI page unescaped")
	}
}

// bimiPageApp serves /bimi against a prepared database.
func bimiPageApp(t *testing.T, db *sqlx.DB) (*fiber.App, *App) {
	t.Helper()
	engine := html.New("../../views", ".html")
	engine.AddFuncMap(TemplateFuncs())
	if err := engine.Load(); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Views: engine, ErrorHandler: ErrorHandler})
	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db, config.Config{})}
	app.Get("/bimi", a.HandleBIMIPage)
	return app, a
}

func getBIMIPage(t *testing.T, app *fiber.App, path string) (int, string) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("request %q: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}
