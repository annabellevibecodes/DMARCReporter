package handlers

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
	"github.com/annabellevibecodes/dmarcreporter/internal/scoring"
)

// The health score is out of a maximum that moves: components with nothing to
// judge — no TLS sessions, no BIMI record — leave the maximum as well as the
// total, so a domain is never marked down for data nobody sent. A card that
// prints a fixed denominator therefore lies, and can print a score larger than
// the total it claims to be out of.
func TestHealthCardShowsTheRealMaximum(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	fb := &models.Feedback{
		ReportMetadata: models.ReportMetadata{
			OrgName: "google.com", ReportID: "r1",
			DateRange: models.DateRange{Begin: begin, End: begin + 86399},
		},
		PolicyPublished: models.PolicyPublished{Domain: "example.com", Policy: "reject", ADKIM: "r", ASPF: "r"},
		Records: []models.Record{{
			Row: models.Row{SourceIP: "192.0.2.10", Count: 100, PolicyEvaluated: models.PolicyEvaluated{
				Disposition: "none", DKIM: "pass", SPF: "pass",
			}},
			Identifiers: models.Identifiers{HeaderFrom: "example.com", EnvelopeFrom: "example.com"},
		}},
	}
	if _, err := database.SaveReport(db, fb, "r1.xml", nil); err != nil {
		t.Fatal(err)
	}

	// A TLS report brings the transport-security component into play, which
	// is what pushes the maximum above 100.
	var policy parser.TLSPolicy
	policy.Policy.PolicyType = "sts"
	policy.Policy.PolicyDomain = "example.com"
	policy.Summary.TotalSuccess = 100
	report := &parser.TLSReport{
		OrganizationName: "google.com", ContactInfo: "tlsrpt@google.com",
		ReportID: "t1", Policies: []parser.TLSPolicy{policy},
	}
	report.DateRange.Start = time.Unix(begin, 0).UTC()
	report.DateRange.End = time.Unix(begin+86399, 0).UTC()
	if _, err := database.SaveTLSRPTWithMeta(db, report, database.TLSRPTMeta{
		Transport: database.TransportSMTP, DKIMStatus: "valid", ReceivedAt: begin + 86400,
	}, "t1.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db, config.Config{}),
		Cfg: config.Config{TLSRPTRequireDKIM: true}}

	// The score itself must be out of more than 100 for this test to mean
	// anything; if the weights ever change so it is not, say so plainly
	// rather than passing vacuously.
	score, err := scoring.ComputeWithOptions(db, "", database.StatsFilter{}, scoring.DefaultWeights, true)
	if err != nil {
		t.Fatal(err)
	}
	if score.Max <= 100 {
		t.Fatalf("max = %d; this test needs a component beyond the DMARC 100 to be in play", score.Max)
	}

	engine := html.New("../../views", ".html")
	engine.AddFuncMap(TemplateFuncs())
	if err := engine.Load(); err != nil {
		t.Fatal(err)
	}
	app := fiber.New(fiber.Config{Views: engine, ErrorHandler: ErrorHandler})
	app.Get("/", a.HandleDashboard)

	resp, err := app.Test(httptest.NewRequest("GET", "/", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	page := string(body)

	if strings.Contains(page, "<small>/100</small>") {
		t.Errorf("the health card prints a fixed /100 while the score is out of %d", score.Max)
	}
	if want := "<small>/" + itoa(score.Max) + "</small>"; !strings.Contains(page, want) {
		t.Errorf("the health card does not show %q", want)
	}
	// The banner has always used the real maximum; both must agree.
	if want := "/" + itoa(score.Max) + "</b>"; !strings.Contains(page, want) {
		t.Errorf("the banner does not show %q either", want)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
