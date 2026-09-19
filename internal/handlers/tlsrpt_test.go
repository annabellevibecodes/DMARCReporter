package handlers

import (
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	htmlengine "github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// tlsTestApp wires the TLS routes against an in-memory database.
func tlsTestApp(t *testing.T, requireDKIM bool) (*fiber.App, *sqlx.DB) {
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
	a := &App{DB: db, EnrichWorker: NewEnrichWorker(db, config.Config{}), Cfg: config.Config{TLSRPTRequireDKIM: requireDKIM}}
	app.Get("/tlsrpt", a.HandleTLSRPTList)
	app.Get("/tlsrpt/:id", a.HandleTLSRPTDetail)
	return app, db
}

// seedTLSReport stores one report with a single MTA-STS policy and, when
// given, one failure row.
func seedTLSReport(t *testing.T, db *sqlx.DB, org, reportID string, begin int64, meta database.TLSRPTMeta, success, failure int64, details ...parser.TLSFailureDetail) int64 {
	t.Helper()
	var p parser.TLSPolicy
	p.Policy.PolicyType = "sts"
	p.Policy.PolicyDomain = "example.com"
	p.Policy.MXHost = parser.FlexStrings{"mx.example.com"}
	p.Policy.PolicyString = parser.FlexStrings{"version: STSv1", "mode: testing", "mx: mx.example.com", "max_age: 86400"}
	p.Summary.TotalSuccess = success
	p.Summary.TotalFailure = failure
	p.FailureDetails = details

	report := &parser.TLSReport{
		OrganizationName: org, ContactInfo: "tlsrpt@" + org, ReportID: reportID,
		Policies: []parser.TLSPolicy{p},
	}
	report.DateRange.Start = time.Unix(begin, 0).UTC()
	report.DateRange.End = time.Unix(begin+86399, 0).UTC()

	id, err := database.SaveTLSRPTWithMeta(db, report, meta, reportID+".json", []byte(`{"report-id":"x"}`))
	if err != nil {
		t.Fatalf("seed %s: %v", reportID, err)
	}
	return id
}

func getPage(t *testing.T, app *fiber.App, path string) (int, string) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func recentDay(daysAgo int) int64 {
	return time.Now().UTC().AddDate(0, 0, -daysAgo).Truncate(24 * time.Hour).Unix()
}

func signedMeta(begin int64) database.TLSRPTMeta {
	return database.TLSRPTMeta{
		Transport: database.TransportSMTP, DKIMStatus: "valid",
		DKIMDomain: "reporter.example", ReceivedAt: begin + 86400,
	}
}

// The page renders with data and shows the headline figures.
func TestTLSRPTPageRenders(t *testing.T) {
	app, db := tlsTestApp(t, true)
	seedTLSReport(t, db, "google.com", "g-1", recentDay(2), signedMeta(recentDay(2)), 900, 10,
		parser.TLSFailureDetail{
			ResultType: "certificate-expired", FailedSessionCount: 10,
			SendingMTAIP: "198.51.100.10", ReceivingMXHostname: "mx.example.com",
			ReceivingIP: "203.0.113.5",
		})

	code, body := getPage(t, app, "/tlsrpt?period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, want := range []string{"TLS success rate", "certificate-expired", "mx.example.com", "203.0.113.5", "google.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	// 900 of 910 sessions succeeded.
	if !strings.Contains(body, "98.9") {
		t.Error("headline rate not rendered")
	}
}

// An empty period is an explicit state, not a broken page.
func TestTLSRPTPageEmptyState(t *testing.T) {
	app, _ := tlsTestApp(t, true)
	code, body := getPage(t, app, "/tlsrpt?period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "No TLS sessions reported") {
		t.Error("empty state missing")
	}
	if !strings.Contains(body, "_smtp._tls") {
		t.Error("empty state should say how reports start arriving")
	}
}

// An unsigned mailed report is visibly held back rather than silently dropped.
func TestTLSRPTPageShowsDKIMExclusion(t *testing.T) {
	app, db := tlsTestApp(t, true)
	day := recentDay(2)
	seedTLSReport(t, db, "unsigned.example", "u-1", day,
		database.TLSRPTMeta{Transport: database.TransportSMTP, DKIMStatus: "absent", ReceivedAt: day + 86400},
		5000, 5000)

	code, body := getPage(t, app, "/tlsrpt?period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	// Every session in the window belongs to the excluded report, so the
	// metrics have nothing to show — while the report itself stays listed
	// with its own counts, which is the point of keeping it.
	if !strings.Contains(body, "No TLS sessions reported") {
		t.Error("the excluded report's sessions must not reach the figures")
	}
	if !strings.Contains(body, "excluded") {
		t.Error("the page should say a report was excluded")
	}
	// It is still listed, with its status, so the operator can see it.
	if !strings.Contains(body, "unsigned.example") || !strings.Contains(body, "absent") {
		t.Error("the excluded report should still be listed with its DKIM status")
	}
}

// Drill-down narrows the failure tables and says so.
func TestTLSRPTPageDrillDown(t *testing.T) {
	app, db := tlsTestApp(t, true)
	day := recentDay(2)
	seedTLSReport(t, db, "google.com", "g-1", day, signedMeta(day), 100, 12,
		parser.TLSFailureDetail{
			ResultType: "certificate-expired", FailedSessionCount: 8,
			ReceivingMXHostname: "mx1.example.com", ReceivingIP: "203.0.113.5",
		},
		parser.TLSFailureDetail{
			ResultType: "starttls-not-supported", FailedSessionCount: 4,
			ReceivingMXHostname: "mx2.example.com", ReceivingIP: "203.0.113.9",
		})

	code, body := getPage(t, app, "/tlsrpt?period=30d&mx=mx1.example.com")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "MX host: mx1.example.com") {
		t.Error("active filter chip missing")
	}
	if strings.Contains(body, "starttls-not-supported") {
		t.Error("the other host's failures should be filtered out")
	}
	if !strings.Contains(body, "narrows the failure tables only") {
		t.Error("the page must say which figures the drill-down reached")
	}
}

// A bad drill-down value is rejected rather than reaching a query.
func TestTLSRPTPageRejectsBadFilters(t *testing.T) {
	app, _ := tlsTestApp(t, true)
	for _, path := range []string{
		"/tlsrpt?domain=not%20a%20domain",
		"/tlsrpt?domain=example.com%2Fetc",
		"/tlsrpt?mx=" + strings.Repeat("a", 300),
		"/tlsrpt?rip=" + strings.Repeat("9", 60),
	} {
		if code, _ := getPage(t, app, path); code != fiber.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, code)
		}
	}
}

// The detail view shows the report as sent: every policy entry, the parsed
// MTA-STS body and the full failure table.
func TestTLSRPTDetailShowsPoliciesAndFailures(t *testing.T) {
	app, db := tlsTestApp(t, true)
	day := recentDay(2)
	id := seedTLSReport(t, db, "google.com", "g-1", day, signedMeta(day), 900, 10,
		parser.TLSFailureDetail{
			ResultType: "certificate-expired", FailedSessionCount: 10,
			SendingMTAIP: "198.51.100.10", ReceivingMXHostname: "mx.example.com",
			ReceivingIP: "203.0.113.5", ReceivingMXHelo: "mail-out.example.net",
			FailureReasonCode: "X509_V_ERR_CERT_HAS_EXPIRED",
		})

	code, body := getPage(t, app, "/tlsrpt/"+strconv.FormatInt(id, 10))
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	for _, want := range []string{
		"mode: testing", "86,400s", "mx.example.com", // parsed policy
		"certificate-expired", "X509_V_ERR_CERT_HAS_EXPIRED", "mail-out.example.net", // failure detail
		"reporter.example", // DKIM
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page is missing %q", want)
		}
	}
}

// An excluded report explains itself on its own page.
func TestTLSRPTDetailExplainsExclusion(t *testing.T) {
	app, db := tlsTestApp(t, true)
	day := recentDay(2)
	id := seedTLSReport(t, db, "unsigned.example", "u-1", day,
		database.TLSRPTMeta{Transport: database.TransportSMTP, DKIMStatus: "absent",
			DKIMDetail: "no DKIM-Signature header"}, 10, 0)

	code, body := getPage(t, app, "/tlsrpt/"+strconv.FormatInt(id, 10))
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "excluded from the TLS metrics") {
		t.Error("the detail page should say the report is excluded")
	}
	if !strings.Contains(body, "no DKIM-Signature header") {
		t.Error("the reason should be shown")
	}
}

func TestTLSRPTDetailNotFound(t *testing.T) {
	app, _ := tlsTestApp(t, true)
	if code, _ := getPage(t, app, "/tlsrpt/9999"); code != fiber.StatusNotFound {
		t.Errorf("status = %d, want 404", code)
	}
	if code, _ := getPage(t, app, "/tlsrpt/abc"); code != fiber.StatusBadRequest {
		t.Errorf("status = %d, want 400", code)
	}
}

// With the requirement off, the same unsigned report counts — and the page
// says none are being held back.
func TestTLSRPTPageWithoutDKIMRequirement(t *testing.T) {
	app, db := tlsTestApp(t, false)
	day := recentDay(2)
	seedTLSReport(t, db, "unsigned.example", "u-1", day,
		database.TLSRPTMeta{Transport: database.TransportSMTP, DKIMStatus: "absent", ReceivedAt: day + 86400},
		500, 0)

	code, body := getPage(t, app, "/tlsrpt?period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	if !strings.Contains(body, "500") {
		t.Error("with the requirement off the unsigned report should be counted")
	}
	if !strings.Contains(body, "TLSRPT_REQUIRE_DKIM is off") {
		t.Error("the page should say the requirement is off")
	}
}
