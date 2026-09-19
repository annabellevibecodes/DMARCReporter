package handlers

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	htmlengine "github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

func tlsAPIApp(t *testing.T, requireDKIM bool) (*fiber.App, *sqlx.DB) {
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
	app.Get("/api/tls", a.HandleAPITLS)
	app.Get("/api/tls/failures", a.HandleAPITLSFailures)
	app.Get("/api/tls/policies", a.HandleAPITLSPolicies)
	app.Get("/api/tls/reporters", a.HandleAPITLSReporters)
	return app, db
}

func getJSON(t *testing.T, app *fiber.App, path string) (int, map[string]any) {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusOK {
		return resp.StatusCode, nil
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%s returned invalid JSON: %v\n%s", path, err, body)
	}
	return resp.StatusCode, out
}

// seedAPIScenario stores two reports: one clean, one with three failure rows
// across two hosts and two result types.
func seedAPIScenario(t *testing.T, db *sqlx.DB) {
	t.Helper()
	day := recentDay(2)
	seedTLSReport(t, db, "google.com", "a-1", day, signedMeta(day), 900, 18,
		parser.TLSFailureDetail{
			ResultType: "certificate-expired", FailedSessionCount: 10,
			SendingMTAIP: "198.51.100.10", ReceivingMXHostname: "mx1.example.com",
			ReceivingIP: "203.0.113.5", FailureReasonCode: "X509_V_ERR_CERT_HAS_EXPIRED",
		},
		parser.TLSFailureDetail{
			ResultType: "starttls-not-supported", FailedSessionCount: 8,
			SendingMTAIP: "2001:db8::10", ReceivingMXHostname: "mx2.example.com",
			ReceivingIP: "2001:db8::25",
		})
	seedTLSReport(t, db, "microsoft.com", "b-1", recentDay(3), signedMeta(recentDay(3)), 400, 0)
}

func TestAPITLSPayload(t *testing.T) {
	app, db := tlsAPIApp(t, true)
	seedAPIScenario(t, db)

	code, body := getJSON(t, app, "/api/tls?period=30d")
	if code != fiber.StatusOK {
		t.Fatalf("status = %d", code)
	}
	window, _ := body["window"].(map[string]any)
	if window["require_dkim"] != true {
		t.Error("the window should say whether the DKIM rule was applied")
	}
	current, _ := body["current"].(map[string]any)
	for _, key := range []string{
		"rate", "by_domain", "volume", "policy_mix", "failures", "receivers", "senders",
		"reasons", "policy_divergence", "readiness", "endpoint_health", "dane",
		"coverage", "hygiene", "family", "incidents", "rollup",
	} {
		if _, ok := current[key]; !ok {
			t.Errorf("payload is missing %q", key)
		}
	}
	rate, _ := current["rate"].(map[string]any)
	if rate["success"].(float64) != 1300 || rate["failure"].(float64) != 18 {
		t.Errorf("rate = %v", rate)
	}
}

func TestAPITLSComparison(t *testing.T) {
	app, db := tlsAPIApp(t, true)
	seedAPIScenario(t, db)

	_, body := getJSON(t, app, "/api/tls?period=7d&compare=1")
	window, _ := body["window"].(map[string]any)
	if _, ok := window["previous"]; !ok {
		t.Error("compare=1 should describe the previous window")
	}
	if body["previous"] == nil {
		t.Error("compare=1 should return the previous window's payload")
	}

	_, body = getJSON(t, app, "/api/tls?period=7d")
	if body["previous"] != nil {
		t.Error("without compare=1 there should be no previous payload")
	}
}

func TestAPITLSFailuresFilters(t *testing.T) {
	app, db := tlsAPIApp(t, true)
	seedAPIScenario(t, db)

	// Unfiltered: both result types.
	_, body := getJSON(t, app, "/api/tls/failures?period=30d")
	breakdown, _ := body["by_result_type"].(map[string]any)
	types, _ := breakdown["types"].([]any)
	if len(types) != 2 {
		t.Fatalf("result types = %d, want 2", len(types))
	}

	// By result type.
	_, body = getJSON(t, app, "/api/tls/failures?period=30d&result_type=certificate-expired")
	breakdown, _ = body["by_result_type"].(map[string]any)
	types, _ = breakdown["types"].([]any)
	if len(types) != 1 {
		t.Errorf("filtered result types = %d, want 1", len(types))
	}
	if total := breakdown["total_failed_sessions"].(float64); total != 10 {
		t.Errorf("filtered total = %v, want 10", total)
	}
	filters, _ := body["filters"].(map[string]any)
	if filters["result_type"] != "certificate-expired" {
		t.Errorf("filters echo = %v", filters)
	}

	// By MX host.
	_, body = getJSON(t, app, "/api/tls/failures?period=30d&mx=mx2.example.com")
	breakdown, _ = body["by_result_type"].(map[string]any)
	if total := breakdown["total_failed_sessions"].(float64); total != 8 {
		t.Errorf("mx-filtered total = %v, want 8", total)
	}

	// By receiving IP, in a non-canonical spelling: it must still match the
	// canonical form that was stored.
	_, body = getJSON(t, app, "/api/tls/failures?period=30d&receiving_ip=2001:0db8:0000::0025")
	breakdown, _ = body["by_result_type"].(map[string]any)
	if total := breakdown["total_failed_sessions"].(float64); total != 8 {
		t.Errorf("receiving_ip-filtered total = %v, want 8", total)
	}

	// By sending IP.
	_, body = getJSON(t, app, "/api/tls/failures?period=30d&sending_ip=198.51.100.10")
	breakdown, _ = body["by_result_type"].(map[string]any)
	if total := breakdown["total_failed_sessions"].(float64); total != 10 {
		t.Errorf("sending_ip-filtered total = %v, want 10", total)
	}
}

func TestAPITLSFailuresRejectsBadFilters(t *testing.T) {
	app, _ := tlsAPIApp(t, true)
	for _, path := range []string{
		"/api/tls/failures?receiving_ip=not-an-ip",
		"/api/tls/failures?sending_ip=999.999.999.999",
		"/api/tls/failures?result_type=drop%20table",
		"/api/tls?domain=bad%20domain",
	} {
		if code, _ := getJSON(t, app, path); code != fiber.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", path, code)
		}
	}
}

func TestAPITLSPolicies(t *testing.T) {
	app, db := tlsAPIApp(t, true)
	seedAPIScenario(t, db)

	_, body := getJSON(t, app, "/api/tls/policies?period=30d")
	mix, _ := body["mix"].(map[string]any)
	overall, _ := mix["overall"].([]any)
	if len(overall) != 1 {
		t.Fatalf("policy types = %d, want 1 (sts)", len(overall))
	}
	readiness, _ := body["readiness"].(map[string]any)
	if readiness["testing_sessions"].(float64) != 1318 {
		t.Errorf("testing sessions = %v, want 1318", readiness["testing_sessions"])
	}
	if readiness["would_block"].(float64) != 18 {
		t.Errorf("would_block = %v, want 18", readiness["would_block"])
	}
	if _, ok := body["divergence"]; !ok {
		t.Error("divergence missing")
	}
}

func TestAPITLSReporters(t *testing.T) {
	app, db := tlsAPIApp(t, true)
	seedAPIScenario(t, db)

	_, body := getJSON(t, app, "/api/tls/reporters?period=30d")
	volume, _ := body["volume"].(map[string]any)
	if volume["reporter_count"].(float64) != 2 {
		t.Errorf("reporter count = %v, want 2", volume["reporter_count"])
	}
	shares, _ := volume["reporter_shares"].([]any)
	if len(shares) != 2 {
		t.Errorf("reporter shares = %d, want 2", len(shares))
	}
	coverage, _ := body["coverage"].(map[string]any)
	if _, ok := coverage["latency"]; !ok {
		t.Error("coverage should carry arrival latency")
	}
	hygiene, _ := body["hygiene"].(map[string]any)
	if hygiene["reports"].(float64) != 2 {
		t.Errorf("hygiene reports = %v, want 2", hygiene["reports"])
	}
}

// The API applies the same RFC 8460 §3 exclusion the page does, and says so.
func TestAPITLSHonoursDKIMRequirement(t *testing.T) {
	strict, db := tlsAPIApp(t, true)
	day := recentDay(2)
	seedTLSReport(t, db, "unsigned.example", "u-1", day,
		database.TLSRPTMeta{Transport: database.TransportSMTP, DKIMStatus: "absent"}, 700, 0)

	_, body := getJSON(t, strict, "/api/tls?period=30d")
	current, _ := body["current"].(map[string]any)
	rate, _ := current["rate"].(map[string]any)
	if rate["success"].(float64) != 0 {
		t.Errorf("strict success = %v, want the unsigned report excluded", rate["success"])
	}
	hygiene, _ := current["hygiene"].(map[string]any)
	if hygiene["excluded"].(float64) != 1 {
		t.Errorf("hygiene should report 1 excluded, got %v", hygiene["excluded"])
	}

	lenient, db2 := tlsAPIApp(t, false)
	seedTLSReport(t, db2, "unsigned.example", "u-1", day,
		database.TLSRPTMeta{Transport: database.TransportSMTP, DKIMStatus: "absent"}, 700, 0)
	_, body = getJSON(t, lenient, "/api/tls?period=30d")
	current, _ = body["current"].(map[string]any)
	rate, _ = current["rate"].(map[string]any)
	if rate["success"].(float64) != 700 {
		t.Errorf("lenient success = %v, want 700", rate["success"])
	}
	window, _ := body["window"].(map[string]any)
	if window["require_dkim"] != false {
		t.Error("the window should report that the rule was off")
	}
}
