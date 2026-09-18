package scoring

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

func openDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func day(n int) int64 {
	return time.Now().UTC().AddDate(0, 0, -n).Truncate(24 * time.Hour).Unix()
}

// saveDMARC stores one report where every message passes, so the DMARC half
// of the score is stable and the TLS half is what the test is varying.
func saveDMARC(t *testing.T, db *sqlx.DB, org, id, domain string, begin int64) {
	t.Helper()
	fb := &models.Feedback{
		ReportMetadata:  models.ReportMetadata{OrgName: org, ReportID: id, DateRange: models.DateRange{Begin: begin, End: begin + 86399}},
		PolicyPublished: models.PolicyPublished{Domain: domain, Policy: "reject", ADKIM: "r", ASPF: "r", Pct: 100},
		Records: []models.Record{{
			Row:         models.Row{SourceIP: "192.0.2.10", Count: 100, PolicyEvaluated: models.PolicyEvaluated{Disposition: "none", DKIM: "pass", SPF: "pass"}},
			Identifiers: models.Identifiers{HeaderFrom: domain, EnvelopeFrom: domain},
		}},
	}
	if _, err := database.SaveReport(db, fb, id+".xml", []byte("<xml/>")); err != nil {
		t.Fatalf("save dmarc %s: %v", id, err)
	}
}

// saveTLS stores one TLS report for domain with the given session counts.
func saveTLS(t *testing.T, db *sqlx.DB, org, id, domain string, begin, success, failure int64, status string) {
	t.Helper()
	var p parser.TLSPolicy
	p.Policy.PolicyType = "sts"
	p.Policy.PolicyDomain = domain
	p.Policy.MXHost = parser.FlexStrings{"mx." + domain}
	p.Summary.TotalSuccess = success
	p.Summary.TotalFailure = failure

	report := &parser.TLSReport{OrganizationName: org, ReportID: id, Policies: []parser.TLSPolicy{p}}
	report.DateRange.Start = time.Unix(begin, 0).UTC()
	report.DateRange.End = time.Unix(begin+86399, 0).UTC()

	if _, err := database.SaveTLSRPTWithMeta(db, report, database.TLSRPTMeta{
		Transport: database.TransportSMTP, DKIMStatus: status, ReceivedAt: begin + 86400,
	}, id+".json", []byte("{}")); err != nil {
		t.Fatalf("save tls %s: %v", id, err)
	}
}

func window() database.StatsFilter {
	return database.StatsFilter{From: day(30)}
}

// The heart of the component: a domain nobody sends TLS reports about must
// score exactly as it did before the component existed — the weight leaves
// the maximum as well as the total.
func TestTLSComponentSkippedWithoutData(t *testing.T) {
	db := openDB(t)
	saveDMARC(t, db, "google.com", "d-1", "example.com", day(2))

	s, err := Compute(db, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}
	if s.TLSScored {
		t.Error("nothing to judge, so the component must not be scored")
	}
	if s.Components.TLS != 0 {
		t.Errorf("component = %v, want 0", s.Components.TLS)
	}
	if s.Max != 100 {
		t.Errorf("max = %d, want the DMARC 100 with the TLS weight left out", s.Max)
	}
}

// Evidence of breakage scores differently from absence of evidence: the same
// domain, one with no reports and one failing every session.
func TestTLSNoDataAndFailureScoreDifferently(t *testing.T) {
	noData := openDB(t)
	saveDMARC(t, noData, "google.com", "d-1", "example.com", day(2))
	absent, err := Compute(noData, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}

	failing := openDB(t)
	saveDMARC(t, failing, "google.com", "d-1", "example.com", day(2))
	saveTLS(t, failing, "google.com", "t-1", "example.com", day(2), 0, 500, "valid")
	broken, err := Compute(failing, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}

	if !broken.TLSScored {
		t.Fatal("a domain with sessions must be scored")
	}
	if absent.Max == broken.Max {
		t.Errorf("maxima are equal (%d): the two states must not score alike", absent.Max)
	}
	// Absence keeps the full DMARC percentage; breakage drags it down.
	absentPct := float64(absent.Total) / float64(absent.Max) * 100
	brokenPct := float64(broken.Total) / float64(broken.Max) * 100
	if brokenPct >= absentPct {
		t.Errorf("failing TLS scored %.1f%% and no data scored %.1f%% — breakage must cost more",
			brokenPct, absentPct)
	}
}

// A healthy TLS domain earns close to the full component, and more reporters
// are worth more than one.
func TestTLSComponentScoresRateAndCoverage(t *testing.T) {
	db := openDB(t)
	saveDMARC(t, db, "google.com", "d-1", "example.com", day(2))
	saveTLS(t, db, "google.com", "t-1", "example.com", day(2), 1000, 0, "valid")

	oneReporter, err := Compute(db, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}
	if !oneReporter.TLSScored || oneReporter.TLSReporters != 1 {
		t.Fatalf("score = %+v", oneReporter)
	}
	// 100% rate → 70% of the weight, plus half the coverage third.
	if got := oneReporter.Components.TLS; got < 12.7 || got > 13.0 {
		t.Errorf("component = %.2f, want ~12.75 of 15 (rate full, coverage half)", got)
	}

	saveTLS(t, db, "microsoft.com", "t-2", "example.com", day(2), 500, 0, "valid")
	twoReporters, err := Compute(db, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}
	if twoReporters.Components.TLS <= oneReporter.Components.TLS {
		t.Errorf("two reporters (%.2f) should beat one (%.2f)",
			twoReporters.Components.TLS, oneReporter.Components.TLS)
	}
	if got := twoReporters.Components.TLS; got < 14.9 || got > 15.1 {
		t.Errorf("component = %.2f, want the full 15", got)
	}
	if twoReporters.Max != 115 {
		t.Errorf("max = %d, want 115 once TLS is in play", twoReporters.Max)
	}
}

// A half-failing domain lands between the two.
func TestTLSComponentTracksRate(t *testing.T) {
	db := openDB(t)
	saveDMARC(t, db, "google.com", "d-1", "example.com", day(2))
	saveTLS(t, db, "google.com", "t-1", "example.com", day(2), 500, 500, "valid")

	s, err := Compute(db, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}
	if s.TLSRate < 49 || s.TLSRate > 51 {
		t.Errorf("rate = %.1f, want ~50", s.TLSRate)
	}
	// 50% of the rate share (10.5) + half coverage (2.25) = 7.5.
	if got := s.Components.TLS; got < 7.3 || got > 7.7 {
		t.Errorf("component = %.2f, want ~7.5", got)
	}
}

// Reports excluded by the RFC 8460 §3 signature rule are not evidence, so a
// domain whose only TLS reports are unsigned scores as "no data" — never as
// a failure.
func TestTLSComponentIgnoresExcludedReports(t *testing.T) {
	db := openDB(t)
	saveDMARC(t, db, "google.com", "d-1", "example.com", day(2))
	saveTLS(t, db, "unsigned.example", "t-1", "example.com", day(2), 0, 900, "absent")

	s, err := Compute(db, "example.com", window(), DefaultWeights)
	if err != nil {
		t.Fatal(err)
	}
	if s.TLSScored {
		t.Error("an excluded report is not evidence and must not be scored")
	}
	if s.Max != 100 {
		t.Errorf("max = %d, want the TLS weight left out", s.Max)
	}

	// With the requirement off, the same data is judged.
	lenient, err := ComputeWithOptions(db, "example.com", window(), DefaultWeights, false)
	if err != nil {
		t.Fatal(err)
	}
	if !lenient.TLSScored || lenient.Components.TLS > 3 {
		t.Errorf("lenient score = %+v, want the failing sessions counted", lenient)
	}
}

// The weights come from configuration, and a zero TLS weight disables the
// component without disturbing the rest.
func TestWeightsFromConfig(t *testing.T) {
	w := WeightsFromConfig(config.Config{
		HealthWeightPassRate: 40, HealthWeightEnforcement: 25, HealthWeightSpoof: 15,
		HealthWeightCoverage: 10, HealthWeightAlerts: 10, HealthWeightTLS: 20,
	})
	if w.TLS != 20 {
		t.Errorf("TLS weight = %v, want 20", w.TLS)
	}
	// An empty config falls back to the defaults rather than scoring nothing.
	if got := WeightsFromConfig(config.Config{}); got != DefaultWeights {
		t.Errorf("empty config = %+v, want the defaults", got)
	}
}

func TestLabelForUsesShareOfMaximum(t *testing.T) {
	// 90 of 115 is 78% — Good, not Excellent, even though 90 ≥ 85.
	if got := LabelFor(90, 115); got != "Good" {
		t.Errorf("LabelFor(90, 115) = %q, want Good", got)
	}
	if got := LabelFor(90, 100); got != "Excellent" {
		t.Errorf("LabelFor(90, 100) = %q, want Excellent", got)
	}
}
