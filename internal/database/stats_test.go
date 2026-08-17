package database

import (
	"errors"
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/jmoiron/sqlx"
)

func openTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// testFeedback builds a report with two records: 100 passing messages from
// 192.0.2.10 (DKIM pass via selector s1) and 10 failing messages from
// 192.0.2.20 (both fail, policy overridden as forwarded).
func testFeedback(reportID string, begin int64) *models.Feedback {
	return &models.Feedback{
		ReportMetadata: models.ReportMetadata{
			OrgName:  "google.com",
			ReportID: reportID,
			DateRange: models.DateRange{
				Begin: begin,
				End:   begin + 86399,
			},
		},
		PolicyPublished: models.PolicyPublished{
			Domain: "example.com",
			Policy: "quarantine",
			Pct:    100,
		},
		Records: []models.Record{
			{
				Row: models.Row{
					SourceIP: "192.0.2.10",
					Count:    100,
					PolicyEvaluated: models.PolicyEvaluated{
						Disposition: "none", DKIM: "pass", SPF: "fail",
					},
				},
				Identifiers: models.Identifiers{
					EnvelopeTo: "gmail.com", EnvelopeFrom: "example.com", HeaderFrom: "example.com",
				},
				AuthResults: models.AuthResults{
					DKIM: []models.DKIMAuthResult{{Domain: "example.com", Selector: "s1", Result: "pass"}},
				},
			},
			{
				Row: models.Row{
					SourceIP: "192.0.2.20",
					Count:    10,
					PolicyEvaluated: models.PolicyEvaluated{
						Disposition: "none", DKIM: "fail", SPF: "fail",
						Reasons: []models.PolicyOverrideReason{{Type: "forwarded"}},
					},
				},
				Identifiers: models.Identifiers{
					EnvelopeTo: "gmail.com", EnvelopeFrom: "example.com", HeaderFrom: "example.com",
				},
				AuthResults: models.AuthResults{
					DKIM: []models.DKIMAuthResult{{Domain: "example.com", Selector: "s1", Result: "fail"}},
				},
			},
		},
	}
}

func TestSaveReportAndDashboardStats(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", []byte("<feedback/>")); err != nil {
		t.Fatalf("SaveReport: %v", err)
	}

	s, err := GetDashboardStats(db, StatsFilter{})
	if err != nil {
		t.Fatalf("GetDashboardStats: %v", err)
	}
	if s.TotalMessages != 110 || s.Passed != 100 || s.Failed != 10 {
		t.Errorf("stats = total %d passed %d failed %d, want 110/100/10", s.TotalMessages, s.Passed, s.Failed)
	}
	if s.TotalReports != 1 || s.TotalDomains != 1 {
		t.Errorf("reports/domains = %d/%d, want 1/1", s.TotalReports, s.TotalDomains)
	}
}

func TestSaveReportDuplicate(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatalf("first SaveReport: %v", err)
	}
	_, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil)
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second SaveReport err = %v, want ErrDuplicate", err)
	}
}

func TestDKIMSelectorStatsWeightedByCount(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}

	stats, err := GetDKIMSelectorStats(db, "example.com")
	if err != nil {
		t.Fatalf("GetDKIMSelectorStats: %v", err)
	}
	if len(stats) != 1 {
		t.Fatalf("selector stats = %d rows, want 1", len(stats))
	}
	s := stats[0]
	// 100 messages passed, 10 failed — weighted by message count, not row count.
	if s.Total != 110 || s.Passed != 100 || s.Failed != 10 {
		t.Errorf("selector %q = total %d passed %d failed %d, want 110/100/10", s.Selector, s.Total, s.Passed, s.Failed)
	}
}

func TestPolicyOverrideBreakdown(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}

	stats, err := GetPolicyOverrideBreakdown(db, StatsFilter{})
	if err != nil {
		t.Fatalf("GetPolicyOverrideBreakdown: %v", err)
	}
	if len(stats) != 1 || stats[0].Type != "forwarded" || stats[0].TotalMessages != 10 {
		t.Errorf("override breakdown = %+v, want one 'forwarded' row with 10 messages", stats)
	}
}

func TestTrendDataDailyWithGapFill(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}

	from := time.Now().UTC().AddDate(0, 0, -7).Unix()
	if !TrendDaily(from) {
		t.Fatal("TrendDaily(7d ago) = false, want true")
	}
	points, err := GetTrendData(db, StatsFilter{From: from}, true)
	if err != nil {
		t.Fatalf("GetTrendData: %v", err)
	}
	if len(points) != 1 {
		t.Fatalf("raw points = %d, want 1", len(points))
	}

	filled := FillTrendGaps(points, from, 0, true)
	if len(filled) != 8 { // 7 days ago through today inclusive
		t.Errorf("filled points = %d, want 8", len(filled))
	}
	var nonZero int
	var passed int64
	for _, p := range filled {
		if p.Passed != 0 || p.Failed != 0 {
			nonZero++
			passed = p.Passed
		}
	}
	if nonZero != 1 || passed != 100 {
		t.Errorf("nonZero buckets = %d (passed=%d), want 1 bucket with 100 passed", nonZero, passed)
	}
}

func TestTrendWeeklyLabelsMatchSQLite(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("r1", begin), "r1.xml", nil); err != nil {
		t.Fatal(err)
	}
	points, err := GetTrendData(db, StatsFilter{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) == 0 {
		t.Fatal("no weekly points")
	}
	// The Go-side label for the same timestamp must match SQLite's %G-%V bucket,
	// otherwise gap filling would duplicate buckets.
	want := trendBucketLabel(time.Unix(begin, 0), false)
	if points[0].Week != want {
		t.Errorf("sqlite bucket %q != go bucket %q", points[0].Week, want)
	}
	filled := FillTrendGaps(points, 0, 0, false)
	seen := map[string]bool{}
	for _, p := range filled {
		if seen[p.Week] {
			t.Errorf("duplicate bucket %q after gap fill", p.Week)
		}
		seen[p.Week] = true
	}
}

func TestListDomainsFilteredScopesByPeriod(t *testing.T) {
	db := openTestDB(t)
	old := time.Now().UTC().AddDate(-2, 0, 0).Unix()
	recent := time.Now().UTC().AddDate(0, 0, -2).Unix()
	if _, err := SaveReport(db, testFeedback("old", old), "old.xml", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveReport(db, testFeedback("recent", recent), "recent.xml", nil); err != nil {
		t.Fatal(err)
	}

	all, err := ListDomainsFiltered(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].TotalMessages != 220 {
		t.Errorf("unfiltered = %+v, want one domain with 220 messages", all)
	}

	from := time.Now().UTC().AddDate(0, 0, -30).Unix()
	scoped, err := ListDomainsFiltered(db, StatsFilter{From: from})
	if err != nil {
		t.Fatal(err)
	}
	if len(scoped) != 1 || scoped[0].TotalMessages != 110 {
		t.Errorf("scoped = %+v, want one domain with 110 messages", scoped)
	}
}

func TestGetActivePolicyEmptyDB(t *testing.T) {
	db := openTestDB(t)
	policy, err := GetActivePolicy(db, StatsFilter{})
	if err != nil {
		t.Fatalf("GetActivePolicy on empty db: %v", err)
	}
	if policy != "" {
		t.Errorf("policy = %q, want empty", policy)
	}
}
