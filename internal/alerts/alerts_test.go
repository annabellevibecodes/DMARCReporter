package alerts

import (
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

func testCfg() config.Config {
	return config.Config{
		AlertWebhookURL:   "http://webhook.invalid/", // enables delivery
		AlertPassRateDrop: 5, AlertReporterGapDays: 3,
		AlertNewSourceMin: 10, AlertMinWindowMessages: 50, AlertKnownDropPts: 20,
		AlertNewSelectorHours: 48, AlertSelectorMissingDays: 7, AlertDNSErrorPct: 5,
		AlertOverrideFactor: 3, AlertSpoofFactor: 3, AlertSpoofAbs: 50, AlertRecentHours: 48,
	}
}

func openDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type recOpt struct {
	ip               string
	count            int
	dkim, spf        string
	disposition      string
	selector, sigDom string
	rawDKIM, rawSPF  string
	reason           string
}

func save(t *testing.T, db *sqlx.DB, org, id, domain, policy string, begin int64, recs ...recOpt) {
	t.Helper()
	fb := &models.Feedback{
		ReportMetadata:  models.ReportMetadata{OrgName: org, ReportID: id, DateRange: models.DateRange{Begin: begin, End: begin + 86399}},
		PolicyPublished: models.PolicyPublished{Domain: domain, Policy: policy, ADKIM: "r", ASPF: "r", Pct: 100, PctPresent: true},
	}
	for _, r := range recs {
		disp := r.disposition
		if disp == "" {
			disp = "none"
		}
		rec := models.Record{
			Row:         models.Row{SourceIP: r.ip, Count: r.count, PolicyEvaluated: models.PolicyEvaluated{Disposition: disp, DKIM: r.dkim, SPF: r.spf}},
			Identifiers: models.Identifiers{HeaderFrom: domain, EnvelopeFrom: domain},
		}
		if r.selector != "" {
			res := r.rawDKIM
			if res == "" {
				res = r.dkim
			}
			sd := r.sigDom
			if sd == "" {
				sd = domain
			}
			rec.AuthResults.DKIM = []models.DKIMAuthResult{{Domain: sd, Selector: r.selector, Result: res}}
		}
		if r.rawSPF != "" {
			rec.AuthResults.SPF = []models.SPFAuthResult{{Domain: domain, Result: r.rawSPF}}
		}
		if r.reason != "" {
			rec.Row.PolicyEvaluated.Reasons = []models.PolicyOverrideReason{{Type: r.reason}}
		}
		fb.Records = append(fb.Records, rec)
	}
	if _, err := database.SaveReport(db, fb, id+".xml", nil); err != nil {
		t.Fatal(err)
	}
}

func fire(t *testing.T, db *sqlx.DB, cfg config.Config) (map[string][]Alert, []Alert) {
	t.Helper()
	fired, delivered := EvaluateWith(db, cfg, func(config.Config, []Alert) {})
	byRule := map[string][]Alert{}
	for _, a := range fired {
		byRule[a.Rule] = append(byRule[a.Rule], a)
	}
	return byRule, delivered
}

// Baseline: healthy traffic, one reporter daily, expected selector signing — nothing fires.
func seedBaseline(t *testing.T, db *sqlx.DB) {
	now := time.Now().UTC()
	for i := 1; i <= 14; i++ {
		begin := now.AddDate(0, 0, -i).Truncate(24 * time.Hour).Unix()
		save(t, db, "google.com", "g"+itoa(i), "example.com", "reject", begin,
			recOpt{ip: "10.0.0.1", count: 100, dkim: "pass", spf: "pass", selector: "s1", rawSPF: "pass"})
	}
	if err := database.SetSelectorExpected(db, "example.com", "s1", 1); err != nil {
		t.Fatal(err)
	}
}

func itoa(i int) string {
	return time.Unix(int64(i), 0).UTC().Format("05") + "-" + string(rune('a'+i%26))
}

func TestRulesSilentOnBaseline(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	byRule, delivered := fire(t, db, testCfg())
	if len(byRule) != 0 || len(delivered) != 0 {
		t.Errorf("baseline fired: %+v", byRule)
	}
}

func TestRuleNewFailingSource(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()
	save(t, db, "google.com", "new1", "example.com", "reject", now.Add(-20*time.Hour).Unix(),
		recOpt{ip: "203.0.113.9", count: 60, dkim: "fail", spf: "fail"}, // ≥ 50 all failing → critical
		recOpt{ip: "203.0.113.10", count: 5, dkim: "fail", spf: "fail"}) // below ALERT_NEW_SOURCE_MIN
	cfg := testCfg()
	cfg.AlertPassRateDrop = 50 // keep X2 quiet: the 60 failures also dent the weekly pass rate
	byRule, delivered := fire(t, db, cfg)
	got := byRule["new_failing_source"]
	if len(got) != 1 || got[0].Key != "203.0.113.9" || got[0].Domain != "example.com" || got[0].Severity != database.SeverityCritical {
		t.Fatalf("X1 = %+v", got)
	}
	if len(delivered) != 1 {
		t.Errorf("delivered = %d", len(delivered))
	}
	// Firing again: count increments, nothing redelivered.
	_, delivered2 := fire(t, db, cfg)
	if len(delivered2) != 0 {
		t.Errorf("second run redelivered %d", len(delivered2))
	}
	list, _ := database.ListAlerts(db, "open", "", 10)
	if len(list) != 1 || list[0].Count != 2 || list[0].Rule != "new_failing_source" {
		t.Errorf("stored = %+v", list)
	}
	// Acknowledge → the next firing re-opens it (deliver=true at the DB level;
	// alerts_sent still dedupes same-day delivery).
	if ok, _ := database.AcknowledgeAlert(db, list[0].ID); !ok {
		t.Fatal("ack failed")
	}
	deliver, _, err := database.UpsertAlert(db, database.Alert{Rule: "new_failing_source", Domain: "example.com", Key: "203.0.113.9", Severity: "warning"})
	if err != nil || !deliver {
		t.Errorf("reopen deliver=%v err=%v", deliver, err)
	}
	list, _ = database.ListAlerts(db, "open", "", 10)
	if len(list) != 1 || list[0].Count != 3 || list[0].AcknowledgedAt != 0 {
		t.Errorf("after reopen = %+v", list)
	}
}

func TestRulePassRateDrop(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	for i := 1; i <= 14; i++ {
		begin := now.AddDate(0, 0, -i).Truncate(24 * time.Hour).Unix()
		dkim := "pass"
		if i <= 7 {
			dkim = "fail" // this week: everything fails
		}
		save(t, db, "google.com", "p"+itoa(i), "example.com", "none", begin,
			recOpt{ip: "10.0.0.1", count: 20, dkim: dkim, spf: dkim, selector: "s1"})
	}
	byRule, _ := fire(t, db, testCfg())
	got := byRule["pass_rate_drop"]
	if len(got) != 1 || got[0].Domain != "example.com" || got[0].Severity != database.SeverityCritical {
		t.Errorf("X2 = %+v", got)
	}
}

func TestRuleKnownSourceDegraded(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	for i := 1; i <= 9; i++ {
		begin := now.AddDate(0, 0, -i).Truncate(24 * time.Hour).Unix()
		dkim := "pass"
		if i <= 1 {
			dkim = "fail"
		}
		save(t, db, "google.com", "k"+itoa(i), "example.com", "none", begin,
			recOpt{ip: "10.0.0.5", count: 20, dkim: dkim, spf: dkim})
	}
	if err := database.UpsertIPLabel(db, database.IPLabel{IP: "10.0.0.5", Label: "Relay", Classification: "known_good"}); err != nil {
		t.Fatal(err)
	}
	byRule, _ := fire(t, db, testCfg())
	got := byRule["known_source_degraded"]
	if len(got) != 1 || got[0].Key != "10.0.0.5" {
		t.Errorf("X3 = %+v", got)
	}
}

func TestRuleNewAndMissingSelector(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()
	// New unexpected selector seen yesterday.
	save(t, db, "google.com", "sel1", "example.com", "reject", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass", selector: "k2"})
	// Expected selector last seen 10 days ago.
	save(t, db, "google.com", "sel2", "example.com", "reject", now.AddDate(0, 0, -10).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass", selector: "old"})
	if err := database.SetSelectorExpected(db, "example.com", "old", 1); err != nil {
		t.Fatal(err)
	}
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["new_selector"]; len(got) != 1 || got[0].Key != "k2" {
		t.Errorf("X4 = %+v", got)
	}
	if got := byRule["selector_missing"]; len(got) != 1 || got[0].Key != "old" {
		t.Errorf("X5 = %+v", got)
	}
	// Marking k2 expected silences X4.
	if err := database.SetSelectorExpected(db, "example.com", "k2", 1); err != nil {
		t.Fatal(err)
	}
	byRule, _ = fire(t, db, testCfg())
	if got := byRule["new_selector"]; len(got) != 0 {
		t.Errorf("X4 after expected = %+v", got)
	}
}

func TestRuleReporterSilent(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()
	save(t, db, "Yahoo", "y1", "example.com", "reject", now.AddDate(0, 0, -6).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass"})
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["reporter_silent"]; len(got) != 1 || got[0].Key != "Yahoo" {
		t.Errorf("X6 = %+v", got)
	}
}

func TestRulePolicyChangedAndInconsistent(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	save(t, db, "google.com", "c1", "example.com", "none", now.AddDate(0, 0, -3).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass"})
	save(t, db, "google.com", "c2", "example.com", "reject", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass"})
	// Outlook still sees p=none in the same recent window → inconsistent.
	save(t, db, "Enterprise Outlook", "o1", "example.com", "none", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 10, dkim: "pass", spf: "pass"})
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["policy_changed"]; len(got) != 1 || got[0].Domain != "example.com" || got[0].Severity != database.SeverityInfo {
		t.Errorf("X7 = %+v", got)
	}
	if got := byRule["policy_inconsistent"]; len(got) != 1 || got[0].Domain != "example.com" {
		t.Errorf("X8 = %+v", got)
	}
}

func TestRuleDNSErrorSpike(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	save(t, db, "Yahoo", "d1", "example.com", "none", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 30, dkim: "fail", spf: "fail", selector: "s1", rawDKIM: "temperror", rawSPF: "temperror"},
		recOpt{ip: "10.0.0.2", count: 10, dkim: "pass", spf: "pass", selector: "s1", rawSPF: "pass"})
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["dns_error_spike"]; len(got) != 1 || got[0].Key != "Yahoo" {
		t.Errorf("X9 = %+v", got)
	}
}

func TestRuleOverrideSpike(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	// Baseline: 2 overridden messages/day for a week, then 40 yesterday.
	for i := 3; i <= 9; i++ {
		save(t, db, "google.com", "ov"+itoa(i), "example.com", "reject", now.AddDate(0, 0, -i).Truncate(24*time.Hour).Unix(),
			recOpt{ip: "10.0.0.1", count: 2, dkim: "fail", spf: "fail", reason: "forwarded"})
	}
	save(t, db, "google.com", "ovnow", "example.com", "reject", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "10.0.0.1", count: 40, dkim: "fail", spf: "fail", reason: "forwarded"})
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["override_spike"]; len(got) != 1 || got[0].Domain != "example.com" {
		t.Errorf("X10 = %+v", got)
	}
}

func TestDeliveryDisabledStillPersists(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()
	save(t, db, "google.com", "new2", "example.com", "reject", now.Add(-20*time.Hour).Unix(),
		recOpt{ip: "203.0.113.9", count: 60, dkim: "fail", spf: "fail"})
	cfg := testCfg()
	cfg.AlertWebhookURL = "" // no channel
	cfg.AlertPassRateDrop = 50
	called := false
	fired, delivered := EvaluateWith(db, cfg, func(config.Config, []Alert) { called = true })
	if len(fired) == 0 || called || len(delivered) != 1 {
		t.Errorf("fired=%d delivered=%d called=%v", len(fired), len(delivered), called)
	}
	open, _, _ := database.CountOpenAlerts(db, "example.com")
	if open != 1 {
		t.Errorf("open alerts = %d", open)
	}
}

func TestRuleSpoofSpike(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	// Baseline: 1 unauthenticated message/day from outside SPF; yesterday 80.
	for i := 3; i <= 9; i++ {
		save(t, db, "google.com", "sp"+itoa(i), "example.com", "reject", now.AddDate(0, 0, -i).Truncate(24*time.Hour).Unix(),
			recOpt{ip: "203.0.113.50", count: 1, dkim: "fail", spf: "fail"},
			recOpt{ip: "10.0.0.1", count: 50, dkim: "pass", spf: "pass"})
	}
	save(t, db, "google.com", "spnow", "example.com", "reject", now.AddDate(0, 0, -1).Truncate(24*time.Hour).Unix(),
		recOpt{ip: "203.0.113.50", count: 80, dkim: "fail", spf: "fail"},
		recOpt{ip: "10.0.0.9", count: 5, dkim: "fail", spf: "fail"}) // inside SPF → not counted
	cfg := testCfg()
	cfg.AlertPassRateDrop = 50
	// Without an SPF expansion the rule stays silent.
	byRule, _ := fire(t, db, cfg)
	if got := byRule["spoof_spike"]; len(got) != 0 {
		t.Errorf("X11 fired without SPF cache: %+v", got)
	}
	if err := database.UpsertSPFCache(db, database.SPFCacheEntry{Domain: "example.com", CIDRs: `["10.0.0.0/8"]`, CheckedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	byRule, _ = fire(t, db, cfg)
	got := byRule["spoof_spike"]
	if len(got) != 1 || got[0].Domain != "example.com" || got[0].Severity != database.SeverityCritical || got[0].Payload["not_in_spf"] != int64(80) {
		t.Errorf("X11 = %+v", got)
	}
}
