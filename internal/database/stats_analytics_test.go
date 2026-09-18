package database

import (
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// rec builds one record row for the seeded reports below.
func rec(ip string, count int, disp, dkim, spf, headerFrom string, reasons ...string) models.Record {
	r := models.Record{
		Row:         models.Row{SourceIP: ip, Count: count, PolicyEvaluated: models.PolicyEvaluated{Disposition: disp, DKIM: dkim, SPF: spf}},
		Identifiers: models.Identifiers{EnvelopeFrom: headerFrom, HeaderFrom: headerFrom},
		AuthResults: models.AuthResults{
			DKIM: []models.DKIMAuthResult{{Domain: headerFrom, Selector: "s1", Result: dkim}},
			SPF:  []models.SPFAuthResult{{Domain: headerFrom, Scope: "mfrom", Result: spf}},
		},
	}
	for _, t := range reasons {
		r.Row.PolicyEvaluated.Reasons = append(r.Row.PolicyEvaluated.Reasons, models.PolicyOverrideReason{Type: t})
	}
	return r
}

func feedback(org, reportID, domain, policy string, begin int64, recs ...models.Record) *models.Feedback {
	return &models.Feedback{
		ReportMetadata: models.ReportMetadata{OrgName: org, ReportID: reportID,
			DateRange: models.DateRange{Begin: begin, End: begin + 86399}},
		PolicyPublished: models.PolicyPublished{Domain: domain, Policy: policy, Pct: 100, PctPresent: true},
		Records:         recs,
	}
}

// TestAnalyticsSeedAndMatrixProperty seeds a small corpus spanning two domains
// and two windows and checks every phase-2 metric against golden values:
//
//	now-2d  example.com (p=reject): A both 100, B dkim-only 30, C neither 20 (disposition none,
//	                                no reason → C8), D neither 10 (reason forwarded), E spf-only 5 (quarantine)
//	now-2d  other.test  (p=none):   F neither 40, G both 60
//	now-20d example.com (p=reject): A both 200, C neither 5 (reject)
func TestAnalyticsSeedAndMatrixProperty(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	d2 := now.AddDate(0, 0, -2).Unix()
	d20 := now.AddDate(0, 0, -20).Unix()

	fixtures := []*models.Feedback{
		feedback("google.com", "e1", "example.com", "reject", d2,
			rec("10.0.0.1", 100, "none", "pass", "pass", "example.com"),
			rec("10.0.0.2", 30, "none", "pass", "fail", "example.com"),
			rec("10.0.0.3", 20, "none", "fail", "fail", "example.com"),
			rec("10.0.0.4", 10, "none", "fail", "fail", "example.com", "forwarded"),
			rec("10.0.0.5", 5, "quarantine", "fail", "pass", "example.com"),
		),
		feedback("Yahoo", "o1", "other.test", "none", d2,
			rec("10.0.0.6", 40, "none", "fail", "fail", "other.test"),
			rec("10.0.0.7", 60, "none", "pass", "pass", "other.test"),
		),
		feedback("google.com", "e0", "example.com", "reject", d20,
			rec("10.0.0.1", 200, "none", "pass", "pass", "example.com"),
			rec("10.0.0.3", 5, "reject", "fail", "fail", "example.com"),
		),
	}
	for _, fb := range fixtures {
		if _, err := SaveReport(db, fb, fb.ReportMetadata.ReportID+".xml", nil); err != nil {
			t.Fatal(err)
		}
	}

	// Property: Σ matrix buckets == total messages for every domain/window combination.
	for _, dom := range []string{"", "example.com", "other.test"} {
		for _, from := range []int64{0, now.AddDate(0, 0, -7).Unix(), now.AddDate(0, 0, -30).Unix()} {
			f := StatsFilter{Domain: dom, From: from}
			m, err := GetAuthMatrix(db, f)
			if err != nil {
				t.Fatal(err)
			}
			s, err := GetDashboardStats(db, f)
			if err != nil {
				t.Fatal(err)
			}
			if m.Total() != s.TotalMessages {
				t.Errorf("domain=%q from=%d: matrix total %d != messages %d", dom, from, m.Total(), s.TotalMessages)
			}
			if s.Passed != m.BothPass+m.DKIMOnlyPass+m.SPFOnlyPass || s.Failed != m.BothFail {
				t.Errorf("domain=%q from=%d: passed/failed %d/%d inconsistent with matrix %+v", dom, from, s.Passed, s.Failed, m)
			}
			d, err := GetDispositionStats(db, f)
			if err != nil {
				t.Fatal(err)
			}
			if d.Total() != s.TotalMessages {
				t.Errorf("domain=%q from=%d: disposition total %d != %d", dom, from, d.Total(), s.TotalMessages)
			}
		}
	}

	// C1–C4 golden (last 7 days, example.com): 165 msgs, 135 pass, DKIM aligned 130, SPF aligned 105.
	s, _ := GetDashboardStats(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()})
	if s.TotalMessages != 165 || s.Passed != 135 || s.DKIMAlignedPass != 130 || s.SPFAlignedPass != 105 {
		t.Errorf("C1–C4 = %+v", s)
	}
	// C5 golden.
	m, _ := GetAuthMatrix(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()})
	if m.BothPass != 100 || m.DKIMOnlyPass != 30 || m.SPFOnlyPass != 5 || m.BothFail != 30 {
		t.Errorf("C5 = %+v", m)
	}

	// Compare: previous window of equal length must hold the d20 report only.
	f := StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -10).Unix(), Compare: true}
	prev, ok := f.PreviousWindow()
	if !ok {
		t.Fatal("PreviousWindow not ok")
	}
	if prev.To != f.From-1 || f.From-prev.From < 10*86400-2 || f.From-prev.From > 10*86400+2 {
		t.Errorf("previous window = [%d,%d] for current from=%d", prev.From, prev.To, f.From)
	}
	cmp, err := WithComparison(f, func(sf StatsFilter) (*DashboardStats, error) { return GetDashboardStats(db, sf) })
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Previous == nil || (*cmp.Previous).TotalMessages != 205 || cmp.Current.TotalMessages != 165 {
		t.Errorf("comparison = cur %+v prev %+v", cmp.Current, cmp.Previous)
	}
	if _, ok := (StatsFilter{}).PreviousWindow(); ok {
		t.Error("all-time filter must not have a previous window")
	}

	// C6 golden.
	d, _ := GetDispositionStats(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()})
	if d.None != 160 || d.Quarantine != 5 || d.Reject != 0 {
		t.Errorf("C6 = %+v", d)
	}

	// C7: p=reject → rate = enforced/failing = 5/30 (quarantine 5 of 30 neither).
	enf, err := GetEnforcementEffectiveness(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if enf.Policy != "reject" || enf.Failing != 30 || enf.Enforced != 5 || enf.Rate == nil || *enf.Rate < 16.6 || *enf.Rate > 16.7 {
		t.Errorf("C7 = %+v rate=%v", enf, enf.Rate)
	}
	// C7: p=none → Rate nil.
	enfNone, _ := GetEnforcementEffectiveness(db, StatsFilter{Domain: "other.test"})
	if enfNone.Policy != "none" || enfNone.Rate != nil {
		t.Errorf("C7 none = %+v rate=%v", enfNone, enfNone.Rate)
	}

	// C8: only 10.0.0.3's 20 messages (disposition none under p=reject, no reason);
	// 10.0.0.4 has a reason, 10.0.0.5 was quarantined, other.test is p=none.
	un, err := GetUnexplainedOverrides(db, StatsFilter{From: now.AddDate(0, 0, -7).Unix()}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if un.Messages != 20 || un.Records != 1 || len(un.Sources) != 1 || un.Sources[0].SourceIP != "10.0.0.3" {
		t.Errorf("C8 = %+v", un)
	}

	// S1: inventory for example.com over 7 days.
	th := ipinfo.DefaultPatternThresholds
	rows, total, err := GetSourceInventory(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()}, SourceQuery{Sort: "ip", Dir: "asc"}, th)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || len(rows) != 5 {
		t.Fatalf("S1 rows = %d/%d", len(rows), total)
	}
	byIP := map[string]SourceInventoryRow{}
	for _, r := range rows {
		byIP[r.SourceIP] = r
	}
	if r := byIP["10.0.0.1"]; r.BothPass != 100 || r.Pattern != ipinfo.PatternHealthy || r.IsNew || r.FirstSeen != d20 || r.RawDKIMPass != 100 {
		t.Errorf("S1 10.0.0.1 = %+v", r)
	}
	if r := byIP["10.0.0.2"]; r.DKIMOnly != 30 || r.Pattern != ipinfo.PatternForwarder || !r.IsNew {
		t.Errorf("S1 10.0.0.2 = %+v", r)
	}
	if r := byIP["10.0.0.3"]; r.Neither != 20 || r.Pattern != ipinfo.PatternSpoofSuspect || r.IsNew || r.DispNone != 20 {
		t.Errorf("S1 10.0.0.3 = %+v", r)
	}
	if r := byIP["10.0.0.5"]; r.SPFOnly != 5 || r.Pattern != ipinfo.PatternBrokenSigning || r.DispQuarantine != 5 {
		t.Errorf("S1 10.0.0.5 = %+v", r)
	}

	// S3 override via ip_labels flips the SQL pattern too.
	if err := UpsertIPLabel(db, IPLabel{IP: "10.0.0.3", Label: "Known relay", Classification: "known_good"}); err != nil {
		t.Fatal(err)
	}
	rows, _, _ = GetSourceInventory(db, StatsFilter{Domain: "example.com"}, SourceQuery{Search: "10.0.0.3"}, th)
	if len(rows) != 1 || rows[0].Pattern != ipinfo.PatternHealthy || rows[0].Label != "Known relay" {
		t.Errorf("S3 override = %+v", rows)
	}
	// Pattern filter honours the override: only 10.0.0.4 (10 neither, no label) remains a suspect.
	rows, _, _ = GetSourceInventory(db, StatsFilter{Domain: "example.com"}, SourceQuery{Pattern: ipinfo.PatternSpoofSuspect}, th)
	if len(rows) != 1 || rows[0].SourceIP != "10.0.0.4" {
		t.Errorf("pattern filter after override = %+v", rows)
	}

	// S2: new sources in the last 7 days for example.com = 10.0.0.2, .4, .5 (not .1/.3, seen 20d ago).
	newSrc, err := GetNewSources(db, StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()}, th, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(newSrc) != 3 {
		t.Errorf("S2 = %d rows: %+v", len(newSrc), newSrc)
	}
	if all, _ := GetNewSources(db, StatsFilter{}, th, 10); all != nil {
		t.Errorf("S2 all-time should be nil, got %d", len(all))
	}

	// Source detail.
	det, err := GetSourceDetail(db, "10.0.0.1", StatsFilter{From: now.AddDate(0, 0, -30).Unix()}, th)
	if err != nil || det == nil {
		t.Fatalf("detail: %v %v", det, err)
	}
	if det.Row.TotalMessages != 300 || len(det.Selectors) != 1 || len(det.Reporters) != 1 || len(det.Timeline) == 0 {
		t.Errorf("detail = %+v", det.Row)
	}
	if missing, _ := GetSourceDetail(db, "192.0.2.99", StatsFilter{}, th); missing != nil {
		t.Error("detail for unknown ip should be nil")
	}

	// S4: without cache → not resolved; with cache → split.
	sv, err := GetSpoofVolume(db, StatsFilter{From: now.AddDate(0, 0, -7).Unix()}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if sv.Resolved || sv.Total != 70 || sv.Unresolved != 70 || len(sv.Domains) != 2 {
		t.Errorf("S4 unresolved = %+v", sv)
	}
	if err := UpsertSPFCache(db, SPFCacheEntry{Domain: "example.com", CIDRs: `["10.0.0.4/32"]`, CheckedAt: now.Unix()}); err != nil {
		t.Fatal(err)
	}
	sv, _ = GetSpoofVolume(db, StatsFilter{From: now.AddDate(0, 0, -7).Unix()}, 10)
	if !sv.Resolved || sv.InSPF != 10 || sv.NotInSPF != 20 || sv.Unresolved != 40 || len(sv.Domains) != 1 || sv.Domains[0] != "other.test" {
		t.Errorf("S4 resolved = %+v", sv)
	}
	if sv.NotInSPFShare() < 66.6 || sv.NotInSPFShare() > 66.7 {
		t.Errorf("S4 share = %v", sv.NotInSPFShare())
	}
}

func TestSPFCacheEntryContains(t *testing.T) {
	e := SPFCacheEntry{CIDRs: `["192.0.2.0/24","2001:db8::/32","198.51.100.7"]`}
	for ip, want := range map[string]bool{
		"192.0.2.10": true, "192.0.3.1": false, "2001:db8:1::1": true, "198.51.100.7": true, "198.51.100.8": false, "garbage": false,
	} {
		if got := e.Contains(ip); got != want {
			t.Errorf("Contains(%s) = %v want %v", ip, got, want)
		}
	}
}
