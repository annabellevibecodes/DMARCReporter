package database

import (
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/psl"
)

// authRec builds a record with explicit raw auth results.
func authRec(ip string, count int, evalDKIM, evalSPF, envFrom, headerFrom string, dkim []models.DKIMAuthResult, spf []models.SPFAuthResult) models.Record {
	return models.Record{
		Row:         models.Row{SourceIP: ip, Count: count, PolicyEvaluated: models.PolicyEvaluated{Disposition: "none", DKIM: evalDKIM, SPF: evalSPF}},
		Identifiers: models.Identifiers{EnvelopeFrom: envFrom, HeaderFrom: headerFrom},
		AuthResults: models.AuthResults{DKIM: dkim, SPF: spf},
	}
}

func TestAuthMetricsGolden(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	d2 := now.AddDate(0, 0, -2).Unix()
	d30 := now.AddDate(0, 0, -30).Unix()

	fb := feedback("google.com", "a1", "example.com", "quarantine", d2,
		// 100 msgs: exact-aligned selector s1 pass, spf mfrom pass
		authRec("10.0.0.1", 100, "pass", "pass", "example.com", "example.com",
			[]models.DKIMAuthResult{{Domain: "example.com", Selector: "s1", Result: "pass"}},
			[]models.SPFAuthResult{{Domain: "example.com", Scope: "mfrom", Result: "pass"}}),
		// 20 msgs: relaxed-aligned selector k1 (mail.example.com), spf helo pass on other domain (gap)
		authRec("10.0.0.2", 20, "pass", "fail", "bounce.example.com", "example.com",
			[]models.DKIMAuthResult{{Domain: "mail.example.com", Selector: "k1", Result: "pass"}},
			[]models.SPFAuthResult{{Domain: "relay.example.net", Scope: "helo", Result: "pass"}}),
		// 10 msgs: third-party signer passes raw but eval dkim fail (gap), spf temperror
		authRec("10.0.0.3", 10, "fail", "fail", "esp.example.net", "example.com",
			[]models.DKIMAuthResult{{Domain: "esp.example.net", Selector: "esp", Result: "pass"}, {Domain: "example.com", Selector: "s1", Result: "fail"}},
			[]models.SPFAuthResult{{Domain: "esp.example.net", Scope: "mfrom", Result: "temperror"}}),
		// 5 msgs: null sender, no signatures, spf none
		authRec("10.0.0.4", 5, "fail", "fail", "<>", "example.com", nil,
			[]models.SPFAuthResult{{Domain: "", Scope: "helo", Result: "none"}}),
	)
	if _, err := SaveReport(db, fb, "a1.xml", nil); err != nil {
		t.Fatal(err)
	}
	// Older report so selector s1 has an all-time first_seen before the window.
	old := feedback("Yahoo", "a0", "example.com", "quarantine", d30,
		authRec("10.0.0.1", 50, "pass", "pass", "example.com", "example.com",
			[]models.DKIMAuthResult{{Domain: "example.com", Selector: "s1", Result: "pass"}},
			[]models.SPFAuthResult{{Domain: "example.com", Result: "pass"}}))
	if _, err := SaveReport(db, old, "a0.xml", nil); err != nil {
		t.Fatal(err)
	}
	if err := SetSelectorExpected(db, "example.com", "s1", 1); err != nil {
		t.Fatal(err)
	}

	f := StatsFilter{Domain: "example.com", From: now.AddDate(0, 0, -7).Unix()}

	// A1
	sel, err := GetSelectorInventory(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 3 { // s1 (two rows fold into one), k1, esp
		t.Fatalf("A1 selectors = %+v", sel)
	}
	byKey := map[string]DKIMSelectorStat{}
	for _, s := range sel {
		byKey[s.SigningDomain+"/"+s.Selector] = s
	}
	if s := byKey["example.com/s1"]; s.Total != 110 || s.Passed != 100 || s.Sources != 2 || s.Expected != 1 || s.FirstSeen != d30 || s.IsNew {
		t.Errorf("A1 s1 = %+v", s)
	}
	if s := byKey["mail.example.com/k1"]; !s.IsNew || s.Expected != -1 || s.Sources != 1 {
		t.Errorf("A1 k1 = %+v", s)
	}

	// A2: pass 130 (100+20+10), fail 10.
	raw, _ := GetDKIMRawResults(db, f)
	got := map[string]int64{}
	for _, r := range raw {
		got[r.Value] = r.Messages
	}
	if got["pass"] != 130 || got["fail"] != 10 {
		t.Errorf("A2 = %v", got)
	}

	// A3: exact 110 (100 s1 + 10 s1-fail row), relaxed 20, third-party 10.
	al, err := GetDKIMSigningAlignment(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if al.Exact != 110 || al.Relaxed != 20 || al.ThirdParty != 10 || al.Total != 140 {
		t.Errorf("A3 = %+v", al)
	}
	if len(al.ThirdPartyDomains) != 1 || al.ThirdPartyDomains[0].Domain != "esp.example.net" {
		t.Errorf("A3 third parties = %+v", al.ThirdPartyDomains)
	}
	hist := map[int]int64{}
	for _, h := range al.Histogram {
		hist[h.Signatures] = h.Messages
	}
	if hist[0] != 5 || hist[1] != 120 || hist[2] != 10 {
		t.Errorf("A3 histogram = %v", hist)
	}

	// A4 / A5
	spfRaw, _ := GetSPFRawResults(db, f)
	got = map[string]int64{}
	for _, r := range spfRaw {
		got[r.Value] = r.Messages
	}
	if got["pass"] != 120 || got["temperror"] != 10 || got["none"] != 5 {
		t.Errorf("A4 = %v", got)
	}
	scope, _ := GetSPFScopeSplit(db, f)
	got = map[string]int64{}
	for _, r := range scope {
		got[r.Value] = r.Messages
	}
	if got["mfrom"] != 110 || got["helo"] != 25 {
		t.Errorf("A5 = %v", got)
	}

	// A6
	ef, err := GetEnvelopeFromAlignment(db, f)
	if err != nil {
		t.Fatal(err)
	}
	cls := map[string]string{}
	for _, r := range ef {
		cls[r.EnvelopeFrom] = r.Alignment
	}
	if cls["example.com"] != psl.AlignExact || cls["bounce.example.com"] != psl.AlignRelaxed || cls["esp.example.net"] != psl.AlignMisaligned || cls["<>"] != psl.AlignNullSender {
		t.Errorf("A6 = %v", cls)
	}

	// A7: 10.0.0.2 (spf raw pass, eval fail) and 10.0.0.3 (dkim raw pass, eval fail).
	gap, err := GetAlignmentGap(db, f, 10)
	if err != nil {
		t.Fatal(err)
	}
	if gap.Messages != 30 || gap.Records != 2 || gap.DKIMMessages != 10 || gap.SPFMessages != 20 || len(gap.Pairs) != 2 {
		t.Errorf("A7 = %+v", gap)
	}

	// A8: google.com raw results = dkim 140 + spf 135 = 275, errors 10 (temperror).
	dns, err := GetDNSErrorRate(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(dns) != 1 || dns[0].OrgName != "google.com" || dns[0].Results != 275 || dns[0].Errors != 10 {
		t.Errorf("A8 = %+v", dns)
	}
	if dns[0].Rate < 3.6 || dns[0].Rate > 3.7 {
		t.Errorf("A8 rate = %v", dns[0].Rate)
	}
}

func policyFeedback(org, id, domain string, begin int64, pp models.PolicyPublished, headerFrom string, count int, pass bool) *models.Feedback {
	pp.Domain = domain
	ev := "fail"
	if pass {
		ev = "pass"
	}
	return &models.Feedback{
		ReportMetadata:  models.ReportMetadata{OrgName: org, ReportID: id, DateRange: models.DateRange{Begin: begin, End: begin + 86399}},
		PolicyPublished: pp,
		Records: []models.Record{{
			Row:         models.Row{SourceIP: "10.1.0.1", Count: count, PolicyEvaluated: models.PolicyEvaluated{Disposition: "none", DKIM: ev, SPF: ev}},
			Identifiers: models.Identifiers{HeaderFrom: headerFrom, EnvelopeFrom: headerFrom},
		}},
	}
}

func TestPolicyMetricsGolden(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC()
	day := func(n int) int64 { return now.AddDate(0, 0, -n).Truncate(24 * time.Hour).Unix() }

	none := models.PolicyPublished{Policy: "none", ADKIM: "r", ASPF: "r", Pct: 100, PctPresent: true}
	// Google reports sp explicitly + np; Outlook reports fo; Yahoo omits sp/pct.
	rejectG := models.PolicyPublished{Policy: "reject", SubdomainPolicy: "reject", SPPresent: true, NP: "reject", ADKIM: "r", ASPF: "r", Pct: 100, PctPresent: true}
	rejectO := models.PolicyPublished{Policy: "reject", SubdomainPolicy: "reject", SPPresent: true, ADKIM: "r", ASPF: "r", Pct: 100, PctPresent: true, FailureOptions: "1", FOPresent: true}
	rejectY := models.PolicyPublished{Policy: "reject", ADKIM: "r", ASPF: "r", Pct: 100}
	// A disagreeing reporter: sees sp=none.
	rejectSPNone := models.PolicyPublished{Policy: "reject", SubdomainPolicy: "none", SPPresent: true, ADKIM: "r", ASPF: "r", Pct: 100, PctPresent: true}

	fixtures := []*models.Feedback{
		policyFeedback("google.com", "g10", "example.com", day(10), none, "example.com", 100, false),
		policyFeedback("google.com", "g9", "example.com", day(9), none, "example.com", 100, false),
		policyFeedback("google.com", "g5", "example.com", day(5), rejectG, "example.com", 100, true), // change none→reject
		policyFeedback("Enterprise Outlook", "o8", "example.com", day(8), none, "example.com", 50, false),
		policyFeedback("Enterprise Outlook", "o5", "example.com", day(5), rejectO, "example.com", 50, true), // same change same day
		policyFeedback("Yahoo", "y4", "example.com", day(4), rejectY, "news.example.com", 30, true),         // subdomain traffic
		policyFeedback("GMX", "x3", "example.com", day(3), rejectSPNone, "example.com", 10, false),          // disagrees on sp; failing
	}
	for _, fb := range fixtures {
		if _, err := SaveReport(db, fb, fb.ReportMetadata.ReportID+".xml", nil); err != nil {
			t.Fatal(err)
		}
	}

	// P1: dominant tuple in the last 7 days is Google's reject record (100 msgs); GMX differs.
	f := StatsFilter{Domain: "example.com", From: day(7)}
	ap, err := GetActivePolicyTuple(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if ap.Tuple == nil || ap.Tuple.P != "reject" || ap.Tuple.NP != "reject" || ap.Consistent {
		t.Fatalf("P1 = %+v", ap)
	}
	agree := map[string]bool{}
	for _, r := range ap.Reporters {
		agree[r.OrgName] = r.Agrees
	}
	if !agree["google.com"] || !agree["Enterprise Outlook"] || !agree["Yahoo"] || agree["GMX"] {
		t.Errorf("P1 per-reporter agreement = %v", agree)
	}

	// P2: two effective tuples (sp=reject via 3 reporters folding 3 raw variants; sp=none via GMX).
	cons, err := GetPolicyConsistency(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(cons) != 2 || cons[0].SP != "reject" || cons[0].Variants != 3 || len(cons[0].ReporterList) != 3 || cons[1].SP != "none" || cons[1].ReporterList[0] != "GMX" {
		t.Errorf("P2 = %+v", cons)
	}

	// P3: one merged change (none→reject) seen by Google and Outlook on day-5; GMX/Yahoo have no history.
	log, err := GetPolicyChangeLog(db, "example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(log) != 1 {
		t.Fatalf("P3 = %+v", log)
	}
	ch := log[0]
	if ch.At != day(5) || len(ch.Reporters) != 2 || len(ch.Diff) != 2 { // p and sp (none→reject)
		t.Errorf("P3 entry = %+v", ch)
	}
	if ch.PassRateBefore != 0 || ch.MessagesBefore != 250 || ch.PassRateAfter < 94.7 || ch.PassRateAfter > 94.8 || ch.MessagesAfter != 190 {
		t.Errorf("P3 before/after = %.1f/%d %.1f/%d", ch.PassRateBefore, ch.MessagesBefore, ch.PassRateAfter, ch.MessagesAfter)
	}

	// P4: news.example.com governed by p (Yahoo published no sp).
	subs, err := GetSubdomainTraffic(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) != 1 || subs[0].HeaderFrom != "news.example.com" || subs[0].GovernedBy != "p" || subs[0].EffectiveSP != "reject" || subs[0].TotalMessages != 30 {
		t.Errorf("P4 = %+v", subs)
	}

	// P5: pct=100 → does not apply; with a pct=50 dominant record it does.
	ps, _ := GetPctSampling(db, f)
	if ps.Applies {
		t.Errorf("P5 should not apply at pct=100: %+v", ps)
	}
	half := models.PolicyPublished{Policy: "quarantine", ADKIM: "r", ASPF: "r", Pct: 50, PctPresent: true}
	fbHalf := policyFeedback("google.com", "h1", "half.example", day(1), half, "half.example", 40, false)
	fbHalf.Records[0].Row.PolicyEvaluated.Reasons = []models.PolicyOverrideReason{{Type: "sampled_out"}}
	if _, err := SaveReport(db, fbHalf, "h1.xml", nil); err != nil {
		t.Fatal(err)
	}
	ps, err = GetPctSampling(db, StatsFilter{Domain: "half.example"})
	if err != nil {
		t.Fatal(err)
	}
	if !ps.Applies || ps.Pct != 50 || ps.FailingMessages != 40 || ps.ExpectedSampledOut != 20 || ps.ObservedSampledOut != 40 || ps.ObservedShare != 100 {
		t.Errorf("P5 = %+v", ps)
	}

	// P6: p=reject with a known_good source failing → at risk.
	if err := UpsertIPLabel(db, IPLabel{IP: "10.1.0.1", Label: "Our relay", Classification: "known_good"}); err != nil {
		t.Fatal(err)
	}
	rd, err := GetEnforcementReadiness(db, StatsFilter{Domain: "example.com", From: day(7)})
	if err != nil {
		t.Fatal(err)
	}
	if rd.Policy != "reject" || rd.Neither != 10 || rd.KnownGoodNeither != 10 || len(rd.KnownGoodSources) != 1 || rd.KnownGoodSources[0].Label != "Our relay" {
		t.Errorf("P6 = %+v", rd)
	}
	rdNone, _ := GetEnforcementReadiness(db, StatsFilter{Domain: "example.com", From: day(11), To: day(8)})
	if rdNone.Policy != "none" || rdNone.NeitherShare != 100 {
		t.Errorf("P6 none = %+v", rdNone)
	}
}
