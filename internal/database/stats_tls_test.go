package database

import (
	"fmt"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// The T-series scenario spans four days in September 2026.
const (
	tlsDay1 = 1788220800 // 2026-09-01T00:00:00Z
	tlsDay2 = 1788307200
	tlsDay3 = 1788393600
	tlsDay4 = 1788480000
)

// tlsScenarioNow is "now" for the metrics that need one, a day after day 4.
var tlsScenarioNow = time.Unix(tlsDay4+86400, 0).UTC()

// tlsPolicy builds one policies[] entry.
func tlsPolicy(policyType, domain string, mxHosts []string, success, failure int64, details ...parser.TLSFailureDetail) parser.TLSPolicy {
	var p parser.TLSPolicy
	p.Policy.PolicyType = policyType
	p.Policy.PolicyDomain = domain
	p.Policy.MXHost = mxHosts
	p.Summary.TotalSuccess = success
	p.Summary.TotalFailure = failure
	p.FailureDetails = details
	return p
}

// tlsSTSPolicy is tlsPolicy with an MTA-STS policy body attached.
func tlsSTSPolicy(domain, mode string, success, failure int64, details ...parser.TLSFailureDetail) parser.TLSPolicy {
	p := tlsPolicy("sts", domain, []string{"mx.example.com"}, success, failure, details...)
	p.Policy.PolicyString = parser.FlexStrings{
		"version: STSv1", "mode: " + mode, "mx: mx.example.com", "max_age: 604800",
	}
	return p
}

func tlsFail(resultType string, count int64, sendingIP, mxHost, receivingIP string) parser.TLSFailureDetail {
	return parser.TLSFailureDetail{
		ResultType:          resultType,
		SendingMTAIP:        sendingIP,
		ReceivingMXHostname: mxHost,
		ReceivingIP:         receivingIP,
		FailedSessionCount:  count,
	}
}

// saveTLSReport stores one synthetic report as a validly signed mailed report.
func saveTLSReport(t *testing.T, db *sqlx.DB, org, reportID string, day int64, policies ...parser.TLSPolicy) int64 {
	t.Helper()
	return saveTLSReportMeta(t, db, org, reportID, day, TLSRPTMeta{
		Transport:  TransportSMTP,
		DKIMStatus: tlsDKIMValid,
		ReceivedAt: day + 86400 + 7200, // arrives 2h after the window closes
	}, policies...)
}

func saveTLSReportMeta(t *testing.T, db *sqlx.DB, org, reportID string, day int64, meta TLSRPTMeta, policies ...parser.TLSPolicy) int64 {
	t.Helper()
	report := &parser.TLSReport{
		OrganizationName: org,
		ContactInfo:      "tlsrpt@" + org,
		ReportID:         reportID,
		Policies:         policies,
	}
	report.DateRange.Start = time.Unix(day, 0).UTC()
	report.DateRange.End = time.Unix(day+86399, 0).UTC()

	id, err := SaveTLSRPTWithMeta(db, report, meta, reportID+".json", []byte("{}"))
	if err != nil {
		t.Fatalf("save report %s: %v", reportID, err)
	}
	return id
}

// tlsScenario builds the shared fixture: two reporters over three days, an
// MTA-STS domain in testing and a DANE domain, with a spread of failures.
func tlsScenario(t *testing.T) *sqlx.DB {
	t.Helper()
	db := openTestDB(t)

	// Day 1 — Google: mostly fine, one expired certificate on one node.
	saveTLSReport(t, db, "google.com", "g-1", tlsDay1,
		tlsSTSPolicy("example.com", "testing", 900, 10,
			tlsFail("certificate-expired", 10, "198.51.100.10", "mx.example.com", "203.0.113.5")))

	// Day 2 — Google: the same node again, plus a second failure mode on the
	// same session population (overlapping result types, I1).
	saveTLSReport(t, db, "google.com", "g-2", tlsDay2,
		tlsSTSPolicy("example.com", "testing", 800, 20,
			tlsFail("certificate-expired", 20, "198.51.100.10", "mx.example.com", "203.0.113.5"),
			tlsFail("validation-failure", 15, "198.51.100.10", "mx.example.com", "203.0.113.5")))

	// Day 2 — Microsoft: small reporter, failing every session (the case a
	// session-weighted rate hides).
	saveTLSReport(t, db, "microsoft.com", "m-1", tlsDay2,
		tlsSTSPolicy("example.com", "testing", 0, 6,
			tlsFail("starttls-not-supported", 6, "192.0.2.77", "mx.example.com", "203.0.113.9")))

	// Day 3 — Google: the certificate problem continues, and the MTA-STS
	// endpoint itself starts failing. A HELO mismatch appears on a new node.
	saveTLSReport(t, db, "google.com", "g-3", tlsDay3,
		tlsSTSPolicy("example.com", "testing", 700, 30,
			tlsFail("certificate-expired", 25, "198.51.100.10", "mx.example.com", "203.0.113.5"),
			parser.TLSFailureDetail{
				ResultType: "sts-policy-fetch-error", FailedSessionCount: 5,
				SendingMTAIP: "198.51.100.11", ReceivingMXHostname: "mx.example.com",
				ReceivingIP: "203.0.113.6", ReceivingMXHelo: "mail-out.example.net",
				FailureReasonCode: "HTTP_404",
			}))

	// Day 3 — Google: a DANE domain with an invalid TLSA record, over IPv6.
	saveTLSReport(t, db, "google.com", "g-4", tlsDay3,
		tlsPolicy("tlsa", "dane.example.com", []string{"mx1.dane.example.com"}, 200, 4,
			tlsFail("tlsa-invalid", 4, "2001:db8::10", "mx1.dane.example.com", "2001:db8::25")))

	return db
}

func tlsWindow() TLSFilter {
	return TLSFilter{From: tlsDay1, To: tlsDay4, RequireDKIM: true}
}

// T1: the headline rate, its per-domain split and its daily series.
func TestGetTLSRateT1(t *testing.T) {
	db := tlsScenario(t)

	rate, err := GetTLSRate(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	// 900+800+0+700+200 success, 10+20+6+30+4 failure.
	if rate.Success != 2600 || rate.Failure != 70 || rate.Total != 2670 {
		t.Fatalf("rate = %+v, want 2600/70/2670", rate)
	}
	if got := fmt.Sprintf("%.2f", rate.Rate); got != "97.38" {
		t.Errorf("rate = %s%%, want 97.38%%", got)
	}

	byDomain, err := GetTLSRateByDomain(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(byDomain) != 2 {
		t.Fatalf("domains = %d, want 2", len(byDomain))
	}
	if byDomain[0].PolicyDomain != "example.com" || byDomain[0].Failure != 66 {
		t.Errorf("worst domain = %+v, want example.com with 66 failures first", byDomain[0])
	}
	if byDomain[1].PolicyDomain != "dane.example.com" || byDomain[1].Success != 200 {
		t.Errorf("second domain = %+v", byDomain[1])
	}

	series, err := GetTLSDailySeries(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 3 {
		t.Fatalf("days = %d, want 3", len(series))
	}
	if series[0].Day != "2026-09-01" || series[0].Success != 900 || series[0].Failure != 10 {
		t.Errorf("day 1 = %+v", series[0])
	}
	// Day 2 merges both reporters; day 3 merges both domains.
	if series[1].Success != 800 || series[1].Failure != 26 {
		t.Errorf("day 2 = %+v, want 800/26", series[1])
	}
	if series[2].Success != 900 || series[2].Failure != 34 {
		t.Errorf("day 3 = %+v, want 900/34", series[2])
	}
}

// T2: the weighted rate and the per-reporter median answer different
// questions, and the median is the one that exposes a small broken receiver.
func TestGetTLSVolumeT2(t *testing.T) {
	db := tlsScenario(t)

	vol, err := GetTLSVolume(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if vol.Sessions != 2670 || vol.Reports != 5 || vol.ReporterCount != 2 {
		t.Fatalf("volume = %d sessions / %d reports / %d reporters", vol.Sessions, vol.Reports, vol.ReporterCount)
	}
	if vol.Reporters[0].OrgName != "google.com" {
		t.Errorf("reporters should be ordered by volume, got %+v", vol.Reporters)
	}
	if got := fmt.Sprintf("%.1f", vol.Reporters[0].Share); got != "99.8" {
		t.Errorf("google share = %s%%, want 99.8%%", got)
	}
	if got := fmt.Sprintf("%.2f", vol.WeightedRate); got != "97.38" {
		t.Errorf("weighted rate = %s%%", got)
	}
	// Microsoft saw 0 of 6 sessions succeed; the median of {97.55, 0} is
	// ~48.8%, which is the number that makes the broken receiver visible.
	if vol.MedianReporterRate > 50 {
		t.Errorf("median reporter rate = %.2f%%, want the failing reporter to drag it below 50%%", vol.MedianReporterRate)
	}
	if len(vol.ByDay) != 3 {
		t.Errorf("daily series = %d points, want 3", len(vol.ByDay))
	}
}

// T3: policy types, including the double-attribution caveat.
func TestGetTLSPolicyMixT3(t *testing.T) {
	db := tlsScenario(t)

	mix, err := GetTLSPolicyMix(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]TLSPolicyTypeRow{}
	for _, row := range mix.Overall {
		byType[row.PolicyType] = row
	}
	if byType["sts"].Sessions != 2466 {
		t.Errorf("sts sessions = %d, want 2466", byType["sts"].Sessions)
	}
	if byType["tlsa"].Sessions != 204 {
		t.Errorf("tlsa sessions = %d, want 204", byType["tlsa"].Sessions)
	}
	if mix.MultiPolicySessions != 0 {
		t.Errorf("no report in the scenario is multi-policy, got %d sessions", mix.MultiPolicySessions)
	}
	if len(mix.ByReporter["microsoft.com"]) != 1 {
		t.Errorf("per-reporter mix = %+v", mix.ByReporter)
	}

	// With a genuinely multi-policy report the caveat kicks in.
	saveTLSReport(t, db, "yahoo.com", "y-1", tlsDay2,
		tlsPolicy("sts", "example.com", []string{"mx.example.com"}, 50, 1),
		tlsPolicy("tlsa", "example.com", []string{"mx.example.com"}, 50, 1))
	mix, err = GetTLSPolicyMix(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if mix.MultiPolicySessions != 51 {
		t.Errorf("multi-policy sessions = %d, want 51 (counted once, not twice)", mix.MultiPolicySessions)
	}
}

// T4: result types grouped as the RFC groups them.
func TestGetTLSFailureBreakdownT4(t *testing.T) {
	db := tlsScenario(t)

	b, err := GetTLSFailureBreakdown(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string]TLSResultTypeRow{}
	for _, row := range b.Types {
		byType[row.ResultType] = row
	}
	if byType["certificate-expired"].FailedSessions != 55 {
		t.Errorf("certificate-expired = %d, want 55", byType["certificate-expired"].FailedSessions)
	}
	if byType["certificate-expired"].Group != TLSGroupNegotiation {
		t.Errorf("certificate-expired grouped as %q", byType["certificate-expired"].Group)
	}

	byGroup := map[string]TLSResultTypeRow{}
	for _, row := range b.Groups {
		byGroup[row.ResultType] = row
	}
	// negotiation: 55 expired + 15 validation + 6 starttls = 76.
	if byGroup[TLSGroupNegotiation].FailedSessions != 76 {
		t.Errorf("negotiation group = %d, want 76", byGroup[TLSGroupNegotiation].FailedSessions)
	}
	if byGroup[TLSGroupDANE].FailedSessions != 4 {
		t.Errorf("dane group = %d, want 4", byGroup[TLSGroupDANE].FailedSessions)
	}
	if byGroup[TLSGroupMTASTS].FailedSessions != 5 {
		t.Errorf("mta-sts group = %d, want 5", byGroup[TLSGroupMTASTS].FailedSessions)
	}

	// I1 holds: the failure observations exceed the 70 sessions the summaries
	// reported, because one session hit two result types on day 2.
	if b.Total != 85 {
		t.Errorf("failure observations = %d, want 85", b.Total)
	}
	rate, err := GetTLSRate(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if b.Total <= rate.Failure {
		t.Errorf("fixture should overlap: observations %d vs sessions %d", b.Total, rate.Failure)
	}
}

func TestTLSResultGroup(t *testing.T) {
	cases := map[string]string{
		"certificate-expired":    TLSGroupNegotiation,
		"dane-required":          TLSGroupDANE,
		"STS-Policy-Fetch-Error": TLSGroupMTASTS,
		"quantum-handshake":      TLSGroupUnregistered,
		"":                       TLSGroupUnregistered,
	}
	for in, want := range cases {
		if got := TLSResultGroup(in); got != want {
			t.Errorf("TLSResultGroup(%q) = %q, want %q", in, got, want)
		}
	}
}

// T5: the per-IP view is what exposes one bad node behind a healthy-looking
// MX name, and a HELO that disagrees with its host is its own finding.
func TestGetTLSReceiversT5(t *testing.T) {
	db := tlsScenario(t)

	recv, err := GetTLSReceivers(db, tlsWindow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var mx TLSReceiverRow
	for _, row := range recv.ByHost {
		if row.MXHostname == "mx.example.com" {
			mx = row
		}
	}
	if mx.FailedSessions != 81 {
		t.Errorf("mx.example.com failures = %d, want 81", mx.FailedSessions)
	}
	if mx.DistinctIPs != 3 {
		t.Errorf("distinct receiving IPs behind mx.example.com = %d, want 3", mx.DistinctIPs)
	}

	byIP := map[string]int64{}
	for _, row := range recv.ByIP {
		byIP[row.ReceivingIP] = row.FailedSessions
	}
	// One node carries nearly everything; the others are almost clean.
	if byIP["203.0.113.5"] != 70 {
		t.Errorf("203.0.113.5 = %d failures, want 70", byIP["203.0.113.5"])
	}
	if byIP["203.0.113.9"] != 6 || byIP["203.0.113.6"] != 5 {
		t.Errorf("per-IP split = %v", byIP)
	}

	if len(recv.HeloMismatches) != 1 {
		t.Fatalf("helo mismatches = %+v, want 1", recv.HeloMismatches)
	}
	if recv.HeloMismatches[0].Helo != "mail-out.example.net" {
		t.Errorf("helo mismatch = %+v", recv.HeloMismatches[0])
	}
}

// T6: senders roll up to networks and providers, using the shared cache.
func TestGetTLSSendersT6(t *testing.T) {
	db := tlsScenario(t)
	if _, err := db.Exec(`
		INSERT INTO ip_info (ip, rdns, whois_org, whois_asn, looked_up_at)
		VALUES ('198.51.100.10', 'out1.sender.example', 'Sender Inc', 'AS64500', 1)`); err != nil {
		t.Fatal(err)
	}

	senders, err := GetTLSSenders(db, tlsWindow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var top TLSSenderRow
	for _, row := range senders.ByIP {
		if row.SendingIP == "198.51.100.10" {
			top = row
		}
	}
	if top.FailedSessions != 70 {
		t.Errorf("198.51.100.10 = %d, want 70", top.FailedSessions)
	}
	if top.RDNS != "out1.sender.example" || top.WhoisOrg != "Sender Inc" {
		t.Errorf("enrichment not joined: %+v", top)
	}

	byNetwork := map[string]TLSSenderNetworkRow{}
	for _, row := range senders.ByNetwork {
		byNetwork[row.Network] = row
	}
	// .10 and .11 share a /24, so the network view shows them together.
	if got := byNetwork["198.51.100.0/24"]; got.FailedSessions != 75 || got.IPs != 2 {
		t.Errorf("198.51.100.0/24 = %+v, want 75 failures across 2 IPs", got)
	}
	if got := byNetwork["2001:db8::/64"]; got.FailedSessions != 4 {
		t.Errorf("IPv6 /64 rollup = %+v", got)
	}
}

func TestTLSSenderNetwork(t *testing.T) {
	cases := map[string]string{
		"198.51.100.10": "198.51.100.0/24",
		"203.0.113.255": "203.0.113.0/24",
		"2001:db8::10":  "2001:db8::/64",
		"not-an-ip":     "",
		"":              "",
	}
	for in, want := range cases {
		if got := TLSSenderNetwork(in); got != want {
			t.Errorf("TLSSenderNetwork(%q) = %q, want %q", in, got, want)
		}
	}
}

// T7: reason codes, and the volume that came with no reason at all.
func TestGetTLSReasonsT7(t *testing.T) {
	db := tlsScenario(t)

	reasons, err := GetTLSReasons(db, tlsWindow(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(reasons.Overall) != 1 || reasons.Overall[0].ReasonCode != "HTTP_404" {
		t.Fatalf("reasons = %+v", reasons.Overall)
	}
	if reasons.Overall[0].FailedSessions != 5 {
		t.Errorf("HTTP_404 = %d, want 5", reasons.Overall[0].FailedSessions)
	}
	if reasons.ByResultType[0].ResultType != "sts-policy-fetch-error" {
		t.Errorf("reason not attributed to its result type: %+v", reasons.ByResultType[0])
	}
	if reasons.WithoutReason != 80 {
		t.Errorf("failures with no reason code = %d, want 80", reasons.WithoutReason)
	}
}

// T8: two policy strings for one domain on one day is a divergence.
func TestGetTLSPolicyDivergenceT8(t *testing.T) {
	db := tlsScenario(t)

	if rows, err := GetTLSPolicyDivergence(db, tlsWindow()); err != nil {
		t.Fatal(err)
	} else if len(rows) != 0 {
		t.Fatalf("scenario should be consistent, got %+v", rows)
	}

	// A second reporter sees a different policy for example.com the same day.
	saveTLSReport(t, db, "yahoo.com", "y-2", tlsDay2,
		tlsSTSPolicy("example.com", "enforce", 10, 0))

	rows, err := GetTLSPolicyDivergence(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("divergences = %+v, want 1", rows)
	}
	if rows[0].Day != "2026-09-02" || rows[0].PolicyDomain != "example.com" || rows[0].Distinct != 2 {
		t.Errorf("divergence = %+v", rows[0])
	}
}

// T9: what the failures seen in testing would have cost in enforce.
func TestGetTLSEnforcementReadinessT9(t *testing.T) {
	db := tlsScenario(t)

	r, err := GetTLSEnforcementReadiness(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if r.TestingSessions != 2466 {
		t.Errorf("testing sessions = %d, want 2466", r.TestingSessions)
	}
	if r.TestingFailures != 66 || r.WouldBlock != 66 {
		t.Errorf("would-block = %d (failures %d), want 66", r.WouldBlock, r.TestingFailures)
	}
	if r.EnforceSessions != 0 {
		t.Errorf("nothing is in enforce yet, got %d", r.EnforceSessions)
	}
	var none TLSModeRow
	for _, m := range r.Modes {
		if m.Mode == "(none)" {
			none = m
		}
	}
	if none.Sessions != 204 {
		t.Errorf("the TLSA policy has no STS mode; got %+v", none)
	}
}

// T10: the MTA-STS endpoint is its own failure domain, separate from the MX.
func TestGetTLSEndpointHealthT10(t *testing.T) {
	db := tlsScenario(t)

	h, err := GetTLSEndpointHealth(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if h.FetchError != 5 || h.Total != 5 {
		t.Errorf("endpoint health = %+v, want 5 fetch errors", h)
	}
	if h.WebPKIInvalid != 0 || h.PolicyInvalid != 0 {
		t.Errorf("unexpected endpoint errors: %+v", h)
	}
	if len(h.ByDay) != 1 || h.ByDay[0].Day != "2026-09-03" {
		t.Errorf("daily series = %+v", h.ByDay)
	}
}

// T11: DANE failures name the organisation that reported them.
func TestGetTLSDaneHealthT11(t *testing.T) {
	db := tlsScenario(t)

	rows, err := GetTLSDaneHealth(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("dane rows = %+v, want 1", rows)
	}
	if rows[0].ResultType != "tlsa-invalid" || rows[0].OrgName != "google.com" {
		t.Errorf("dane row = %+v", rows[0])
	}
	if rows[0].PolicyDomain != "dane.example.com" || rows[0].FailedSessions != 4 {
		t.Errorf("dane row = %+v", rows[0])
	}
}

// T12: coverage, latency and the reporter that went quiet.
func TestGetTLSCoverageT12(t *testing.T) {
	db := tlsScenario(t)

	c, err := GetTLSCoverage(db, tlsWindow(), 3, tlsScenarioNow)
	if err != nil {
		t.Fatal(err)
	}
	if c.Reporters != 2 {
		t.Errorf("reporters = %d, want 2", c.Reporters)
	}
	if len(c.New) != 2 {
		t.Errorf("both reporters are new in this window, got %v", c.New)
	}
	// Every report arrives 2h after its window closes.
	if c.Latency.Samples != 5 || c.Latency.MedianHours < 1.9 || c.Latency.MedianHours > 2.1 {
		t.Errorf("latency = %+v, want ~2h over 5 samples", c.Latency)
	}
	// The window is 2026-09-01 … 09-04; no report window began on the 4th.
	if c.WindowDays != 4 || c.DaysWithNoReport != 1 {
		t.Errorf("coverage days = %d of %d, want 1 missing of 4", c.DaysWithNoReport, c.WindowDays)
	}

	// Microsoft stopped after day 2, but at this point it is only two days
	// silent — inside the three-day gap, so not yet lapsed.
	if len(c.Lapsed) != 0 {
		t.Errorf("nothing should be lapsed yet, got %+v", c.Lapsed)
	}

	// Two days later both reporters have crossed the threshold.
	later, err := GetTLSCoverage(db, tlsWindow(), 3, tlsScenarioNow.AddDate(0, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	silent := map[string]int{}
	for _, g := range later.Lapsed {
		silent[g.OrgName] = g.DaysSilent
	}
	if len(silent) != 2 {
		t.Fatalf("lapsed = %+v, want both reporters", later.Lapsed)
	}
	if silent["microsoft.com"] != 4 || silent["google.com"] != 3 {
		t.Errorf("days silent = %v, want microsoft 4 and google 3", silent)
	}
}

// T13: hygiene shows what the other metrics are quietly leaving out.
func TestGetTLSHygieneT13(t *testing.T) {
	db := tlsScenario(t)

	// An unsigned mailed report: stored, listed, and excluded from metrics.
	saveTLSReportMeta(t, db, "unsigned.example", "u-1", tlsDay2,
		TLSRPTMeta{Transport: TransportSMTP, DKIMStatus: "absent"},
		tlsSTSPolicy("example.com", "testing", 5000, 5000))
	// An uploaded report: no carrying message, so never excluded.
	saveTLSReportMeta(t, db, "upload.example", "up-1", tlsDay2,
		TLSRPTMeta{Transport: TransportUpload, DKIMStatus: "not_applicable"},
		tlsSTSPolicy("example.com", "testing", 100, 0))

	h, err := GetTLSHygiene(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if h.Reports != 7 {
		t.Errorf("hygiene counts every report including excluded ones, got %d of 7", h.Reports)
	}
	if h.Excluded != 1 {
		t.Errorf("excluded = %d, want the one unsigned mailed report", h.Excluded)
	}
	byStatus := map[string]int64{}
	for _, s := range h.DKIMByStatus {
		byStatus[s.Status] = s.Count
	}
	if byStatus["absent"] != 1 || byStatus[tlsDKIMValid] != 5 {
		t.Errorf("dkim breakdown = %v", byStatus)
	}
	if h.TransportUpload != 1 || h.TransportSMTP != 6 {
		t.Errorf("transport split = %d smtp / %d upload", h.TransportSMTP, h.TransportUpload)
	}

	// And the exclusion really is applied everywhere else.
	rate, err := GetTLSRate(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if rate.Failure != 70 {
		t.Errorf("failures = %d; the unsigned report's 5000 must not be counted", rate.Failure)
	}
	if rate.Success != 2700 {
		t.Errorf("successes = %d, want 2600 plus the 100 uploaded", rate.Success)
	}
}

// The DKIM requirement gates on transport, so switching it off changes only
// the mailed reports, and uploads are unaffected either way.
func TestTLSFilterDKIMExclusion(t *testing.T) {
	db := tlsScenario(t)
	saveTLSReportMeta(t, db, "unsigned.example", "u-1", tlsDay2,
		TLSRPTMeta{Transport: TransportSMTP, DKIMStatus: "absent"},
		tlsSTSPolicy("example.com", "testing", 1000, 0))
	saveTLSReportMeta(t, db, "upload.example", "up-1", tlsDay2,
		TLSRPTMeta{Transport: TransportUpload, DKIMStatus: "not_applicable"},
		tlsSTSPolicy("example.com", "testing", 100, 0))

	strict := tlsWindow()
	strict.RequireDKIM = true
	lenient := tlsWindow()
	lenient.RequireDKIM = false

	withDKIM, err := GetTLSRate(db, strict)
	if err != nil {
		t.Fatal(err)
	}
	without, err := GetTLSRate(db, lenient)
	if err != nil {
		t.Fatal(err)
	}
	if withDKIM.Success != 2700 {
		t.Errorf("strict successes = %d, want 2600 + 100 uploaded", withDKIM.Success)
	}
	if without.Success != 3700 {
		t.Errorf("lenient successes = %d, want the unsigned 1000 included too", without.Success)
	}
}

// T14: which stack the failures are on.
func TestGetTLSFamilySplitT14(t *testing.T) {
	db := tlsScenario(t)

	s, err := GetTLSFamilySplit(db, tlsWindow())
	if err != nil {
		t.Fatal(err)
	}
	if s.SendingV4 != 81 || s.SendingV6 != 4 {
		t.Errorf("sending split = %d v4 / %d v6, want 81/4", s.SendingV4, s.SendingV6)
	}
	if s.ReceivingV4 != 81 || s.ReceivingV6 != 4 {
		t.Errorf("receiving split = %d v4 / %d v6", s.ReceivingV4, s.ReceivingV6)
	}
	if got := fmt.Sprintf("%.1f", s.SendingV6Share); got != "4.7" {
		t.Errorf("v6 share = %s%%, want 4.7%%", got)
	}
}

// T15: consecutive days collapse into one incident with a duration.
func TestGetTLSIncidentsT15(t *testing.T) {
	db := tlsScenario(t)

	incidents, err := GetTLSIncidents(db, tlsWindow(), tlsScenarioNow)
	if err != nil {
		t.Fatal(err)
	}
	var certExpired *TLSIncident
	for i := range incidents {
		if incidents[i].ResultType == "certificate-expired" {
			certExpired = &incidents[i]
		}
	}
	if certExpired == nil {
		t.Fatalf("no certificate-expired incident in %+v", incidents)
	}
	if certExpired.Days != 3 || certExpired.FirstDay != "2026-09-01" || certExpired.LastDay != "2026-09-03" {
		t.Errorf("incident = %+v, want a 3-day run from 09-01 to 09-03", certExpired)
	}
	if certExpired.FailedSessions != 55 {
		t.Errorf("incident volume = %d, want 55", certExpired.FailedSessions)
	}
	if certExpired.Ongoing {
		t.Error("the run ended before 'now', so it is not ongoing")
	}
	// The single-day tlsa-invalid is its own one-day incident, not merged in.
	for _, inc := range incidents {
		if inc.ResultType == "tlsa-invalid" && inc.Days != 1 {
			t.Errorf("tlsa incident = %+v, want a single day", inc)
		}
	}
}

// A gap in the middle of a run splits it into two incidents.
func TestGetTLSIncidentsSplitsOnGap(t *testing.T) {
	db := openTestDB(t)
	saveTLSReport(t, db, "google.com", "i-1", tlsDay1,
		tlsSTSPolicy("example.com", "enforce", 10, 1,
			tlsFail("certificate-expired", 1, "198.51.100.10", "mx.example.com", "203.0.113.5")))
	// nothing on day 2
	saveTLSReport(t, db, "google.com", "i-3", tlsDay3,
		tlsSTSPolicy("example.com", "enforce", 10, 1,
			tlsFail("certificate-expired", 1, "198.51.100.10", "mx.example.com", "203.0.113.5")))

	incidents, err := GetTLSIncidents(db, tlsWindow(), tlsScenarioNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 2 {
		t.Fatalf("incidents = %+v, want 2 separated by the quiet day", incidents)
	}
	for _, inc := range incidents {
		if inc.Days != 1 {
			t.Errorf("incident = %+v, want one day each", inc)
		}
	}
}

// Comparison against the preceding window of equal length.
func TestTLSWithComparison(t *testing.T) {
	db := tlsScenario(t)
	// Day 1 and 2 are the current window; the two days before it are empty.
	f := TLSFilter{From: tlsDay1, To: tlsDay2 + 86399, Compare: true, RequireDKIM: true}

	cmp, err := TLSWithComparison(f, func(sf TLSFilter) (*TLSRate, error) {
		return GetTLSRate(db, sf)
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Current.Success != 1700 {
		t.Errorf("current = %+v, want 900+800 successes", cmp.Current)
	}
	if cmp.Previous == nil {
		t.Fatal("comparison window missing")
	}
	if (*cmp.Previous).Total != 0 {
		t.Errorf("previous window should be empty, got %+v", *cmp.Previous)
	}

	// Without Compare there is no second query.
	f.Compare = false
	cmp, err = TLSWithComparison(f, func(sf TLSFilter) (*TLSRate, error) {
		return GetTLSRate(db, sf)
	})
	if err != nil {
		t.Fatal(err)
	}
	if cmp.Previous != nil {
		t.Error("previous window computed without Compare")
	}
}

// The domain filter scopes both session and failure metrics.
func TestTLSFilterByDomain(t *testing.T) {
	db := tlsScenario(t)
	f := tlsWindow()
	f.Domain = "dane.example.com"

	rate, err := GetTLSRate(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if rate.Success != 200 || rate.Failure != 4 {
		t.Errorf("scoped rate = %+v, want only the DANE domain", rate)
	}
	b, err := GetTLSFailureBreakdown(db, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Types) != 1 || b.Types[0].ResultType != "tlsa-invalid" {
		t.Errorf("scoped failures = %+v", b.Types)
	}
}
