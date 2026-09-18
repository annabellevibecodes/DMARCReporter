package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

func tlsCfg() config.Config {
	c := testCfg()
	c.AlertTLSRateDrop = 5
	c.AlertTLSMinWindowSessions = 100
	c.AlertTLSStripMinSessions = 5
	c.AlertTLSPolicyHostErrPct = 5
	c.AlertTLSReporterGapDays = 3
	c.AlertTLSNewFailingIPMin = 10
	c.TLSRPTRequireDKIM = true
	return c
}

// saveTLS stores one TLS report as a validly signed mailed report.
func saveTLS(t *testing.T, db *sqlx.DB, org, id string, begin int64, policies ...parser.TLSPolicy) {
	t.Helper()
	report := &parser.TLSReport{
		OrganizationName: org, ContactInfo: "tlsrpt@" + org, ReportID: id, Policies: policies,
	}
	report.DateRange.Start = time.Unix(begin, 0).UTC()
	report.DateRange.End = time.Unix(begin+86399, 0).UTC()
	if _, err := database.SaveTLSRPTWithMeta(db, report, database.TLSRPTMeta{
		Transport: database.TransportSMTP, DKIMStatus: "valid", ReceivedAt: begin + 86400,
	}, id+".json", []byte("{}")); err != nil {
		t.Fatalf("save %s: %v", id, err)
	}
}

func stsPolicy(domain, mode string, mx []string, success, failure int64, details ...parser.TLSFailureDetail) parser.TLSPolicy {
	var p parser.TLSPolicy
	p.Policy.PolicyType = "sts"
	p.Policy.PolicyDomain = domain
	p.Policy.MXHost = mx
	p.Policy.PolicyString = parser.FlexStrings{"version: STSv1", "mode: " + mode, "max_age: 604800"}
	p.Summary.TotalSuccess = success
	p.Summary.TotalFailure = failure
	p.FailureDetails = details
	return p
}

func fail(resultType string, count int64, host, receivingIP string) parser.TLSFailureDetail {
	return parser.TLSFailureDetail{
		ResultType: resultType, FailedSessionCount: count,
		ReceivingMXHostname: host, ReceivingIP: receivingIP,
	}
}

// daysAgo returns midnight UTC n days back.
func daysAgo(n int) int64 {
	return time.Now().UTC().AddDate(0, 0, -n).Truncate(24 * time.Hour).Unix()
}

// fireRule evaluates one rule by name against db.
func fireRule(t *testing.T, db *sqlx.DB, cfg config.Config, name string) []Alert {
	t.Helper()
	ctx := &Context{DB: db, Cfg: cfg, Now: time.Now().UTC()}
	for _, r := range Rules {
		if r.Name != name {
			continue
		}
		out, err := r.Fn(ctx)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return out
	}
	t.Fatalf("rule %s is not registered", name)
	return nil
}

// Every TLS rule must be registered in the shared table, or it never runs.
func TestTLSRulesAreRegistered(t *testing.T) {
	want := []string{
		"tls_rate_drop", "tls_starttls_stripped", "tls_cert_expired", "tls_policy_inconsistent",
		"tls_policy_host_error", "tls_dane_invalid", "tls_reporter_silent", "tls_new_failing_receiver",
	}
	byName := map[string]Rule{}
	for _, r := range Rules {
		byName[r.Name] = r
	}
	for _, name := range want {
		r, ok := byName[name]
		if !ok {
			t.Errorf("%s is missing from Rules", name)
			continue
		}
		if r.ID == "" || r.Description == "" || r.Threshold == nil || r.Fn == nil {
			t.Errorf("%s has an incomplete entry: %+v", name, r)
		}
		if got := r.Threshold(tlsCfg()); got == "" {
			t.Errorf("%s has an empty threshold description", name)
		}
	}
}

// X12: a week-over-week fall, with enough traffic in both windows to mean it.
func TestRuleTLSRateDrop(t *testing.T) {
	db := openDB(t)
	// Previous week: 1000 of 1000 succeeded. This week: 800 of 1000.
	saveTLS(t, db, "google.com", "prev", daysAgo(10), stsPolicy("example.com", "testing", []string{"mx.example.com"}, 1000, 0))
	saveTLS(t, db, "google.com", "cur", daysAgo(3), stsPolicy("example.com", "testing", []string{"mx.example.com"}, 800, 200))

	alerts := fireRule(t, db, tlsCfg(), "tls_rate_drop")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if alerts[0].Domain != "example.com" || alerts[0].Severity != database.SeverityCritical {
		t.Errorf("alert = %+v", alerts[0])
	}
	if !strings.Contains(alerts[0].Message, "100.0% → 80.0%") {
		t.Errorf("message should show both rates: %q", alerts[0].Message)
	}
}

// Too little traffic and the comparison says nothing, so the rule stays quiet.
func TestRuleTLSRateDropIgnoresThinWindows(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "prev", daysAgo(10), stsPolicy("example.com", "testing", []string{"mx.example.com"}, 20, 0))
	saveTLS(t, db, "google.com", "cur", daysAgo(3), stsPolicy("example.com", "testing", []string{"mx.example.com"}, 5, 15))

	if alerts := fireRule(t, db, tlsCfg(), "tls_rate_drop"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none below the session floor", alerts)
	}
}

// X13 is the one worth getting right: a host that used to negotiate TLS and
// now reports STARTTLS missing is the stripping signature.
func TestRuleTLSStarttlsStripped(t *testing.T) {
	db := openDB(t)
	// Before: the reporter negotiated TLS with this host happily.
	saveTLS(t, db, "google.com", "before", daysAgo(9),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 500, 0))
	// Now: STARTTLS refused on the same host.
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 0, 40,
			fail("starttls-not-supported", 40, "mx.example.com", "203.0.113.5")))

	alerts := fireRule(t, db, tlsCfg(), "tls_starttls_stripped")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	a := alerts[0]
	if a.Severity != database.SeverityCritical {
		t.Errorf("stripping must be critical, got %q", a.Severity)
	}
	if a.Key != "google.com|mx.example.com" {
		t.Errorf("key = %q, want reporter and host", a.Key)
	}
	if !strings.Contains(a.Message, "negotiated TLS there before") {
		t.Errorf("message should say the host used to work: %q", a.Message)
	}
	if a.Payload["prior_success"].(int64) != 500 {
		t.Errorf("payload = %+v", a.Payload)
	}
}

// A host that never worked is a configuration problem, not stripping: the
// rule must not fire, or it cries wolf on every unconfigured server.
func TestRuleTLSStarttlsStrippedNeedsPriorSuccess(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 0, 40,
			fail("starttls-not-supported", 40, "mx.example.com", "203.0.113.5")))

	if alerts := fireRule(t, db, tlsCfg(), "tls_starttls_stripped"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none without prior success", alerts)
	}
}

// A host already being stripped before the window is not news.
func TestRuleTLSStarttlsStrippedIgnoresOngoing(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "before", daysAgo(9),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 500, 10,
			fail("starttls-not-supported", 10, "mx.example.com", "203.0.113.5")))
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 0, 40,
			fail("starttls-not-supported", 40, "mx.example.com", "203.0.113.5")))

	if alerts := fireRule(t, db, tlsCfg(), "tls_starttls_stripped"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none: this host was already being stripped", alerts)
	}
}

// Prior success is matched through the policy's mx pattern, which may be a
// wildcard — never by string equality with the hostname (I6).
func TestRuleTLSStarttlsStrippedMatchesWildcardPolicy(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "before", daysAgo(9),
		stsPolicy("example.com", "enforce", []string{"*.mail.example.com"}, 500, 0))
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "enforce", []string{"*.mail.example.com"}, 0, 20,
			fail("starttls-not-supported", 20, "mx1.mail.example.com", "203.0.113.5")))

	alerts := fireRule(t, db, tlsCfg(), "tls_starttls_stripped")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want the wildcard policy to count as prior success", alerts)
	}
}

// X14 fires on any expired certificate at all.
func TestRuleTLSCertExpired(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "testing", []string{"mx.example.com"}, 100, 3,
			fail("certificate-expired", 3, "mx.example.com", "203.0.113.5")))

	alerts := fireRule(t, db, tlsCfg(), "tls_cert_expired")
	if len(alerts) != 1 || alerts[0].Severity != database.SeverityCritical {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts[0].Key != "mx.example.com" {
		t.Errorf("key = %q, want the host", alerts[0].Key)
	}
}

// X16: policy-host failures as a share of the domain's sessions.
func TestRuleTLSPolicyHostError(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "testing", []string{"mx.example.com"}, 80, 20,
			fail("sts-policy-fetch-error", 20, "mx.example.com", "203.0.113.5")))

	alerts := fireRule(t, db, tlsCfg(), "tls_policy_host_error")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if !strings.Contains(alerts[0].Message, "20.0%") {
		t.Errorf("message should carry the share: %q", alerts[0].Message)
	}

	// Below the threshold it stays quiet.
	db2 := openDB(t)
	saveTLS(t, db2, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "testing", []string{"mx.example.com"}, 1000, 2,
			fail("sts-policy-fetch-error", 2, "mx.example.com", "203.0.113.5")))
	if alerts := fireRule(t, db2, tlsCfg(), "tls_policy_host_error"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none below 5%%", alerts)
	}
}

// X17 names the organisation, since a DANE failure is reported by a partner.
func TestRuleTLSDaneInvalid(t *testing.T) {
	db := openDB(t)
	var p parser.TLSPolicy
	p.Policy.PolicyType = "tlsa"
	p.Policy.PolicyDomain = "dane.example.com"
	p.Policy.MXHost = parser.FlexStrings{"mx1.dane.example.com"}
	p.Summary.TotalSuccess = 100
	p.Summary.TotalFailure = 4
	p.FailureDetails = []parser.TLSFailureDetail{fail("tlsa-invalid", 4, "mx1.dane.example.com", "203.0.113.9")}
	saveTLS(t, db, "google.com", "now", daysAgo(1), p)

	alerts := fireRule(t, db, tlsCfg(), "tls_dane_invalid")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want 1", alerts)
	}
	if !strings.Contains(alerts[0].Message, "google.com") {
		t.Errorf("message should name the reporter: %q", alerts[0].Message)
	}
}

// X18 reuses the X6 shape over TLS reports.
func TestRuleTLSReporterSilent(t *testing.T) {
	db := openDB(t)
	saveTLS(t, db, "quiet.example", "old", daysAgo(6),
		stsPolicy("example.com", "testing", []string{"mx.example.com"}, 10, 0))

	alerts := fireRule(t, db, tlsCfg(), "tls_reporter_silent")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want the silent reporter", alerts)
	}
	if alerts[0].Key != "tls|quiet.example" {
		// Namespaced so a TLS reporter going quiet does not collide with the
		// DMARC rule's alert for an organisation of the same name.
		t.Errorf("key = %q, want a tls-namespaced key", alerts[0].Key)
	}

	// A reporter still sending is not silent.
	db2 := openDB(t)
	saveTLS(t, db2, "busy.example", "recent", daysAgo(1),
		stsPolicy("example.com", "testing", []string{"mx.example.com"}, 10, 0))
	if alerts := fireRule(t, db2, tlsCfg(), "tls_reporter_silent"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none", alerts)
	}
}

// X19: one node fails while its siblings are fine.
func TestRuleTLSNewFailingReceiver(t *testing.T) {
	db := openDB(t)
	// Before: two nodes, one already failing — that one is not new.
	saveTLS(t, db, "google.com", "before", daysAgo(9),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 500, 12,
			fail("certificate-expired", 12, "mx.example.com", "203.0.113.5")))
	// Now: the known-bad node plus a new one.
	saveTLS(t, db, "google.com", "now", daysAgo(1),
		stsPolicy("example.com", "enforce", []string{"mx.example.com"}, 400, 40,
			fail("certificate-expired", 15, "mx.example.com", "203.0.113.5"),
			fail("certificate-expired", 25, "mx.example.com", "203.0.113.6")))

	alerts := fireRule(t, db, tlsCfg(), "tls_new_failing_receiver")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %+v, want only the new node", alerts)
	}
	a := alerts[0]
	if !strings.Contains(a.Message, "203.0.113.6") {
		t.Errorf("message = %q, want the new node", a.Message)
	}
	if a.Severity != database.SeverityCritical {
		t.Errorf("a single bad node behind a healthy host is critical, got %q", a.Severity)
	}
}

// A report excluded by the RFC 8460 §3 signature rule must not raise alerts
// either: what the page shows and what fires have to agree.
func TestTLSRulesHonourDKIMExclusion(t *testing.T) {
	db := openDB(t)
	report := &parser.TLSReport{
		OrganizationName: "unsigned.example", ReportID: "u-1",
		Policies: []parser.TLSPolicy{stsPolicy("example.com", "testing", []string{"mx.example.com"}, 0, 50,
			fail("certificate-expired", 50, "mx.example.com", "203.0.113.5"))},
	}
	report.DateRange.Start = time.Unix(daysAgo(1), 0).UTC()
	report.DateRange.End = time.Unix(daysAgo(1)+86399, 0).UTC()
	if _, err := database.SaveTLSRPTWithMeta(db, report, database.TLSRPTMeta{
		Transport: database.TransportSMTP, DKIMStatus: "absent",
	}, "u-1.json", []byte("{}")); err != nil {
		t.Fatal(err)
	}

	if alerts := fireRule(t, db, tlsCfg(), "tls_cert_expired"); len(alerts) != 0 {
		t.Errorf("alerts = %+v, want none from an excluded report", alerts)
	}

	lenient := tlsCfg()
	lenient.TLSRPTRequireDKIM = false
	if alerts := fireRule(t, db, lenient, "tls_cert_expired"); len(alerts) != 1 {
		t.Errorf("alerts = %+v, want the alert once the requirement is off", alerts)
	}
}

// An empty database produces no TLS alerts and no errors.
func TestTLSRulesQuietOnEmptyDatabase(t *testing.T) {
	db := openDB(t)
	ctx := &Context{DB: db, Cfg: tlsCfg(), Now: time.Now().UTC()}
	for _, r := range Rules {
		if !strings.HasPrefix(r.Name, "tls_") {
			continue
		}
		out, err := r.Fn(ctx)
		if err != nil {
			t.Errorf("%s on an empty database: %v", r.Name, err)
		}
		if len(out) != 0 {
			t.Errorf("%s fired on an empty database: %+v", r.Name, out)
		}
	}
}
