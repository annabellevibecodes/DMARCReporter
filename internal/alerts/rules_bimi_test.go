package alerts

import (
	"encoding/json"
	"net/mail"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// snapBIMI records one observation of a domain's assertion record.
func snapBIMI(t *testing.T, db *sqlx.DB, domain, selector, content string, at int64) {
	t.Helper()
	if _, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: domain, Selector: selector, Kind: database.BIMISnapshotRecord,
		Content: content, FirstSeen: at, LastSeen: at,
	}); err != nil {
		t.Fatalf("snapshot %s/%s: %v", domain, selector, err)
	}
}

func TestBIMIRecordChangedFiresOnlyOnAChange(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()

	// First observation: nothing to compare against, so no alert.
	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg", now.Add(-72*time.Hour).Unix())
	if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_record_changed"]) != 0 {
		t.Fatalf("first observation fired: %v", byRule["bimi_record_changed"])
	}

	// A rotated logo inside the recent window fires once.
	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo-2026.svg", now.Add(-2*time.Hour).Unix())
	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_record_changed"]
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want 1: %v", len(got), got)
	}
	if got[0].Domain != "example.com" || got[0].Key != "default" {
		t.Errorf("alert scoped to %s/%s", got[0].Domain, got[0].Key)
	}
	if got[0].Severity != database.SeverityInfo {
		t.Errorf("severity = %q, want info: a rotation is routine", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "logo published") {
		t.Errorf("message does not say what changed: %q", got[0].Message)
	}
}

// A record that stops resolving is the change worth catching, and it must not
// be reported as though the domain had withdrawn its logo.
func TestBIMIRecordChangedDistinguishesLossFromFailure(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()

	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg", now.Add(-72*time.Hour).Unix())
	if _, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: "example.com", Selector: "default", Kind: database.BIMISnapshotRecord,
		Content: "", Error: "server misbehaving",
		FirstSeen: now.Add(-time.Hour).Unix(), LastSeen: now.Add(-time.Hour).Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_record_changed"]
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Message, "lookup failed") {
		t.Errorf("message = %q, want it to name the lookup failure", got[0].Message)
	}
}

func TestBIMIBlockedByPolicy(t *testing.T) {
	db := openDB(t)
	now := time.Now().UTC()
	// A domain at p=none that nonetheless publishes a logo.
	for i := 1; i <= 3; i++ {
		begin := now.AddDate(0, 0, -i).Truncate(24 * time.Hour).Unix()
		save(t, db, "google.com", "n"+itoa(i), "example.com", "none", begin,
			recOpt{ip: "10.0.0.1", count: 100, dkim: "pass", spf: "pass"})
	}
	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg", now.Add(-time.Hour).Unix())

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_blocked_by_policy"]
	if len(got) != 1 {
		t.Fatalf("alerts = %d, want 1: %v", len(got), got)
	}
	if got[0].Severity != database.SeverityWarning {
		t.Errorf("severity = %q, want warning", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "p=none") {
		t.Errorf("message = %q, want the blocking tag named", got[0].Message)
	}
}

func TestBIMIBlockedByPolicyStaysQuietWhenItShould(t *testing.T) {
	now := time.Now().UTC()

	t.Run("policy qualifies", func(t *testing.T) {
		db := openDB(t)
		seedBaseline(t, db) // p=reject
		snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg", now.Add(-time.Hour).Unix())
		if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_blocked_by_policy"]) != 0 {
			t.Errorf("fired on an eligible domain: %v", byRule["bimi_blocked_by_policy"])
		}
	})

	t.Run("declination is a decision, not a fault", func(t *testing.T) {
		db := openDB(t)
		for i := 1; i <= 3; i++ {
			begin := now.AddDate(0, 0, -i).Truncate(24 * time.Hour).Unix()
			save(t, db, "google.com", "d"+itoa(i), "example.com", "none", begin,
				recOpt{ip: "10.0.0.1", count: 100, dkim: "pass", spf: "pass"})
		}
		snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=; a=;", now.Add(-time.Hour).Unix())
		if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_blocked_by_policy"]) != 0 {
			t.Errorf("fired on a declination: %v", byRule["bimi_blocked_by_policy"])
		}
	})

	t.Run("no reports means no verdict", func(t *testing.T) {
		db := openDB(t)
		snapBIMI(t, db, "unreported.example", "default", "v=BIMI1; l=https://unreported.example/l.svg", now.Add(-time.Hour).Unix())
		if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_blocked_by_policy"]) != 0 {
			t.Errorf("fired without knowing the policy: %v", byRule["bimi_blocked_by_policy"])
		}
	})
}

func TestBIMIUnexpectedSelector(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()

	if err := database.UpsertBIMISelector(db, database.BIMISelector{
		Domain: "example.com", Selector: "winter", Source: database.BIMISelectorPublished,
		FirstSeen: now.Add(-2 * time.Hour).Unix(), LastSeen: now.Unix(),
	}); err != nil {
		t.Fatal(err)
	}

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_unexpected_selector"]
	if len(got) != 1 || got[0].Key != "winter" {
		t.Fatalf("alerts = %v, want one for the winter selector", got)
	}

	// Marking it expected silences it.
	if err := database.SetBIMISelectorExpected(db, "example.com", "winter", 1); err != nil {
		t.Fatal(err)
	}
	if byRule, _ = fire(t, db, testCfg()); len(byRule["bimi_unexpected_selector"]) != 0 {
		t.Errorf("still firing after the selector was marked expected: %v", byRule["bimi_unexpected_selector"])
	}
}

// An old selector is not news, however unexpected it is.
func TestBIMIUnexpectedSelectorIgnoresOldOnes(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	old := time.Now().UTC().AddDate(0, 0, -30).Unix()
	if err := database.UpsertBIMISelector(db, database.BIMISelector{
		Domain: "example.com", Selector: "legacy", FirstSeen: old, LastSeen: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_unexpected_selector"]) != 0 {
		t.Errorf("fired on a selector first seen 30 days ago: %v", byRule["bimi_unexpected_selector"])
	}
}

// The BIMI rules must contribute nothing at all to a database that has never
// had an Enrich run, which is every database on the day this ships.
func TestBIMIRulesSilentWithoutSnapshots(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	byRule, _ := fire(t, db, testCfg())
	for _, rule := range []string{"bimi_record_changed", "bimi_blocked_by_policy", "bimi_unexpected_selector"} {
		if len(byRule[rule]) != 0 {
			t.Errorf("%s fired with no BIMI data: %v", rule, byRule[rule])
		}
	}
}

// snapDoc stores one fetched-document snapshot: the shape the Enrich worker
// writes, built here without a network so the rules can be exercised.
func snapDoc(t *testing.T, db *sqlx.DB, domain, selector, kind, content string, detail any, errMsg string) {
	t.Helper()
	blob, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: domain, Selector: selector, Kind: kind,
		Content: content, Detail: string(blob), Error: errMsg,
	}); err != nil {
		t.Fatal(err)
	}
}

func healthyIndicator(hash string) bimi.IndicatorResult {
	return bimi.IndicatorResult{
		Fetch:  bimi.FetchResult{URL: "https://example.com/logo.svg", Status: 200, Bytes: 900, Body: []byte("x")},
		SHA256: hash,
		Bytes:  900,
		SVGPS:  bimi.SVGPSResult{Valid: true, Title: "Example"},
		Valid:  true,
	}
}

func healthyEvidence(hash string, notAfter time.Time) bimi.EvidenceResult {
	return bimi.EvidenceResult{
		Fetch:              bimi.FetchResult{URL: "https://example.com/vmc.pem", Status: 200, Bytes: 4000, Body: []byte("x")},
		Certificates:       2,
		Subject:            "Example, Inc.",
		Issuer:             "Test MVA",
		NotAfter:           notAfter.Unix(),
		DaysToExpiry:       int(time.Until(notAfter).Hours() / 24),
		SANs:               []string{"example.com"},
		CoversRecordDomain: true,
		Fingerprint:        "fingerprint",
		Trusted:            true,
		RootSource:         bimi.RootsMVA,
		Mark:               &bimi.EmbeddedMark{SHA256: hash, HashMatches: true, SVGPS: bimi.SVGPSResult{Valid: true}},
		Revocation:         bimi.RevocationResult{Status: "good"},
		Valid:              true,
	}
}

// Nothing fires for a domain whose logo and certificate are in order.
func TestBIMIValidationRulesSilentWhenHealthy(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem", time.Now().Unix())
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fingerprint",
		healthyEvidence("hash-a", time.Now().AddDate(1, 0, 0)), "")

	byRule, _ := fire(t, db, testCfg())
	for _, rule := range []string{
		"bimi_indicator_unreachable", "bimi_indicator_invalid",
		"bimi_evidence_expiring", "bimi_evidence_invalid", "bimi_indicator_mismatch",
	} {
		if len(byRule[rule]) != 0 {
			t.Errorf("%s fired on a healthy setup: %v", rule, byRule[rule])
		}
	}
}

// A domain whose documents have never been checked raises nothing: the active
// checks are optional, and their absence must not read as breakage.
func TestBIMIValidationRulesSilentWithoutChecks(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	snapBIMI(t, db, "example.com", "default", "v=BIMI1; l=https://example.com/logo.svg", time.Now().Unix())

	byRule, _ := fire(t, db, testCfg())
	for _, rule := range []string{
		"bimi_indicator_unreachable", "bimi_indicator_invalid",
		"bimi_evidence_expiring", "bimi_evidence_invalid", "bimi_indicator_mismatch",
	} {
		if len(byRule[rule]) != 0 {
			t.Errorf("%s fired without any document check having run: %v", rule, byRule[rule])
		}
	}
}

func TestBIMIIndicatorUnreachable(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	broken := bimi.IndicatorResult{
		Fetch: bimi.FetchResult{URL: "https://example.com/logo.svg", Status: 404, Err: "HTTP 404"},
		Findings: []bimi.Finding{{
			Code: "indicator_unreachable", Severity: bimi.SeverityError,
			Message: "the indicator could not be retrieved: HTTP 404",
		}},
	}
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "", broken, "HTTP 404")

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_indicator_unreachable"]
	if len(got) != 1 {
		t.Fatalf("alerts = %v, want one", got)
	}
	if got[0].Severity != database.SeverityWarning || got[0].Key != "default" {
		t.Errorf("alert = %+v", got[0])
	}
	// A logo that never arrived cannot also be reported as non-conforming.
	if n := len(byRule["bimi_indicator_invalid"]); n != 0 {
		t.Errorf("bimi_indicator_invalid fired %d time(s) for an unreachable logo", n)
	}
}

func TestBIMIIndicatorInvalid(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	bad := healthyIndicator("hash-a")
	bad.Valid = false
	bad.SVGPS = bimi.SVGPSResult{Valid: false, Findings: []bimi.Finding{
		{Code: "svgps_element", Severity: bimi.SeverityError, Message: "<image> is not in the profile's grammar"},
	}}
	bad.Findings = []bimi.Finding{{Code: "indicator_element", Severity: bimi.SeverityError, Message: "<image> is not in the profile's grammar"}}
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", bad, "")

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_indicator_invalid"]
	if len(got) != 1 {
		t.Fatalf("alerts = %v, want one", got)
	}
	if !strings.Contains(got[0].Message, "svgps_element") {
		t.Errorf("message = %q, want the breach named", got[0].Message)
	}
}

func TestBIMIEvidenceExpiryRules(t *testing.T) {
	t.Run("expiring", func(t *testing.T) {
		db := openDB(t)
		seedBaseline(t, db)
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fp",
			healthyEvidence("hash-a", time.Now().AddDate(0, 0, 10)), "")

		byRule, _ := fire(t, db, testCfg())
		got := byRule["bimi_evidence_expiring"]
		if len(got) != 1 || got[0].Severity != database.SeverityWarning {
			t.Fatalf("alerts = %v, want one warning", got)
		}
		if len(byRule["bimi_evidence_invalid"]) != 0 {
			t.Error("an expiring document is not yet invalid")
		}
	})

	t.Run("expired", func(t *testing.T) {
		db := openDB(t)
		seedBaseline(t, db)
		expired := healthyEvidence("hash-a", time.Now().AddDate(0, 0, -1))
		expired.Valid = false
		expired.Findings = []bimi.Finding{{
			Code: "evidence_expired", Severity: bimi.SeverityError,
			Message: "the evidence document expired on 2026-09-17",
		}}
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fp", expired, "expired")

		byRule, _ := fire(t, db, testCfg())
		got := byRule["bimi_evidence_invalid"]
		if len(got) != 1 || got[0].Severity != database.SeverityCritical {
			t.Fatalf("alerts = %v, want one critical", got)
		}
		// Not also warned about as "expiring": that would be two alerts for
		// one fact, at two severities.
		if len(byRule["bimi_evidence_expiring"]) != 0 {
			t.Errorf("an expired document also raised the expiry warning: %v", byRule["bimi_evidence_expiring"])
		}
	})

	t.Run("untrusted", func(t *testing.T) {
		db := openDB(t)
		seedBaseline(t, db)
		untrusted := healthyEvidence("hash-a", time.Now().AddDate(1, 0, 0))
		untrusted.Trusted, untrusted.Valid = false, false
		untrusted.Findings = []bimi.Finding{{
			Code: "evidence_untrusted", Severity: bimi.SeverityError,
			Message: "the evidence document does not chain to a trusted root",
		}}
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
		snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fp", untrusted, "")

		byRule, _ := fire(t, db, testCfg())
		if got := byRule["bimi_evidence_invalid"]; len(got) != 1 {
			t.Fatalf("alerts = %v, want one", got)
		}
	})
}

// X27: the two documents are each fine, and the logo still will not show.
func TestBIMIIndicatorMismatch(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fp",
		healthyEvidence("hash-b", time.Now().AddDate(1, 0, 0)), "")

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_indicator_mismatch"]
	if len(got) != 1 {
		t.Fatalf("alerts = %v, want one", got)
	}
	if got[0].Severity != database.SeverityCritical {
		t.Errorf("severity = %q, want critical", got[0].Severity)
	}
	if !strings.Contains(got[0].Message, "§7.9") {
		t.Errorf("message = %q, want the rule cited", got[0].Message)
	}
	// Nothing else fires: both documents are individually healthy.
	for _, rule := range []string{"bimi_indicator_unreachable", "bimi_indicator_invalid", "bimi_evidence_invalid"} {
		if len(byRule[rule]) != 0 {
			t.Errorf("%s also fired: %v", rule, byRule[rule])
		}
	}
}

// Two selectors of one domain are two separate alerts, not one overwriting the
// other.
func TestBIMIAlertsAreScopedPerSelector(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	for _, sel := range []string{"default", "winter"} {
		snapDoc(t, db, "example.com", sel, database.BIMISnapshotIndicator, "hash-"+sel, healthyIndicator("hash-"+sel), "")
		snapDoc(t, db, "example.com", sel, database.BIMISnapshotEvidence, "fp-"+sel,
			healthyEvidence("other-"+sel, time.Now().AddDate(1, 0, 0)), "")
	}
	byRule, _ := fire(t, db, testCfg())
	if got := byRule["bimi_indicator_mismatch"]; len(got) != 2 {
		t.Fatalf("alerts = %d, want one per selector: %v", len(got), got)
	}
}

// saveBIMIReportXML stores an aggregate report carrying a <bimi> element.
func saveBIMIReportXML(t *testing.T, db *sqlx.DB, org, id, domain string, begin int64, bimi string) {
	t.Helper()
	raw := `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>` + org + `</org_name><report_id>` + id + `</report_id>
  <date_range><begin>` + strconv.FormatInt(begin, 10) + `</begin><end>` + strconv.FormatInt(begin+86399, 10) + `</end></date_range></report_metadata>
  <policy_published><domain>` + domain + `</domain><p>reject</p></policy_published>
  <record><row><source_ip>192.0.2.1</source_ip><count>100</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>` + domain + `</header_from></identifiers></record>
` + bimi + `
</feedback>`
	fb, err := parser.ParseXML(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := database.SaveReport(db, fb, id+".xml", []byte(raw)); err != nil {
		t.Fatalf("save: %v", err)
	}
}

func bimiErrBlock(domain, selector string, errors string) string {
	return `  <bimi><domain aligned="` + domain + `" assertion="` + domain + `">
      <assertion selector="` + selector + `" l="https://` + domain + `/logo.svg" a="">` + errors + `</assertion>
    </domain></bimi>`
}

// X28: a tuple nobody has reported before, with a permanent class treated as
// critical because of what it lets the evaluator do next.
func TestBIMIErrorsReported(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	begin := time.Now().UTC().Add(-3 * time.Hour).Unix()

	saveBIMIReportXML(t, db, "google.com", "bg1", "example.com", begin,
		bimiErrBlock("example.com", "default",
			`<errors><indicator class="perm" type="validation" description="not SVG P/S">12</indicator>
			         <assertion class="temp" type="retrieval">3</assertion></errors>`))

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_errors_reported"]
	if len(got) != 2 {
		t.Fatalf("alerts = %d, want one per new tuple: %v", len(got), got)
	}
	bySeverity := map[string]Alert{}
	for _, a := range got {
		bySeverity[a.Severity] = a
	}
	if _, ok := bySeverity[database.SeverityCritical]; !ok {
		t.Errorf("no critical alert for the permanent error: %v", got)
	}
	if _, ok := bySeverity[database.SeverityInfo]; !ok {
		t.Errorf("no informational alert for the temporary error: %v", got)
	}
	if a := bySeverity[database.SeverityCritical]; !strings.Contains(a.Message, "stop evaluating BIMI") {
		t.Errorf("message does not explain why a permanent error is critical: %q", a.Message)
	}
}

// A tuple that has been reported for months is not news.
func TestBIMIErrorsReportedIgnoresOldTuples(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	old := time.Now().UTC().AddDate(0, 0, -30).Unix()

	saveBIMIReportXML(t, db, "google.com", "old1", "example.com", old,
		bimiErrBlock("example.com", "default",
			`<errors><indicator class="temp" type="retrieval">1</indicator></errors>`))
	saveBIMIReportXML(t, db, "google.com", "new1", "example.com", time.Now().UTC().Add(-2*time.Hour).Unix(),
		bimiErrBlock("example.com", "default",
			`<errors><indicator class="temp" type="retrieval">9</indicator></errors>`))

	byRule, _ := fire(t, db, testCfg())
	if got := byRule["bimi_errors_reported"]; len(got) != 0 {
		t.Errorf("alerts = %v, want none: the tuple has been reported for a month", got)
	}
}

// X29: one configuration, two verdicts.
func TestBIMIEvaluatorDivergence(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	begin := time.Now().UTC().Add(-3 * time.Hour).Unix()

	saveBIMIReportXML(t, db, "google.com", "dg1", "example.com", begin,
		bimiErrBlock("example.com", "default",
			`<errors><evidence class="perm" type="policy">4</evidence></errors>`))
	saveBIMIReportXML(t, db, "outlook.com", "do1", "example.com", begin,
		bimiErrBlock("example.com", "default", ""))

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_evaluator_divergence"]
	if len(got) != 1 {
		t.Fatalf("alerts = %v, want one", got)
	}
	if got[0].Severity != database.SeverityWarning || got[0].Key != "default" {
		t.Errorf("alert = %+v", got[0])
	}
	if !strings.Contains(got[0].Message, "outlook.com reported no errors") {
		t.Errorf("message = %q, want both sides named", got[0].Message)
	}
}

// Evaluators that agree — even agreeing that it is broken — are not a
// divergence.
func TestBIMIEvaluatorDivergenceSilentWhenTheyAgree(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	begin := time.Now().UTC().Add(-3 * time.Hour).Unix()
	errs := `<errors><indicator class="perm" type="validation">2</indicator></errors>`

	saveBIMIReportXML(t, db, "google.com", "ag1", "example.com", begin, bimiErrBlock("example.com", "default", errs))
	saveBIMIReportXML(t, db, "outlook.com", "ao1", "example.com", begin, bimiErrBlock("example.com", "default", errs))

	byRule, _ := fire(t, db, testCfg())
	if got := byRule["bimi_evaluator_divergence"]; len(got) != 0 {
		t.Errorf("alerts = %v, want none when the evaluators agree", got)
	}
}

// seedVerdict records one receiver verdict on seed mail.
func seedVerdict(t *testing.T, db *sqlx.DB, receiver, domain, result string, at time.Time, comment string) {
	t.Helper()
	ar := "mx." + receiver + "; bimi=" + result
	if comment != "" {
		ar += " (" + comment + ")"
	}
	ar += " header.d=" + domain + " header.selector=default"
	header := mail.Header{
		"Message-Id":             {"<" + receiver + result + strconv.FormatInt(at.Unix(), 10) + "@seed>"},
		"From":                   {"news@" + domain},
		"Date":                   {at.Format(time.RFC1123Z)},
		"Authentication-Results": {ar},
	}
	if _, err := database.RecordSeedVerdicts(db, 1, header, 0); err != nil {
		t.Fatal(err)
	}
}

// X30: a receiver that showed the logo and stopped.
func TestBIMIVerdictRegression(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()

	seedVerdict(t, db, "google.com", "example.com", "pass", now.AddDate(0, 0, -5), "")
	seedVerdict(t, db, "google.com", "example.com", "pass", now.AddDate(0, 0, -2), "")
	if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_verdict_regression"]) != 0 {
		t.Fatalf("fired while the receiver still passes: %v", byRule["bimi_verdict_regression"])
	}

	seedVerdict(t, db, "google.com", "example.com", "fail", now.Add(-2*time.Hour), "Invalid SVG")
	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_verdict_regression"]
	if len(got) != 1 {
		t.Fatalf("alerts = %v, want one", got)
	}
	if got[0].Domain != "example.com" || got[0].Severity != database.SeverityWarning {
		t.Errorf("alert = %+v", got[0])
	}
	if !strings.Contains(got[0].Message, "Invalid SVG") {
		t.Errorf("message = %q, want the receiver's own explanation", got[0].Message)
	}
	if !strings.Contains(got[0].Message, "last passed") {
		t.Errorf("message = %q, want it to say when it last worked", got[0].Message)
	}
}

// A receiver that has never shown the logo is a state, not a regression — and
// would otherwise alert for every receiver the day a seed mailbox is added.
func TestBIMIVerdictRegressionNeedsAPreviousPass(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	now := time.Now().UTC()

	seedVerdict(t, db, "outlook.com", "example.com", "none", now.AddDate(0, 0, -2), "")
	seedVerdict(t, db, "outlook.com", "example.com", "skipped", now.Add(-time.Hour), "message failed DMARC")

	if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_verdict_regression"]) != 0 {
		t.Errorf("alerts = %v, want none for a receiver that never passed", byRule["bimi_verdict_regression"])
	}
}

// With no seed mailbox and no verdicts, the rule contributes nothing.
func TestBIMIVerdictRegressionSilentWithoutSeedMail(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	if byRule, _ := fire(t, db, testCfg()); len(byRule["bimi_verdict_regression"]) != 0 {
		t.Errorf("alerts = %v, want none", byRule["bimi_verdict_regression"])
	}
}

// X26 also fires on a certificate that disagrees with its own embedded mark:
// internally inconsistent is as unusable as expired.
func TestBIMIEvidenceInvalidOnSelfContradiction(t *testing.T) {
	db := openDB(t)
	seedBaseline(t, db)
	broken := healthyEvidence("hash-a", time.Now().AddDate(1, 0, 0))
	broken.Valid = false
	broken.Mark.HashMatches = false
	broken.Findings = []bimi.Finding{{
		Code: "evidence_mark_hash", Severity: bimi.SeverityError,
		Message: "the SHA1 hash the certificate records for its own mark does not match the mark embedded in it",
	}}
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotIndicator, "hash-a", healthyIndicator("hash-a"), "")
	snapDoc(t, db, "example.com", "default", database.BIMISnapshotEvidence, "fp", broken, "")

	byRule, _ := fire(t, db, testCfg())
	got := byRule["bimi_evidence_invalid"]
	if len(got) != 1 || got[0].Severity != database.SeverityCritical {
		t.Fatalf("alerts = %v, want one critical", got)
	}
	if !strings.Contains(got[0].Message, "does not match") {
		t.Errorf("message = %q", got[0].Message)
	}
}
