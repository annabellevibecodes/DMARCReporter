package database

import (
	"strings"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// bimiReportXML builds an aggregate report carrying a <bimi> element. The
// records are a fixed 100 passing / 10 failing so the volume arithmetic in the
// B11 and B20 tests is easy to follow.
func bimiReportXML(org, reportID, domain, policy string, begin int64, bimi string) string {
	return `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>` + org + `</org_name><report_id>` + reportID + `</report_id>
  <date_range><begin>` + itoa64(begin) + `</begin><end>` + itoa64(begin+86399) + `</end></date_range></report_metadata>
  <policy_published><domain>` + domain + `</domain><p>` + policy + `</p><adkim>r</adkim><aspf>r</aspf></policy_published>
  <record>
    <row><source_ip>192.0.2.10</source_ip><count>100</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>` + domain + `</header_from></identifiers>
  </record>
  <record>
    <row><source_ip>192.0.2.20</source_ip><count>10</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>` + domain + `</header_from></identifiers>
  </record>
` + bimi + `
</feedback>`
}

func saveBIMIReport(t *testing.T, db *sqlx.DB, org, reportID, domain, policy string, begin int64, bimi string) int64 {
	t.Helper()
	raw := bimiReportXML(org, reportID, domain, policy, begin, bimi)
	fb, err := parser.ParseXML(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", reportID, err)
	}
	id, err := SaveReport(db, fb, reportID+".xml", []byte(raw))
	if err != nil {
		t.Fatalf("save %s: %v", reportID, err)
	}
	return id
}

// bimiBlock is the <bimi> element for one domain, selector and error set.
func bimiBlock(domain, selector, l, a string, errors ...string) string {
	body := ""
	if len(errors) > 0 {
		body = "<errors>" + strings.Join(errors, "") + "</errors>"
	}
	return `  <bimi>
    <domain aligned="` + domain + `" assertion="` + domain + `">
      <assertion selector="` + selector + `" l="` + l + `" a="` + a + `">` + body + `</assertion>
    </domain>
  </bimi>`
}

func errEl(element, class, errType string, count int64) string {
	attr := ` class="` + class + `"`
	if errType != "" {
		attr += ` type="` + errType + `"`
	}
	return "<" + element + attr + ">" + itoa64(count) + "</" + element + ">"
}

func TestBIMIReportingStoresAssertionsAndErrors(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	id := saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem",
			errEl("indicator", "temp", "retrieval", 4)))

	rows, errs, err := ListBIMIAssertions(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("assertions = %d, want 1", len(rows))
	}
	if rows[0].Selector != "default" || rows[0].LValue != "https://example.com/logo.svg" {
		t.Errorf("assertion = %+v", rows[0])
	}
	if got := errs[rows[0].ID]; len(got) != 1 || got[0].Count != 4 {
		t.Errorf("errors = %+v", got)
	}

	// An assertion with no errors is the schema's only success signal and must
	// be stored just the same.
	id2 := saveBIMIReport(t, db, "outlook.com", "o1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem"))
	rows, errs, err = ListBIMIAssertions(db, id2)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("assertions = %d, want the error-free assertion kept", len(rows))
	}
	if len(errs) != 0 {
		t.Errorf("errors = %+v, want none", errs)
	}
}

// B11: the denominator. A domain at p=none contributes nothing however well
// its mail authenticates.
func TestGetBIMIEligibleVolume(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	saveBIMIReport(t, db, "google.com", "g1", "enforced.example", "reject", begin, "")
	saveBIMIReport(t, db, "google.com", "g2", "monitored.example", "none", begin, "")

	got, err := GetBIMIEligibleVolume(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 220 {
		t.Errorf("total = %d, want 220", got.Total)
	}
	if got.Passed != 200 {
		t.Errorf("passed = %d, want 200 (both domains authenticate the same)", got.Passed)
	}
	if got.Eligible != 100 {
		t.Errorf("eligible = %d, want only the enforcing domain's passing mail", got.Eligible)
	}
	byDomain := map[string]int64{}
	for _, d := range got.Domains {
		byDomain[d.Domain] = d.Eligible
	}
	if byDomain["enforced.example"] != 100 || byDomain["monitored.example"] != 0 {
		t.Errorf("per-domain eligible = %v", byDomain)
	}
}

// A sampled quarantine policy is not at full effect, so it is not eligible —
// and pct is read through pct_present, never defaulted.
func TestBIMIEligibleVolumeHonoursPct(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()

	raw := strings.Replace(
		bimiReportXML("google.com", "g1", "sampled.example", "quarantine", begin, ""),
		"<aspf>r</aspf>", "<aspf>r</aspf><pct>50</pct>", 1)
	fb, err := parser.ParseXML(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveReport(db, fb, "g1.xml", []byte(raw)); err != nil {
		t.Fatal(err)
	}

	got, err := GetBIMIEligibleVolume(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Eligible != 0 {
		t.Errorf("eligible = %d, want 0 for p=quarantine with pct=50", got.Eligible)
	}
	if got.Passed != 100 {
		t.Errorf("passed = %d, want the authentication still counted", got.Passed)
	}
}

func TestBIMIErrorsAndPermanentShare(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem",
			errEl("indicator", "temp", "retrieval", 4),
			errEl("evidence", "perm", "expired", 6)))
	saveBIMIReport(t, db, "outlook.com", "o1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem",
			errEl("evidence", "perm", "policy", 10)))

	errs, err := GetBIMIErrors(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(errs) != 3 {
		t.Fatalf("error rows = %d, want one per evaluator and tuple: %+v", len(errs), errs)
	}
	if errs[0].Count != 10 || errs[0].OrgName != "outlook.com" {
		t.Errorf("largest error row = %+v, want the 10-count policy rejection", errs[0])
	}

	share, err := GetBIMIPermanentShare(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if share.Total != 20 || share.Permanent != 16 || share.Temporary != 4 {
		t.Errorf("share = %+v, want 20 total / 16 perm / 4 temp", share)
	}
	if share.Share < 79 || share.Share > 81 {
		t.Errorf("permanent share = %.1f%%, want 80", share.Share)
	}
	if len(share.ByOrg) != 2 {
		t.Errorf("by org = %+v", share.ByOrg)
	}

	// B16: the policy rejection is separable from the rest.
	rejections, err := GetBIMIPolicyRejections(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rejections) != 1 || rejections[0].Count != 10 || rejections[0].OrgName != "outlook.com" {
		t.Errorf("policy rejections = %+v", rejections)
	}
}

// B18: coverage is what stops an empty B12 being read as good news.
func TestGetBIMICoverage(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "",
			errEl("indicator", "temp", "retrieval", 1)))
	saveBIMIReport(t, db, "outlook.com", "o1", "example.com", "reject", begin, "")
	saveBIMIReport(t, db, "yahoo.com", "y1", "example.com", "reject", begin, "")

	got, err := GetBIMICoverage(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Reporters != 3 || got.ReportersWith != 1 {
		t.Errorf("reporters = %d of which %d emit BIMI data", got.Reporters, got.ReportersWith)
	}
	if got.TotalMessages != 330 || got.CoveredMessages != 110 {
		t.Errorf("messages = %d covered of %d", got.CoveredMessages, got.TotalMessages)
	}
	if got.Share < 33 || got.Share > 34 {
		t.Errorf("share = %.1f%%, want about a third", got.Share)
	}
	if len(got.Orgs) != 1 || got.Orgs[0] != "google.com" {
		t.Errorf("orgs = %v, want the one reporter that tells us", got.Orgs)
	}
}

// B17: agreement and disagreement are different findings, and the second sorts
// first because it is the one worth looking at.
func TestGetBIMIDivergence(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()

	// One configuration: google refuses it, outlook accepts it.
	saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem",
			errEl("evidence", "perm", "policy", 3)))
	saveBIMIReport(t, db, "outlook.com", "o1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "https://example.com/vmc.pem"))
	// Another where both agree it is broken.
	saveBIMIReport(t, db, "google.com", "g2", "example.com", "reject", begin+86400,
		bimiBlock("example.com", "winter", "https://example.com/winter.svg", "",
			errEl("indicator", "perm", "validation", 2)))
	saveBIMIReport(t, db, "outlook.com", "o2", "example.com", "reject", begin+86400,
		bimiBlock("example.com", "winter", "https://example.com/winter.svg", "",
			errEl("indicator", "perm", "validation", 5)))

	got, err := GetBIMIDivergence(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("configurations = %d, want 2: %+v", len(got), got)
	}
	if !got[0].Disagree {
		t.Errorf("the disagreement must sort first: %+v", got[0])
	}
	if got[0].Selector != "default" || got[0].Clean != 1 || got[0].Failing != 1 {
		t.Errorf("divergent row = %+v, want one clean and one failing verdict", got[0])
	}
	if got[1].Disagree {
		t.Errorf("both evaluators reported the same error for winter: %+v", got[1])
	}
	if got[1].Failing != 2 {
		t.Errorf("winter verdicts = %+v", got[1].Verdicts)
	}
}

// B14 and B15: what the evaluators echoed back, and how old their judgement of
// the evidence document is.
func TestBIMIReportedConfigsAndFreshness(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	evaluated := time.Unix(begin, 0).UTC().AddDate(0, 0, -10)

	block := `  <bimi>
    <domain aligned="example.com" assertion="example.com">
      <assertion selector="default" l="https://example.com/logo.svg" a="https://example.com/vmc.pem">
        <evidence evidence-date="` + evaluated.Format(time.RFC1123Z) + `"
                  evidence-issuer="Test MVA" evidence-type="VMC"
                  evidence-url="https://example.com/vmc.pem" />
      </assertion>
    </domain>
  </bimi>`
	saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin, block)

	configs, err := GetBIMIReportedConfigs(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 1 {
		t.Fatalf("configs = %+v", configs)
	}
	if configs[0].LValue != "https://example.com/logo.svg" || configs[0].AValue != "https://example.com/vmc.pem" {
		t.Errorf("config = %+v", configs[0])
	}

	fresh, err := GetBIMIEvidenceFreshness(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 1 {
		t.Fatalf("freshness = %+v", fresh)
	}
	// The window ends a day after it begins, and the evaluation is ten days
	// older than that.
	if fresh[0].AgeDays < 10 || fresh[0].AgeDays > 12 {
		t.Errorf("age = %d days, want about 11", fresh[0].AgeDays)
	}
	if fresh[0].Issuer != "Test MVA" {
		t.Errorf("issuer = %q", fresh[0].Issuer)
	}
}

// B19 and B20, including the rate that can exceed 100% and must not be clamped.
func TestBIMIHygieneAndImpressions(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()

	// 100 eligible messages, and an evaluator reporting 150 errors: one
	// message can produce several, so the rate goes over 100%.
	saveBIMIReport(t, db, "google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "",
			errEl("indicator", "perm", "validation", 150)))

	imp, err := GetBIMIImpressions(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if imp.Eligible != 100 || imp.Errors != 150 {
		t.Fatalf("impressions = %+v", imp)
	}
	if !imp.Over100 {
		t.Error("a rate above 100% must be flagged, not hidden")
	}
	if imp.Rate < 149 || imp.Rate > 151 {
		t.Errorf("rate = %.1f, want it reported as it is", imp.Rate)
	}
	if imp.Shown != 0 {
		t.Errorf("shown = %d, want it floored at zero rather than negative", imp.Shown)
	}

	// A report that breaks the draft's rules lands in the hygiene counters.
	broken := `  <bimi>
    <domain aligned="example.com" assertion="example.com">
      <assertion selector="default" l="https://example.com/logo.svg" a="">
        <errors>
          <indicator class="temp" type="retrieval">1</indicator>
          <indicator class="temp" type="retrieval">2</indicator>
          <indicator class="perm" type="nonsense">0</indicator>
        </errors>
      </assertion>
    </domain>
  </bimi>`
	saveBIMIReport(t, db, "outlook.com", "o1", "example.com", "reject", begin, broken)

	h, err := GetBIMIHygiene(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if h.ReportsWithBIMI != 2 {
		t.Errorf("reports with bimi = %d, want 2", h.ReportsWithBIMI)
	}
	if h.DupTuples != 1 {
		t.Errorf("duplicate tuples = %d, want 1", h.DupTuples)
	}
	if h.BadCounts != 1 {
		t.Errorf("bad counts = %d, want the zero counted", h.BadCounts)
	}
	if h.UnknownTypes != 1 {
		t.Errorf("unknown types = %d, want the unregistered type counted", h.UnknownTypes)
	}
	if h.ReportsAffected != 1 {
		t.Errorf("reports affected = %d, want only the broken one", h.ReportsAffected)
	}
	if h.Errors != 4 {
		t.Errorf("error rows = %d, want every tuple stored including the duplicates", h.Errors)
	}
}

// The backfill is how an existing database gains BIMI data, and it must be
// safe to run twice.
func TestBackfillBIMIFromStoredXML(t *testing.T) {
	db := openTestDB(t)
	begin := time.Now().UTC().AddDate(0, 0, -2).Truncate(24 * time.Hour).Unix()
	raw := bimiReportXML("google.com", "g1", "example.com", "reject", begin,
		bimiBlock("example.com", "default", "https://example.com/logo.svg", "",
			errEl("indicator", "temp", "retrieval", 3)))
	fb, err := parser.ParseXML(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	// Import as a pre-BIMI build would have: records and XML, no BIMI rows.
	fb.BIMI = nil
	fb.BIMIHygiene = models.BIMIHygiene{}
	id, err := SaveReport(db, fb, "g1.xml", []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if rows, _, _ := ListBIMIAssertions(db, id); len(rows) != 0 {
		t.Fatalf("assertions = %d before the backfill", len(rows))
	}

	res, err := BackfillBIMI(db)
	if err != nil {
		t.Fatal(err)
	}
	if res.WithBIMI != 1 || res.Assertions != 1 || res.Errors != 1 {
		t.Errorf("backfill = %+v", res)
	}
	rows, errs, err := ListBIMIAssertions(db, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("assertions = %v, %v", rows, err)
	}
	if got := errs[rows[0].ID]; len(got) != 1 || got[0].Count != 3 {
		t.Errorf("errors = %+v", got)
	}
	// The hygiene counters are rewritten too, so coverage counts the report.
	cov, err := GetBIMICoverage(db, StatsFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if cov.ReportsWith != 1 {
		t.Errorf("coverage after backfill = %+v", cov)
	}

	// Running it again must not duplicate anything.
	second, err := BackfillBIMI(db)
	if err != nil {
		t.Fatal(err)
	}
	if second.Assertions != 0 {
		t.Errorf("second run created %d assertion(s); the backfill must be idempotent", second.Assertions)
	}
	if rows, _, _ := ListBIMIAssertions(db, id); len(rows) != 1 {
		t.Errorf("assertions = %d after a second backfill", len(rows))
	}
}
