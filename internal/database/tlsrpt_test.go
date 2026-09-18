package database

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/dkimcheck"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

//go:embed testdata/tlsrpt/*.json
var tlsrptFixtures embed.FS

// loadTLSFixture parses a fixture through the real ingest parser, so these
// tests exercise the same path an imported report takes.
func loadTLSFixture(t *testing.T, name string) (*parser.TLSReport, []byte) {
	t.Helper()
	raw, err := tlsrptFixtures.ReadFile("testdata/tlsrpt/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	report, jsonBytes, err := parser.ParseTLSRPT(name, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return report, jsonBytes
}

// saveTLSFixture imports a fixture as a mailed, validly signed report.
func saveTLSFixture(t *testing.T, db *sqlx.DB, name, filename string) int64 {
	t.Helper()
	report, raw := loadTLSFixture(t, name)
	meta := TLSRPTMeta{
		ReceivedAt: report.DateRange.End.Unix() + 3600,
		Transport:  TransportSMTP,
		DKIMStatus: string(dkimcheck.StatusValid),
		DKIMDomain: "reporter.example",
	}
	id, err := SaveTLSRPTWithMeta(db, report, meta, filename, raw)
	if err != nil {
		t.Fatalf("save fixture %s: %v", name, err)
	}
	return id
}

func getTLSReport(t *testing.T, db *sqlx.DB, id int64) TLSRPTReport {
	t.Helper()
	var r TLSRPTReport
	if err := db.Get(&r, `SELECT `+tlsrptListColumns+` FROM tlsrpt_reports WHERE id = ?`, id); err != nil {
		t.Fatalf("get report %d: %v", id, err)
	}
	return r
}

// The RFC 8460 Appendix B example must import and reproduce its counts
// exactly, including the policy body and every failure-detail row.
func TestSaveTLSRPTAppendixB(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "appendix-b.json", "company-x.example!company-y.example!1459468800!1459555199.json")

	r := getTLSReport(t, db, id)
	if r.TotalSuccess != 5326 || r.TotalFailure != 303 {
		t.Errorf("totals = %d/%d, want 5326/303", r.TotalSuccess, r.TotalFailure)
	}
	if r.OrgName != "Company-X" || r.ReportID != "5065427c-23d3-47ca-b6e0-946ea0e8c4be" {
		t.Errorf("metadata = %q / %q", r.OrgName, r.ReportID)
	}
	if r.UnattributedFailures != 0 || r.UnknownResultTypes != 0 || r.MalformedIPs != 0 || r.MultiPolicy != 0 {
		t.Errorf("hygiene counters should all be zero, got %+v", r)
	}

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 1 {
		t.Fatalf("policies = %d, want 1", len(policies))
	}
	p := policies[0]
	if p.PolicyType != "sts" || p.PolicyDomain != "company-y.example" {
		t.Errorf("policy = %q / %q", p.PolicyType, p.PolicyDomain)
	}
	if p.STSVersion != "STSv1" || p.STSMode != "testing" || p.STSMaxAge != 86400 {
		t.Errorf("parsed sts policy = %q / %q / %d, want STSv1 / testing / 86400", p.STSVersion, p.STSMode, p.STSMaxAge)
	}
	if p.MXHostPattern != "*.mail.company-y.example" {
		t.Errorf("mx pattern = %q", p.MXHostPattern)
	}
	if p.SuccessCount != 5326 || p.FailureCount != 303 {
		t.Errorf("policy counts = %d/%d", p.SuccessCount, p.FailureCount)
	}

	failures, err := ListTLSRPTFailures(db, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 3 {
		t.Fatalf("failure rows = %d, want 3", len(failures))
	}
	// Every optional field the example omits stays empty rather than being
	// invented, and the IPv6 sending address is stored canonicalised.
	first := failures[0]
	if first.ResultType != "certificate-expired" || first.FailedSessionCount != 100 {
		t.Errorf("first failure = %+v", first)
	}
	if first.SendingMTAIP.String != "2001:db8:abcd:12::1" {
		t.Errorf("sending ip = %q, want canonical 2001:db8:abcd:12::1", first.SendingMTAIP.String)
	}
	if first.ReceivingIP.Valid || first.ReceivingMXHelo != "" {
		t.Errorf("absent optional fields should stay unset, got %+v", first)
	}
	if got := failures[2].FailureReasonCode; got != "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED" {
		t.Errorf("reason code = %q", got)
	}
}

// I1. Result types are non-exclusive: one session hitting several errors
// appears in several detail rows, so Σ failed-session-count can exceed the
// summary. The reported total must come from the summary field.
func TestInvariantI1FailureTotalNeverSummedFromDetails(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "overlapping-failure-types.json", "overlapping.json")

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if policies[0].FailureCount != 60 {
		t.Errorf("policy failure count = %d, want the summary value 60", policies[0].FailureCount)
	}

	var detailSum int64
	if err := db.Get(&detailSum, `
		SELECT COALESCE(SUM(f.failed_session_count), 0) FROM tlsrpt_failures f
		 JOIN tlsrpt_policies p ON p.id = f.policy_id WHERE p.tlsrpt_report_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if detailSum != 115 {
		t.Fatalf("fixture should overlap: detail sum = %d, want 115", detailSum)
	}

	totals, err := TLSSessionTotals(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Failure != 60 {
		t.Errorf("rolled-up failures = %d, want 60 (the summary), not %d (the detail sum)", totals.Failure, detailSum)
	}
}

// I2. Two policy entries can describe the same sessions. They are stored
// verbatim, and the rollup that collapses them happens at query time by
// taking the maximum within (report, policy domain, mx pattern).
func TestInvariantI2MultiPolicyRollupIsQueryTime(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "multi-policy-same-domain.json", "multi.json")

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies = %d, want both entries stored", len(policies))
	}
	// Stored exactly as received — the rollup must not have edited these.
	if policies[0].SuccessCount != 900 || policies[0].FailureCount != 10 ||
		policies[1].SuccessCount != 900 || policies[1].FailureCount != 8 {
		t.Errorf("stored counts were altered: %+v / %+v", policies[0], policies[1])
	}
	if policies[0].PolicyType != "sts" || policies[1].PolicyType != "tlsa" {
		t.Errorf("policy types = %q / %q", policies[0].PolicyType, policies[1].PolicyType)
	}

	r := getTLSReport(t, db, id)
	if r.MultiPolicy != 1 {
		t.Error("report should be flagged multi-policy so the UI can explain the rollup")
	}

	totals, err := TLSSessionTotals(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Success != 900 {
		t.Errorf("rolled-up successes = %d, want 900 (max), not 1800 (sum)", totals.Success)
	}
	if totals.Failure != 10 {
		t.Errorf("rolled-up failures = %d, want 10 (max), not 18 (sum)", totals.Failure)
	}
	if totals.MultiPolicyReports != 1 {
		t.Errorf("multi-policy reports = %d, want 1", totals.MultiPolicyReports)
	}
}

// I3. Detail rows may account for less than the summary. The difference is
// surfaced as unattributed failures, never hidden.
func TestInvariantI3UnattributedFailures(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "detail-under-total.json", "under.json")

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if got := policies[0].UnattributedFailures; got != 65 {
		t.Errorf("policy unattributed = %d, want 90 − 25 = 65", got)
	}
	if got := getTLSReport(t, db, id).UnattributedFailures; got != 65 {
		t.Errorf("report unattributed = %d, want 65", got)
	}
}

// I4. Time bucketing uses the body's date-range. A filename that disagrees is
// counted as a hygiene finding and otherwise ignored (RFC 8460 §5.6).
func TestInvariantI4BodyDateRangeWinsOverFilename(t *testing.T) {
	db := openTestDB(t)

	// 2026-09-10T00:00:00Z … 23:59:59Z in the body; the filename claims a
	// different window entirely.
	const bodyBegin, bodyEnd = 1788998400, 1789084799
	id := saveTLSFixture(t, db, "metadata-variance.json",
		"reporter-v.example!example.com!1111111111!2222222222!v1.json.gz")

	r := getTLSReport(t, db, id)
	if r.DateRangeBegin != bodyBegin || r.DateRangeEnd != bodyEnd {
		t.Errorf("stored range = %d–%d, want the body's %d–%d",
			r.DateRangeBegin, r.DateRangeEnd, bodyBegin, bodyEnd)
	}
	if r.RangeVariance != 1 {
		t.Error("filename/body disagreement should be counted")
	}

	// The same report under a filename that agrees is not flagged.
	db2 := openTestDB(t)
	id2 := saveTLSFixture(t, db2, "metadata-variance.json",
		fmt.Sprintf("reporter-v.example!example.com!%d!%d!v1.json.gz", bodyBegin, bodyEnd))
	if got := getTLSReport(t, db2, id2).RangeVariance; got != 0 {
		t.Errorf("agreeing filename flagged as variance (%d)", got)
	}
}

// I5. Two spellings of one IPv6 address must group as a single value, and a
// malformed address is stored as NULL and counted rather than dropping the row.
func TestInvariantI5IPv6NormalisationAndMalformedIPs(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "mixed-ip-families.json", "ipmix.json")

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	failures, err := ListTLSRPTFailures(db, policies[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(failures) != 3 {
		t.Fatalf("failure rows = %d, want all 3 kept including the malformed one", len(failures))
	}

	var distinctSending, distinctReceiving int
	if err := db.Get(&distinctSending, `
		SELECT COUNT(DISTINCT f.sending_mta_ip) FROM tlsrpt_failures f
		 JOIN tlsrpt_policies p ON p.id = f.policy_id WHERE p.tlsrpt_report_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	if err := db.Get(&distinctReceiving, `
		SELECT COUNT(DISTINCT f.receiving_ip) FROM tlsrpt_failures f
		 JOIN tlsrpt_policies p ON p.id = f.policy_id WHERE p.tlsrpt_report_id = ?`, id); err != nil {
		t.Fatal(err)
	}
	// 2001:db8:0:0:0:0:0:1 and 2001:db8::1 are one address; the third row's
	// sending IP is NULL, which COUNT(DISTINCT) ignores.
	if distinctSending != 1 {
		t.Errorf("distinct sending IPs = %d, want 1 — the two spellings must collapse", distinctSending)
	}
	if distinctReceiving != 1 {
		t.Errorf("distinct receiving IPs = %d, want 1", distinctReceiving)
	}
	if got := getTLSReport(t, db, id).MalformedIPs; got != 2 {
		t.Errorf("malformed IP count = %d, want 2 (one sending, one receiving)", got)
	}
}

// I6. mx_host_pattern is a wildcard pattern, never a hostname: an equality
// join to receiving_mx_hostname finds nothing even when the host does match.
// Matching goes through the RFC 8461 §4.1 rules instead.
func TestInvariantI6MXPatternIsNotAHostname(t *testing.T) {
	db := openTestDB(t)
	id := saveTLSFixture(t, db, "mx-wildcard-patterns.json", "pattern.json")

	var joined int
	if err := db.Get(&joined, `
		SELECT COUNT(*) FROM tlsrpt_policies p
		  JOIN tlsrpt_policy_mx m ON m.policy_id = p.id
		  JOIN tlsrpt_failures f ON f.policy_id = p.id
		 WHERE p.tlsrpt_report_id = ? AND m.mx_pattern = f.receiving_mx_hostname`, id); err != nil {
		t.Fatal(err)
	}
	if joined != 0 {
		t.Errorf("equality join matched %d row(s); the reported host is covered by the pattern but never equal to it", joined)
	}

	var patterns []string
	if err := db.Select(&patterns, `
		SELECT m.mx_pattern FROM tlsrpt_policy_mx m
		  JOIN tlsrpt_policies p ON p.id = m.policy_id
		 WHERE p.tlsrpt_report_id = ? ORDER BY m.mx_index`, id); err != nil {
		t.Fatal(err)
	}
	if len(patterns) != 2 {
		t.Fatalf("stored mx patterns = %v, want both entries as separate rows", patterns)
	}

	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.mail.example.com", "mx3.mail.example.com", true},
		{"*.mail.example.com", "mail.example.com", false},
		{"*.mail.example.com", "a.b.mail.example.com", false}, // one label only
		{"mx-backup.example.com", "mx-backup.example.com", true},
		{"mx-backup.example.com", "mx3.mail.example.com", false},
		{"mail.*.example.com", "mail.eu.example.com", false}, // wildcard is leftmost-only
	}
	for _, tc := range cases {
		if got := TLSMXPatternMatches(tc.pattern, tc.host); got != tc.want {
			t.Errorf("TLSMXPatternMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

// A retried report is an ordinary duplicate; the same report-id arriving with
// a different window means a window is being dropped and is counted apart.
func TestDuplicateReportIDWithDifferentRange(t *testing.T) {
	db := openTestDB(t)
	report, raw := loadTLSFixture(t, "appendix-b.json")
	meta := TLSRPTMeta{Transport: TransportSMTP, DKIMStatus: string(dkimcheck.StatusValid)}

	if _, err := SaveTLSRPTWithMeta(db, report, meta, "a.json", raw); err != nil {
		t.Fatalf("first import: %v", err)
	}
	if _, err := SaveTLSRPTWithMeta(db, report, meta, "a.json", raw); !errors.Is(err, ErrDuplicate) {
		t.Errorf("retry error = %v, want ErrDuplicate", err)
	}

	shifted, rawShifted := loadTLSFixture(t, "appendix-b.json")
	shifted.DateRange.Start = shifted.DateRange.Start.AddDate(0, 0, 1)
	shifted.DateRange.End = shifted.DateRange.End.AddDate(0, 0, 1)
	err := func() error {
		_, err := SaveTLSRPTWithMeta(db, shifted, meta, "b.json", rawShifted)
		return err
	}()
	if !errors.Is(err, ErrDuplicateRange) {
		t.Errorf("reused id with new window = %v, want ErrDuplicateRange", err)
	}
}

// The DKIM requirement applies to mailed reports only. Gating on status alone
// would silently drop every manually uploaded report from the metrics.
func TestTLSRPTCountedGate(t *testing.T) {
	cases := []struct {
		transport, status string
		require, want     bool
	}{
		{TransportSMTP, "valid", true, true},
		{TransportSMTP, "absent", true, false},
		{TransportSMTP, "l_tag_present", true, false},
		{TransportSMTP, "unknown", true, false},
		{TransportSMTP, "absent", false, true},
		{TransportUpload, "not_applicable", true, true},
		{TransportUpload, "absent", true, true},
		{"", "unknown", true, true}, // imported before the column existed
	}
	for _, tc := range cases {
		if got := TLSRPTCounted(tc.transport, tc.status, tc.require); got != tc.want {
			t.Errorf("TLSRPTCounted(%q, %q, require=%v) = %v, want %v",
				tc.transport, tc.status, tc.require, got, tc.want)
		}
	}
}

// The remaining fixtures cover report shapes that must survive import intact.
func TestSaveTLSRPTFixtureShapes(t *testing.T) {
	t.Run("no-policy-found is a policy type, not an error", func(t *testing.T) {
		db := openTestDB(t)
		id := saveTLSFixture(t, db, "no-policy-found.json", "nopolicy.json")
		p, err := ListTLSRPTPolicies(db, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(p) != 1 || p[0].PolicyType != "no-policy-found" {
			t.Fatalf("policies = %+v", p)
		}
		if p[0].STSMode != "" || p[0].STSMaxAge != 0 {
			t.Errorf("non-STS policy should have no STS fields: %+v", p[0])
		}
	})

	t.Run("a TLSA RRset keeps both records", func(t *testing.T) {
		db := openTestDB(t)
		id := saveTLSFixture(t, db, "tlsa-two-records.json", "dane.json")
		p, err := ListTLSRPTPolicies(db, id)
		if err != nil {
			t.Fatal(err)
		}
		var lines []string
		if err := json.Unmarshal([]byte(p[0].PolicyString), &lines); err != nil {
			t.Fatal(err)
		}
		if len(lines) != 2 {
			t.Errorf("policy string lines = %v, want the full 2-record RRset", lines)
		}
	})

	t.Run("an unregistered result type is kept and counted", func(t *testing.T) {
		db := openTestDB(t)
		id := saveTLSFixture(t, db, "unknown-result-type.json", "future.json")
		if got := getTLSReport(t, db, id).UnknownResultTypes; got != 1 {
			t.Errorf("unknown result types = %d, want 1", got)
		}
		p, _ := ListTLSRPTPolicies(db, id)
		f, err := ListTLSRPTFailures(db, p[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(f) != 1 || f[0].ResultType != "quantum-handshake-refused" {
			t.Errorf("unregistered result type was not stored verbatim: %+v", f)
		}
	})

	t.Run("missing optional fields import cleanly", func(t *testing.T) {
		db := openTestDB(t)
		id := saveTLSFixture(t, db, "missing-optional-fields.json", "sparse.json")
		r := getTLSReport(t, db, id)
		if r.ContactInfo != "" || r.TotalFailure != 2 {
			t.Errorf("report = %+v", r)
		}
		p, _ := ListTLSRPTPolicies(db, id)
		f, err := ListTLSRPTFailures(db, p[0].ID)
		if err != nil {
			t.Fatal(err)
		}
		if f[0].SendingMTAIP.Valid || f[0].ReceivingMXHostname != "" {
			t.Errorf("unspecified fields should be empty/NULL, got %+v", f[0])
		}
		if r.MalformedIPs != 0 {
			t.Errorf("an absent IP is not a malformed one (count = %d)", r.MalformedIPs)
		}
	})

	t.Run("a multi-day window is stored as sent", func(t *testing.T) {
		db := openTestDB(t)
		id := saveTLSFixture(t, db, "multi-day-range.json", "window.json")
		r := getTLSReport(t, db, id)
		if r.DateRangeEnd-r.DateRangeBegin < 2*86400 {
			t.Errorf("window = %d seconds, want the full multi-day range", r.DateRangeEnd-r.DateRangeBegin)
		}
	})
}

// Reports imported before the extension gain their policy and failure rows
// from the JSON that was kept with them.
func TestBackfillTLSRPT(t *testing.T) {
	db := openTestDB(t)
	report, raw := loadTLSFixture(t, "multi-policy-same-domain.json")

	// A row as the previous version stored it: summary counts and raw JSON,
	// no children, no transport or DKIM columns.
	res, err := db.Exec(`
		INSERT INTO tlsrpt_reports
			(org_name, report_id, contact_info, date_range_begin, date_range_end,
			 policy_domains, total_success, total_failure, raw_json, imported_at, source_filename)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		report.OrganizationName, report.ReportID, report.ContactInfo,
		report.DateRange.Start.Unix(), report.DateRange.End.Unix(),
		"example.com", 1800, 18, string(raw), 0, "legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	out, err := BackfillTLSRPT(db)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if out.Reports != 1 || out.MultiPolicy != 1 || out.Failed != 0 {
		t.Errorf("backfill result = %+v, want 1 report, 1 multi-policy, 0 failed", out)
	}

	policies, err := ListTLSRPTPolicies(db, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies after backfill = %d, want 2", len(policies))
	}
	r := getTLSReport(t, db, id)
	if r.MultiPolicy != 1 {
		t.Error("backfilled report should carry the multi-policy flag")
	}
	// The stored summary is left alone; only the rollup view differs.
	if r.TotalSuccess != 1800 {
		t.Errorf("stored total_success = %d, want the original 1800 left untouched", r.TotalSuccess)
	}
	totals, err := TLSSessionTotals(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Success != 900 {
		t.Errorf("rolled-up successes = %d, want 900", totals.Success)
	}

	// A second run finds nothing left to do.
	again, err := BackfillTLSRPT(db)
	if err != nil {
		t.Fatal(err)
	}
	if again.Reports != 0 {
		t.Errorf("second backfill touched %d report(s), want 0", again.Reports)
	}
}
