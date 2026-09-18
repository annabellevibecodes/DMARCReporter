package export

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// tlsReportData builds a ReportData with a populated TLS section.
func tlsReportData() *ReportData {
	rd := &ReportData{
		GeneratedAt: time.Now().UTC(),
		Domain:      "example.com",
		PeriodLabel: "30 Days",
		TLSRate:     &database.TLSRate{Success: 900, Failure: 100, Total: 1000, Rate: 90},
		TLSPrevRate: &database.TLSRate{Success: 980, Failure: 20, Total: 1000, Rate: 98},
		TLSPolicyMix: &database.TLSPolicyMix{Overall: []database.TLSPolicyTypeRow{
			{PolicyType: "sts", Sessions: 900, Share: 90},
			{PolicyType: "no-policy-found", Sessions: 100, Share: 10},
		}},
		TLSFailures: &database.TLSFailureBreakdown{
			Types: []database.TLSResultTypeRow{
				{ResultType: "certificate-expired", Group: "negotiation", FailedSessions: 80, Share: 80},
				{ResultType: "sts-policy-fetch-error", Group: "mta-sts", FailedSessions: 20, Share: 20},
			},
			Total: 100,
		},
		TLSReceivers: &database.TLSReceivers{ByHost: []database.TLSReceiverRow{
			{MXHostname: "mx1.example.com", DistinctIPs: 2, FailedSessions: 80, ResultTypes: "certificate-expired"},
		}},
		TLSReadiness: &database.TLSEnforcementReadiness{
			TestingSessions: 900, TestingFailures: 100, WouldBlock: 100,
		},
		TLSHygiene: &database.TLSHygiene{Reports: 12, Excluded: 2},
		TLSAlerts: []database.Alert{
			{Rule: "tls_cert_expired", Severity: "critical", Domain: "example.com",
				Message: "Reporter saw an expired certificate on mx1.example.com"},
		},
	}
	return rd
}

// Every format carries the TLS section, with the figures the brief asked for.
func TestTLSSectionInEveryFormat(t *testing.T) {
	rd := tlsReportData()

	t.Run("csv", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteCSV(&buf, rd); err != nil {
			t.Fatal(err)
		}
		assertTLSContent(t, buf.String())
	})

	t.Run("docx", func(t *testing.T) {
		body := buildDocxBody(rd, "Test Report")
		assertTLSContent(t, body)
	})

	t.Run("pdf", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WritePDF(&buf, rd); err != nil {
			t.Fatal(err)
		}
		if buf.Len() == 0 {
			t.Fatal("empty PDF")
		}
		// A PDF's text is compressed, so only the render succeeding is
		// checked here; the shared row builders are asserted above.
	})

	t.Run("xlsx", func(t *testing.T) {
		var buf bytes.Buffer
		if err := WriteXLSX(&buf, rd); err != nil {
			t.Fatal(err)
		}
		if buf.Len() == 0 {
			t.Fatal("empty XLSX")
		}
	})
}

func assertTLSContent(t *testing.T, out string) {
	t.Helper()
	for _, want := range []string{
		"SMTP TLS Reporting",      // section
		"90.0%",                   // T1 rate
		"-8.0 points",             // T1 delta
		"no-policy-found",         // T3
		"certificate-expired",     // T4
		"mx1.example.com",         // T5
		"would have been blocked", // T9
		"tls_cert_expired",        // open TLS alerts
		"Reports excluded",        // hygiene: what was held back
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q", want)
		}
	}
}

// A period with no TLS reports says so, rather than printing zeros that read
// as "every session failed".
func TestTLSSectionEmptyState(t *testing.T) {
	rd := &ReportData{GeneratedAt: time.Now().UTC(), PeriodLabel: "30 Days"}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, rd); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "No TLS reports for this period") {
		t.Errorf("CSV should state the absence plainly:\n%s", out)
	}
	if strings.Contains(out, "0.0%") && strings.Contains(out, "TLS success rate") {
		t.Error("an absent rate must not be rendered as 0.0%")
	}

	if body := buildDocxBody(rd, "Test Report"); !strings.Contains(body, "No TLS reports for this period") {
		t.Error("DOCX should state the absence plainly")
	}
}

// The TLS fields are attacker-controlled free text: anyone who can mail a
// report chooses org_name, failure_reason_code, additional_information and
// the result type. A value starting with a formula trigger must not reach a
// spreadsheet unescaped (CWE-1236).
func TestTLSFieldsAreFormulaEscaped(t *testing.T) {
	rd := tlsReportData()
	rd.TLSFailures.Types = []database.TLSResultTypeRow{
		{ResultType: "=cmd|'/c calc'!A1", Group: "unregistered", FailedSessions: 5, Share: 5},
	}
	rd.TLSReceivers.ByHost = []database.TLSReceiverRow{
		{MXHostname: "+mx.evil.example", DistinctIPs: 1, FailedSessions: 5,
			ResultTypes: "@SUM(1+1)*cmd"},
	}
	rd.TLSPolicyMix.Overall = []database.TLSPolicyTypeRow{
		{PolicyType: "-sts", Sessions: 5, Share: 5},
	}
	rd.TLSAlerts = []database.Alert{
		{Rule: "tls_cert_expired", Severity: "critical", Domain: "example.com",
			Message: "=HYPERLINK(\"http://evil.example\")"},
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, rd); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, dangerous := range []string{
		"\n=cmd|", ",=cmd|",
		"\n+mx.evil", ",+mx.evil",
		"\n@SUM", ",@SUM",
		"\n-sts", ",-sts",
		"\n=HYPERLINK", ",=HYPERLINK",
	} {
		if strings.Contains(out, dangerous) {
			t.Errorf("unescaped formula reached the CSV: %q", dangerous)
		}
	}
	// And the values are still present, quoted, rather than dropped.
	for _, want := range []string{"'=cmd|", "'+mx.evil.example", "'@SUM(1+1)*cmd", "'-sts", "'=HYPERLINK"} {
		if !strings.Contains(out, want) {
			t.Errorf("escaped value missing from the CSV: %q", want)
		}
	}
}

// The row builders escape on their own, so every format that uses them is
// covered rather than only the one with a test.
func TestTLSRowBuildersEscape(t *testing.T) {
	rd := tlsReportData()
	rd.TLSFailures.Types = []database.TLSResultTypeRow{{ResultType: "=evil", Group: "@group"}}
	rd.TLSReceivers.ByHost = []database.TLSReceiverRow{{MXHostname: "-host", ResultTypes: "+types"}}
	rd.TLSPolicyMix.Overall = []database.TLSPolicyTypeRow{{PolicyType: "=sts"}}
	rd.TLSAlerts = []database.Alert{{Rule: "=rule", Severity: "@sev", Domain: "-dom", Message: "+msg"}}

	for _, row := range tlsFailureRows(rd) {
		assertEscaped(t, "failure", row)
	}
	for _, row := range tlsReceiverRows(rd) {
		assertEscaped(t, "receiver", row)
	}
	for _, row := range tlsPolicyRows(rd) {
		assertEscaped(t, "policy", row)
	}
	for _, row := range tlsAlertRows(rd) {
		assertEscaped(t, "alert", row)
	}
}

func assertEscaped(t *testing.T, what string, row []string) {
	t.Helper()
	for _, cell := range row {
		if cell == "" {
			continue
		}
		switch cell[0] {
		case '=', '+', '-', '@', '\t', '\r':
			t.Errorf("%s row cell %q was not escaped", what, cell)
		}
	}
}

// The delta only appears when there is a previous window with traffic to
// compare against.
func TestTLSDelta(t *testing.T) {
	rd := tlsReportData()
	if d, ok := rd.TLSDelta(); !ok || d > -7.9 || d < -8.1 {
		t.Errorf("delta = %v, %v; want ~-8 points", d, ok)
	}

	rd.TLSPrevRate = nil
	if _, ok := rd.TLSDelta(); ok {
		t.Error("no previous window means no delta")
	}

	rd.TLSRate = nil
	if _, ok := rd.TLSDelta(); ok {
		t.Error("no current rate means no delta")
	}
}
