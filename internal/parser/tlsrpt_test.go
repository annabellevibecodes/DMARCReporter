package parser

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const tlsrptFixture = `{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "2026-08-01T00:00:00Z_example.com",
  "policies": [{
    "policy": {"policy-type": "sts", "policy-domain": "example.com"},
    "summary": {"total-successful-session-count": 230, "total-failure-session-count": 3}
  }]
}`

func TestParseTLSRPT(t *testing.T) {
	r, raw, err := ParseTLSRPT("report.json", strings.NewReader(tlsrptFixture))
	if err != nil {
		t.Fatal(err)
	}
	if r.OrganizationName != "Google Inc." || r.ReportID == "" {
		t.Errorf("parsed = %+v", r)
	}
	success, failure := r.Totals()
	if success != 230 || failure != 3 {
		t.Errorf("totals = %d/%d, want 230/3", success, failure)
	}
	if d := r.Domains(); len(d) != 1 || d[0] != "example.com" {
		t.Errorf("domains = %v", d)
	}
	if len(raw) == 0 {
		t.Error("raw JSON is empty")
	}
}

func TestParseTLSRPTGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(tlsrptFixture))
	gw.Close()
	r, _, err := ParseTLSRPT("report.json.gz", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if r.OrganizationName != "Google Inc." {
		t.Errorf("org = %q", r.OrganizationName)
	}
}

func TestParseTLSRPTRejectsMissingReportID(t *testing.T) {
	if _, _, err := ParseTLSRPT("x.json", strings.NewReader(`{"organization-name":"x"}`)); err == nil {
		t.Error("expected error for missing report-id")
	}
}

func TestIsTLSRPTFile(t *testing.T) {
	if !IsTLSRPTFile("a.json") || !IsTLSRPTFile("a.JSON.GZ") {
		t.Error("json files not recognised")
	}
	if IsTLSRPTFile("a.xml") || IsTLSRPTFile("a.gz") {
		t.Error("non-json files misrecognised")
	}
}

// RFC 8460 defines policy-string and mx-host as arrays, but reporters are
// known to send a bare string. Both spellings must land as a slice so nothing
// downstream has to care which arrived.
func TestParseTLSRPTFlexibleStringFields(t *testing.T) {
	const fixture = `{
	  "organization-name": "Reporter",
	  "date-range": {"start-datetime": "2026-09-01T00:00:00Z", "end-datetime": "2026-09-01T23:59:59Z"},
	  "report-id": "flex-1",
	  "policies": [{
	    "policy": {"policy-type": "sts", "policy-domain": "example.com",
	               "policy-string": "version: STSv1", "mx-host": "mx.example.com"},
	    "summary": {"total-successful-session-count": 1, "total-failure-session-count": 0}
	  }, {
	    "policy": {"policy-type": "sts", "policy-domain": "example.com",
	               "policy-string": ["version: STSv1", "mode: enforce"],
	               "mx-host": ["mx1.example.com", "mx2.example.com"]},
	    "summary": {"total-successful-session-count": 2, "total-failure-session-count": 0}
	  }]
	}`
	r, _, err := ParseTLSRPT("flex.json", strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Policies[0].Policy.PolicyString; len(got) != 1 || got[0] != "version: STSv1" {
		t.Errorf("string form of policy-string = %v", got)
	}
	if got := r.Policies[0].Policy.MXHost; len(got) != 1 || got[0] != "mx.example.com" {
		t.Errorf("string form of mx-host = %v", got)
	}
	if got := r.Policies[1].Policy.PolicyString; len(got) != 2 {
		t.Errorf("array form of policy-string = %v", got)
	}
	if got := r.Policies[1].Policy.MXHost; len(got) != 2 {
		t.Errorf("array form of mx-host = %v", got)
	}
}

// Absent optional fields decode as zero values, never as an error.
func TestParseTLSRPTFailureDetails(t *testing.T) {
	const fixture = `{
	  "organization-name": "Reporter",
	  "date-range": {"start-datetime": "2026-09-01T00:00:00Z", "end-datetime": "2026-09-01T23:59:59Z"},
	  "report-id": "detail-1",
	  "policies": [{
	    "policy": {"policy-type": "sts", "policy-domain": "example.com"},
	    "summary": {"total-successful-session-count": 0, "total-failure-session-count": 5},
	    "failure-details": [{
	      "result-type": "certificate-expired",
	      "sending-mta-ip": "192.0.2.1",
	      "receiving-mx-hostname": "mx.example.com",
	      "failed-session-count": 5
	    }]
	  }]
	}`
	r, _, err := ParseTLSRPT("detail.json", strings.NewReader(fixture))
	if err != nil {
		t.Fatal(err)
	}
	d := r.Policies[0].FailureDetails
	if len(d) != 1 {
		t.Fatalf("failure details = %d, want 1", len(d))
	}
	if d[0].ResultType != "certificate-expired" || d[0].FailedSessionCount != 5 {
		t.Errorf("detail = %+v", d[0])
	}
	if d[0].ReceivingIP != "" || d[0].FailureReasonCode != "" || d[0].AdditionalInformation != "" {
		t.Errorf("absent optional fields should be empty: %+v", d[0])
	}
}

// The RFC 8460 §5.3 filename carries the window, which is only ever used to
// notice a disagreement with the body — so parsing it must be exact.
func TestTLSRPTFilenameRange(t *testing.T) {
	cases := []struct {
		filename   string
		begin, end int64
		ok         bool
	}{
		{"company-x.example!company-y.example!1459468800!1459555199.json", 1459468800, 1459555199, true},
		{"company-x.example!company-y.example!1459468800!1459555199!uniq.json.gz", 1459468800, 1459555199, true},
		{"/tmp/mail/company-x!company-y!100!200!u.json", 100, 200, true},
		{"report.json", 0, 0, false},
		{"a!b!notanumber!200.json", 0, 0, false},
		{"a!b!100.json", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range cases {
		begin, end, ok := TLSRPTFilenameRange(tc.filename)
		if ok != tc.ok || begin != tc.begin || end != tc.end {
			t.Errorf("TLSRPTFilenameRange(%q) = %d, %d, %v; want %d, %d, %v",
				tc.filename, begin, end, ok, tc.begin, tc.end, tc.ok)
		}
	}
}

// The submission headers are advisory metadata: absent ones are empty, and an
// unparseable message is not an error.
func TestTLSRPTMailHeaders(t *testing.T) {
	msg := "From: r@reporter.example\r\nTLS-Report-Domain: example.com\r\n" +
		"TLS-Report-Submitter: reporter.example\r\n\r\nbody\r\n"
	domain, submitter := TLSRPTMailHeaders([]byte(msg))
	if domain != "example.com" || submitter != "reporter.example" {
		t.Errorf("headers = %q / %q", domain, submitter)
	}

	plain := "From: r@reporter.example\r\n\r\nbody\r\n"
	if d, s := TLSRPTMailHeaders([]byte(plain)); d != "" || s != "" {
		t.Errorf("absent headers = %q / %q, want empty", d, s)
	}
}
