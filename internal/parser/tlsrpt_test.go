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
