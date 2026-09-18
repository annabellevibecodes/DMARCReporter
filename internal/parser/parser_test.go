package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

const fixtureXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range><begin>1754006400</begin><end>1754092799</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.10</source_ip>
      <count>42</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
        <reason><type>forwarded</type><comment>looks forwarded</comment></reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>gmail.com</envelope_to>
      <envelope_from>example.com</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><scope>mfrom</scope><result>softfail</result></spf>
    </auth_results>
  </record>
</feedback>`

func checkFixture(t *testing.T, filename string, data []byte) {
	t.Helper()
	fb, rawXML, err := Parse(filename, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Parse(%q): %v", filename, err)
	}
	if fb.ReportMetadata.OrgName != "google.com" {
		t.Errorf("org_name = %q, want google.com", fb.ReportMetadata.OrgName)
	}
	if fb.ReportMetadata.ReportID != "12345678901234567890" {
		t.Errorf("report_id = %q", fb.ReportMetadata.ReportID)
	}
	if fb.PolicyPublished.Domain != "example.com" || fb.PolicyPublished.Policy != "quarantine" {
		t.Errorf("policy_published = %+v", fb.PolicyPublished)
	}
	if len(fb.Records) != 1 {
		t.Fatalf("records = %d, want 1", len(fb.Records))
	}
	rec := fb.Records[0]
	if rec.Row.SourceIP != "192.0.2.10" || rec.Row.Count != 42 {
		t.Errorf("row = %+v", rec.Row)
	}
	if rec.Row.PolicyEvaluated.DKIM != "pass" || rec.Row.PolicyEvaluated.SPF != "fail" {
		t.Errorf("policy_evaluated = %+v", rec.Row.PolicyEvaluated)
	}
	if len(rec.Row.PolicyEvaluated.Reasons) != 1 || rec.Row.PolicyEvaluated.Reasons[0].Type != "forwarded" {
		t.Errorf("reasons = %+v", rec.Row.PolicyEvaluated.Reasons)
	}
	if len(rec.AuthResults.DKIM) != 1 || rec.AuthResults.DKIM[0].Selector != "s1" {
		t.Errorf("dkim auth results = %+v", rec.AuthResults.DKIM)
	}
	if !bytes.Contains(rawXML, []byte("<feedback>")) {
		t.Errorf("rawXML does not contain the decompressed report")
	}
}

func TestParsePlainXML(t *testing.T) {
	checkFixture(t, "report.xml", []byte(fixtureXML))
}

func TestParseGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(fixtureXML))
	gw.Close()
	checkFixture(t, "report.xml.gz", buf.Bytes())
}

func TestParseZip(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, err := zw.Create("report.xml")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(fixtureXML))
	zw.Close()
	checkFixture(t, "report.zip", buf.Bytes())
}

func TestParseUnknownExtensionSniffsGzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(fixtureXML))
	gw.Close()
	checkFixture(t, "google.com!example.com!1754006400!1754092799", buf.Bytes())
}

func TestParseRejectsCustomEntities(t *testing.T) {
	evil := `<?xml version="1.0"?>
<!DOCTYPE feedback [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<feedback><report_metadata><report_id>&xxe;</report_id></report_metadata></feedback>`
	if _, _, err := Parse("evil.xml", strings.NewReader(evil)); err == nil {
		t.Fatal("expected error for custom entity, got nil")
	}
}

func TestParseRejectsMissingReportID(t *testing.T) {
	xml := `<?xml version="1.0"?><feedback><report_metadata><org_name>x</org_name></report_metadata></feedback>`
	if _, _, err := Parse("r.xml", strings.NewReader(xml)); err == nil {
		t.Fatal("expected error for missing report_id, got nil")
	}
}

func TestIsDMARCFile(t *testing.T) {
	yes := []string{"a.xml", "a.XML", "a.xml.gz", "a.gz", "a.zip", "google.com!x!1!2.xml.gz"}
	no := []string{"a.pdf", "a.txt", "a.docx", "signature.asc", ""}
	for _, f := range yes {
		if !IsDMARCFile(f) {
			t.Errorf("IsDMARCFile(%q) = false, want true", f)
		}
	}
	for _, f := range no {
		if IsDMARCFile(f) {
			t.Errorf("IsDMARCFile(%q) = true, want false", f)
		}
	}
}

func TestParseXMLNormalizesRecords(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>x</org_name><report_id>r1</report_id>
    <date_range><begin>1</begin><end>2</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record><row><source_ip> 192.0.2.10 </source_ip><count>-5</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record>
  <record><row><source_ip>not-an-ip; DROP TABLE</source_ip><count>7</count>
    <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record>
  <record><row><source_ip>2001:DB8::1</source_ip><count>3</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record>
</feedback>`
	fb, err := ParseXML(strings.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(fb.Records) != 2 {
		t.Fatalf("records = %d, want 2 (invalid source_ip dropped)", len(fb.Records))
	}
	if fb.Records[0].Row.SourceIP != "192.0.2.10" || fb.Records[0].Row.Count != 0 {
		t.Errorf("record 0 = %+v, want trimmed IP and count clamped to 0", fb.Records[0].Row)
	}
	if fb.Records[1].Row.SourceIP != "2001:db8::1" {
		t.Errorf("record 1 ip = %q, want canonical IPv6", fb.Records[1].Row.SourceIP)
	}
}
