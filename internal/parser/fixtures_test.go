package parser

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// fixtureDMARCbisXML mirrors a real GMX report: RFC 9990 namespace,
// discovery_method, testing, no pct/fo, version 1.0.
const fixtureDMARCbisXML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">
   <version>1.0</version>
   <report_metadata>
      <org_name>GMX</org_name>
      <email>noreply-dmarc@sicher.gmx.net</email>
      <extra_contact_info>https://postmaster.gmx.net/en/case?c=r2002</extra_contact_info>
      <report_id>04508b973d4643539e632d55e055560f</report_id>
      <date_range><begin>1780358400</begin><end>1780444799</end></date_range>
   </report_metadata>
   <policy_published>
      <domain>example.com</domain>
      <discovery_method>psl</discovery_method>
      <adkim>r</adkim>
      <aspf>r</aspf>
      <p>reject</p>
      <sp>none</sp>
      <testing>n</testing>
   </policy_published>
   <record>
      <row>
         <source_ip>52.101.188.141</source_ip>
         <count>1</count>
         <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
      </row>
      <identifiers>
         <envelope_from>example.com</envelope_from>
         <header_from>example.com</header_from>
      </identifiers>
      <auth_results>
         <dkim><domain>example.com</domain><selector>selector1</selector><result>pass</result></dkim>
         <spf><domain>example.com</domain><scope>mfrom</scope><result>pass</result></spf>
      </auth_results>
   </record>
</feedback>`

// fixtureNPXML mirrors a Google report carrying np, discovery_method and testing.
const fixtureNPXML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>np-1</report_id>
    <date_range><begin>1754006400</begin><end>1754092799</end></date_range>
    <error>one lookup failed</error>
    <error>another</error>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>reject</sp>
    <np>reject</np>
    <pct>50</pct>
    <fo>1</fo>
    <discovery_method>treewalk</discovery_method>
    <testing>y</testing>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>3</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>fail</result></spf></auth_results>
  </record>
</feedback>`

// fixtureNullSenderXML has envelope_from = <> and a local_policy override with
// an arc=fail comment, as seen from Outlook/Google.
const fixtureNullSenderXML = `<?xml version="1.0"?>
<feedback xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <version>1.0</version>
  <report_metadata>
    <org_name>Enterprise Outlook</org_name>
    <email>dmarcreport@microsoft.com</email>
    <report_id>null-1</report_id>
    <date_range><begin>1784505600</begin><end>1784592000</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
    <fo>1</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>85.195.224.148</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>fail</spf>
        <reason><type>local_policy</type><comment>arc=fail</comment></reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>umbrella22.ch</envelope_to>
      <envelope_from>&lt;&gt;</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><selector>selector1</selector><result>pass</result></dkim>
      <spf><domain>example.com</domain><scope>helo</scope><result>none</result></spf>
    </auth_results>
  </record>
</feedback>`

// fixtureVersion01XML mirrors the Mimecast-style report with a padded 0.1 version.
const fixtureVersion01XML = `<?xml version="1.0" encoding="UTF-8"?>
<feedback>
	<version>0.1
	</version>
	<report_metadata>
		<org_name>Mimecast</org_name>
		<email>dmarc@mimecast.com</email>
		<report_id>v01-1</report_id>
		<date_range><begin>1754006400</begin><end>1754092799</end></date_range>
	</report_metadata>
	<policy_published>
		<domain>example.com</domain>
		<adkim>r</adkim>
		<aspf>r</aspf>
		<p>none</p>
	</policy_published>
	<record>
		<row><source_ip>198.51.100.7</source_ip><count>12</count>
			<policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
		</row>
		<identifiers><header_from>example.com</header_from></identifiers>
		<auth_results><spf><domain>other.example</domain><result>pass</result></spf></auth_results>
	</record>
</feedback>`

const fixtureTLSRPTJSON = `{
  "organization-name": "Google Inc.",
  "date-range": {"start-datetime": "2026-08-01T00:00:00Z", "end-datetime": "2026-08-01T23:59:59Z"},
  "contact-info": "smtp-tls-reporting@google.com",
  "report-id": "2026-08-01T00:00:00Z_example.com",
  "policies": [{
    "policy": {"policy-type": "sts", "policy-domain": "example.com"},
    "summary": {"total-successful-session-count": 10, "total-failure-session-count": 1}
  }]
}`

// buildEML assembles a minimal multipart message with one base64 attachment.
func buildEML(filename, contentType string, data []byte) []byte {
	var b strings.Builder
	b.WriteString("From: reporter@example.net\r\n")
	b.WriteString("To: dmarc@example.com\r\n")
	b.WriteString("Date: Mon, 03 Aug 2026 02:15:00 +0000\r\n")
	b.WriteString("Subject: Report\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n\r\n")
	b.WriteString("--XYZ\r\nContent-Type: text/plain\r\n\r\nSee attachment.\r\n")
	fmt.Fprintf(&b, "--XYZ\r\nContent-Type: %s; name=\"%s\"\r\n", contentType, filename)
	fmt.Fprintf(&b, "Content-Disposition: attachment; filename=\"%s\"\r\n", filename)
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(base64.StdEncoding.EncodeToString(data))
	b.WriteString("\r\n--XYZ--\r\n")
	return []byte(b.String())
}

func TestParseDMARCbisNamespace(t *testing.T) {
	fb, _, err := Parse("gmx.xml", strings.NewReader(fixtureDMARCbisXML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := fb.Namespace(); got != "urn:ietf:params:xml:ns:dmarc-2.0" {
		t.Errorf("namespace = %q", got)
	}
	if fb.VersionText() != "1.0" {
		t.Errorf("version = %q", fb.VersionText())
	}
	pp := fb.PolicyPublished
	if pp.DiscoveryMethod != "psl" || pp.Testing != "n" || pp.Policy != "reject" {
		t.Errorf("policy_published = %+v", pp)
	}
	if !pp.SPPresent || pp.SubdomainPolicy != "none" {
		t.Errorf("sp: present=%v value=%q, want present 'none'", pp.SPPresent, pp.SubdomainPolicy)
	}
	if pp.PctPresent || pp.Pct != 100 {
		t.Errorf("pct: present=%v value=%d, want absent -> 100", pp.PctPresent, pp.Pct)
	}
	if pp.FOPresent || pp.FailureOptions != "0" {
		t.Errorf("fo: present=%v value=%q, want absent -> '0'", pp.FOPresent, pp.FailureOptions)
	}
	if len(fb.Records) != 1 || fb.Records[0].AuthResults.DKIM[0].Selector != "selector1" {
		t.Errorf("records = %+v", fb.Records)
	}
}

func TestParseNPDiscoveryTestingAndErrors(t *testing.T) {
	fb, _, err := Parse("np.xml", strings.NewReader(fixtureNPXML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	pp := fb.PolicyPublished
	if pp.NP != "reject" || pp.DiscoveryMethod != "treewalk" || pp.Testing != "y" {
		t.Errorf("np/discovery/testing = %q/%q/%q", pp.NP, pp.DiscoveryMethod, pp.Testing)
	}
	if !pp.PctPresent || pp.Pct != 50 || !pp.FOPresent || pp.FailureOptions != "1" || !pp.SPPresent || pp.SubdomainPolicy != "reject" {
		t.Errorf("optional tags = %+v", pp)
	}
	if len(fb.ReportMetadata.Errors) != 2 {
		t.Errorf("errors = %v, want 2", fb.ReportMetadata.Errors)
	}
}

func TestParseReasonAndNullSender(t *testing.T) {
	fb, _, err := Parse("outlook.xml", strings.NewReader(fixtureNullSenderXML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rec := fb.Records[0]
	if rec.Identifiers.EnvelopeFrom != "<>" {
		t.Errorf("envelope_from = %q, want <>", rec.Identifiers.EnvelopeFrom)
	}
	if len(rec.Row.PolicyEvaluated.Reasons) != 1 {
		t.Fatalf("reasons = %+v", rec.Row.PolicyEvaluated.Reasons)
	}
	r := rec.Row.PolicyEvaluated.Reasons[0]
	if r.Type != "local_policy" || r.Comment != "arc=fail" {
		t.Errorf("reason = %+v", r)
	}
	if rec.AuthResults.SPF[0].Scope != "helo" {
		t.Errorf("spf scope = %q", rec.AuthResults.SPF[0].Scope)
	}
}

func TestParseVersion01Padded(t *testing.T) {
	fb, _, err := Parse("mimecast.xml", strings.NewReader(fixtureVersion01XML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if fb.VersionText() != "0.1" {
		t.Errorf("version = %q, want 0.1", fb.VersionText())
	}
	pp := fb.PolicyPublished
	if pp.SPPresent || pp.SubdomainPolicy != "" {
		t.Errorf("sp should be absent, got present=%v %q", pp.SPPresent, pp.SubdomainPolicy)
	}
	if fb.Namespace() != "" {
		t.Errorf("namespace = %q, want empty", fb.Namespace())
	}
}

func TestExtractEMLAttachmentsTLSRPT(t *testing.T) {
	eml := buildEML("google.com!example.com!1754006400!1754092799.json", "application/tlsrpt+json", []byte(fixtureTLSRPTJSON))
	atts, date, err := ExtractEMLAttachments(eml, nil)
	if err != nil {
		t.Fatalf("ExtractEMLAttachments: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("attachments = %d, want 1", len(atts))
	}
	if !IsTLSRPTFile(atts[0].Filename) || IsDMARCFile(atts[0].Filename) {
		t.Errorf("attachment %q should route to tlsrpt", atts[0].Filename)
	}
	if date.IsZero() || atts[0].ReceivedAt != date.Unix() || date.Year() != 2026 {
		t.Errorf("date = %v received_at = %d", date, atts[0].ReceivedAt)
	}
	rep, _, err := ParseTLSRPT(atts[0].Filename, bytes.NewReader(atts[0].Data))
	if err != nil {
		t.Fatalf("ParseTLSRPT: %v", err)
	}
	if rep.ReportID == "" || rep.OrganizationName != "Google Inc." {
		t.Errorf("tlsrpt = %+v", rep)
	}
	// The DMARC-only helper must reject a TLS-RPT-only message.
	if _, _, _, err := ParseEML(bytes.NewReader(eml)); err == nil {
		t.Error("ParseEML should fail when the only attachment is a TLS-RPT report")
	}
}

func TestExtractEMLAttachmentsDMARCGzip(t *testing.T) {
	var gz bytes.Buffer
	{
		w := newGzipWriter(&gz)
		w.Write([]byte(fixtureDMARCbisXML))
		w.Close()
	}
	eml := buildEML("gmx!example.com!1780358400!1780444799.xml.gz", "application/gzip", gz.Bytes())
	atts, _, err := ExtractEMLAttachments(eml, nil)
	if err != nil || len(atts) != 1 {
		t.Fatalf("atts=%d err=%v", len(atts), err)
	}
	fb, _, err := Parse(atts[0].Filename, bytes.NewReader(atts[0].Data))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if fb.ReportMetadata.OrgName != "GMX" {
		t.Errorf("org = %q", fb.ReportMetadata.OrgName)
	}
	fbs, _, _, err := ParseEML(bytes.NewReader(eml))
	if err != nil || len(fbs) != 1 {
		t.Errorf("ParseEML: n=%d err=%v", len(fbs), err)
	}
}

func newGzipWriter(w *bytes.Buffer) interface {
	Write([]byte) (int, error)
	Close() error
} {
	return gzip.NewWriter(w)
}
