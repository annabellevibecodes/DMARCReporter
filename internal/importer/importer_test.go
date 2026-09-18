package importer

import (
	"testing"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

const dmarcXML = `<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <report_id>imp-1</report_id>
    <date_range><begin>1754006400</begin><end>1754092799</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record>
    <row><source_ip>192.0.2.10</source_ip><count>4</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><dkim><domain>example.com</domain><selector>s1</selector><result>pass</result></dkim></auth_results>
  </record>
</feedback>`

const tlsJSON = `{"organization-name":"Google Inc.","date-range":{"start-datetime":"2026-08-01T00:00:00Z","end-datetime":"2026-08-01T23:59:59Z"},"report-id":"tls-1","policies":[{"policy":{"policy-type":"sts","policy-domain":"example.com"},"summary":{"total-successful-session-count":1,"total-failure-session-count":0}}]}`

func TestSaveAttachmentsRecordsEvents(t *testing.T) {
	db, err := database.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	atts := []Attachment{
		{Filename: "google.com!example.com!1!2.xml", Data: []byte(dmarcXML), ReceivedAt: 1754100000},
		{Filename: "google.com!example.com!1!2.xml", Data: []byte(dmarcXML)}, // duplicate
		{Filename: "broken.xml", Data: []byte("<feedback><report_metadata></report_metadata></feedback>")},
		{Filename: "tls.json", Data: []byte(tlsJSON)},
		{Filename: "tls.json", Data: []byte(tlsJSON)}, // duplicate
	}
	res, err := SaveAttachments(db, database.IngestSourceUpload, "", atts)
	if err != nil {
		t.Fatalf("SaveAttachments: %v", err)
	}
	if res.Imported != 2 || res.Duplicates != 2 || res.Failed != 1 || res.LastReportID == 0 {
		t.Errorf("result = %+v", res)
	}

	counts, err := database.CountIngestEvents(db, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, c := range counts {
		got[c.Status+"/"+c.Kind] += c.Count
	}
	want := map[string]int64{
		"ok/dmarc": 1, "duplicate/dmarc": 1, "parse_error/dmarc": 1,
		"ok/tlsrpt": 1, "duplicate/tlsrpt": 1,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("events[%s] = %d, want %d (all: %v)", k, got[k], v, got)
		}
	}

	// received_at is persisted from the attachment.
	r, err := database.GetReport(db, res.LastReportID)
	if err != nil || r == nil {
		t.Fatalf("GetReport: %v", err)
	}
	if r.ReceivedAt != 1754100000 {
		t.Errorf("received_at = %d", r.ReceivedAt)
	}

	dups, err := database.ListIngestEvents(db, database.IngestStatusDuplicate, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(dups) != 2 || dups[0].OrgName == "" {
		t.Errorf("duplicate events = %+v", dups)
	}
}
