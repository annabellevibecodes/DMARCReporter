package parser

import (
	"bytes"
	_ "embed"
	"os"
	"testing"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

func parseBIMIFixture(t *testing.T, name string) *models.Feedback {
	t.Helper()
	raw, err := os.ReadFile("testdata/bimi/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	fb, err := ParseXML(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return fb
}

// The reporting draft's own example report must parse — including the two
// defects it ships with: a date range of "1609459200M" and a stray "?" after
// </sp>. Refusing it would mean refusing the only sample report in existence.
func TestParseAppendixA(t *testing.T) {
	fb := parseBIMIFixture(t, "appendix_a.xml")

	if got := fb.ReportMetadata.DateRange.Begin; got != 1609459200 {
		t.Errorf("begin = %d, want the digits salvaged from 1609459200M", got)
	}
	if got := fb.ReportMetadata.DateRange.End; got != 1609545599 {
		t.Errorf("end = %d", got)
	}
	if fb.BIMIHygiene.MalformedFields != 1 {
		t.Errorf("malformed fields = %d, want the salvaged date counted", fb.BIMIHygiene.MalformedFields)
	}
	// The stray "?" is character data in policy_published and must not
	// disturb the policy itself.
	if fb.PolicyPublished.Policy != "reject" || fb.PolicyPublished.SubdomainPolicy != "reject" {
		t.Errorf("policy = %q/%q", fb.PolicyPublished.Policy, fb.PolicyPublished.SubdomainPolicy)
	}
	if len(fb.Records) != 1 || fb.Records[0].Row.Count != 10 {
		t.Errorf("records = %+v", fb.Records)
	}

	if fb.BIMI == nil {
		t.Fatal("no <bimi> element parsed")
	}
	if fb.BIMIHygiene.Present != 1 {
		t.Error("the report carries BIMI data and must be counted as covering it")
	}
	if len(fb.BIMI.Domains) != 1 {
		t.Fatalf("domains = %d", len(fb.BIMI.Domains))
	}
	d := fb.BIMI.Domains[0]
	if d.Aligned != "sender.tld" || d.Assertion != "sender.tld" {
		t.Errorf("domain = %q/%q", d.Aligned, d.Assertion)
	}
	if len(d.Assertions) != 1 {
		t.Fatalf("assertions = %d", len(d.Assertions))
	}
	a := d.Assertions[0]
	if a.Selector != "default" || a.L != "https://www.sender.tld/images/logos/bimi.svg" {
		t.Errorf("assertion = %q / %q", a.Selector, a.L)
	}
	// a="" is present and empty: the domain publishes no evidence document.
	if !a.APresent || a.A != "" {
		t.Errorf("a = %q present=%v, want present and empty", a.A, a.APresent)
	}
	if a.Evidence == nil {
		t.Error("the empty <evidence /> element must still be recorded as present")
	}
	if a.Errors == nil || len(a.Errors.Entries) != 1 {
		t.Fatalf("errors = %+v", a.Errors)
	}
	e := a.Errors.Entries[0]
	if e.Element != "indicator" || e.Class != "temp" || e.Type != "retrieval" || e.Count != 1 {
		t.Errorf("error = %+v", e)
	}
	if e.Description != "DNS RCODE:3" {
		t.Errorf("description = %q", e.Description)
	}
	// Nothing in this report breaks a rule beyond its date range.
	if h := fb.BIMIHygiene; h.DupTuples != 0 || h.BadCounts != 0 || h.UnknownTypes != 0 || h.MissingAttrs != 0 {
		t.Errorf("hygiene = %+v, want only the malformed date", h)
	}
}

// Invariant 3: <assertion> and <evidence> name both structural elements and
// error elements. A parser that confuses them double-counts, and does so
// silently — so this asserts both directions.
func TestBIMIDualRoleElementNames(t *testing.T) {
	fb := parseBIMIFixture(t, "dual_role.xml")
	a := fb.BIMI.Domains[0].Assertions[0]

	// The structural <evidence> element was read as metadata, not as an error.
	if a.Evidence == nil {
		t.Fatal("the structural <evidence> element was not parsed")
	}
	if a.Evidence.Issuer != "Test MVA" || a.Evidence.Type != "VMC" {
		t.Errorf("evidence = %+v", a.Evidence)
	}
	if a.Evidence.URL != "https://sender.tld/vmc.pem" {
		t.Errorf("evidence url = %q", a.Evidence.URL)
	}

	// And the four error elements were read as errors, once each.
	if a.Errors == nil || len(a.Errors.Entries) != 4 {
		t.Fatalf("errors = %d, want exactly four", len(a.Errors.Entries))
	}
	want := map[string]int64{"assertion": 3, "evidence": 5, "indicator": 7, "undefined": 11}
	for _, e := range a.Errors.Entries {
		if want[e.Element] != e.Count {
			t.Errorf("%s error count = %d, want %d", e.Element, e.Count, want[e.Element])
		}
		delete(want, e.Element)
	}
	if len(want) != 0 {
		t.Errorf("error elements not seen: %v", want)
	}

	// The <evidence> *error* must not have overwritten the evidence metadata,
	// and the <assertion> error must not have become another assertion.
	if len(fb.BIMI.Domains[0].Assertions) != 1 {
		t.Errorf("assertions = %d, want the <assertion> error not counted as one",
			len(fb.BIMI.Domains[0].Assertions))
	}
	if fb.BIMIHygiene.UnknownTypes != 0 || fb.BIMIHygiene.DupTuples != 0 {
		t.Errorf("hygiene = %+v, want a clean report", fb.BIMIHygiene)
	}
}

// §3.3: the evidence date is an RFC 5322 date, which is the format mail
// headers use — not ISO 8601.
func TestBIMIEvidenceDateIsRFC5322(t *testing.T) {
	fb := parseBIMIFixture(t, "dual_role.xml")
	ev := fb.BIMI.Domains[0].Assertions[0].Evidence
	want := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC).Unix()
	if ev.ParsedDate != want {
		t.Errorf("parsed date = %d, want %d", ev.ParsedDate, want)
	}
	if ev.DateMalformed {
		t.Error("a valid RFC 5322 date was reported as malformed")
	}

	// An ISO 8601 date is exactly the mistake the draft invites, so it is
	// counted rather than guessed at — and the text is kept.
	other := parseBIMIFixture(t, "hygiene.xml")
	iso := other.BIMI.Domains[0].Assertions[0].Evidence
	if !iso.DateMalformed || iso.ParsedDate != 0 {
		t.Errorf("iso date = %+v, want it recorded as unreadable", iso)
	}
	if iso.Date != "2026-01-02T15:04:05Z" {
		t.Errorf("raw date text was lost: %q", iso.Date)
	}
}

// Every hygiene counter has its own fixture case, because a counter that is
// never incremented is indistinguishable from a healthy corpus.
func TestBIMIHygieneCounters(t *testing.T) {
	fb := parseBIMIFixture(t, "hygiene.xml")
	h := fb.BIMIHygiene

	// Duplicates: the repeated indicator temp:retrieval tuple, the repeated
	// selector:l:a assertion, and the repeated aligned:assertion domain.
	if h.DupTuples != 3 {
		t.Errorf("duplicate tuples = %d, want 3 (error tuple, assertion, domain)", h.DupTuples)
	}
	// Bad counts: a zero, and a count that is not a number at all.
	if h.BadCounts != 2 {
		t.Errorf("bad counts = %d, want 2 (a zero and a non-number)", h.BadCounts)
	}
	// Unknown vocabulary: an unregistered type, an unregistered class, an
	// unregistered element name, and the missing class (which is not in the
	// registry either).
	if h.UnknownTypes != 4 {
		t.Errorf("unknown types = %d, want 4", h.UnknownTypes)
	}
	// Missing attributes: one <indicator> with no class, an <assertion> with
	// no selector and no a=, and a <domain> with neither attribute.
	if h.MissingAttrs != 5 {
		t.Errorf("missing attrs = %d, want 5", h.MissingAttrs)
	}
	// The ISO 8601 evidence date.
	if h.MalformedFields != 1 {
		t.Errorf("malformed fields = %d, want 1", h.MalformedFields)
	}
	if h.Empty() {
		t.Error("a report this broken must not report clean hygiene")
	}

	// Nothing was dropped: every domain and assertion is still there to look
	// at, because a report that breaks a rule is still evidence.
	if len(fb.BIMI.Domains) != 3 {
		t.Errorf("domains = %d, want all three kept", len(fb.BIMI.Domains))
	}
	// A count that would not parse becomes zero rather than a guess.
	for _, e := range fb.BIMI.Domains[0].Assertions[0].Errors.Entries {
		if e.Raw == "not a number" && e.Count != 0 {
			t.Errorf("unparseable count became %d", e.Count)
		}
		if e.Count < 0 {
			t.Errorf("negative count stored: %+v", e)
		}
	}
}

// A report with no <bimi> element must not be counted as covering BIMI — B18
// divides by exactly this.
func TestReportWithoutBIMIIsNotCounted(t *testing.T) {
	fb, err := ParseXML(bytes.NewReader([]byte(`<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>x</org_name><report_id>r</report_id>
  <date_range><begin>1609459200</begin><end>1609545599</end></date_range></report_metadata>
  <policy_published><domain>sender.tld</domain><p>none</p></policy_published>
  <record><row><source_ip>192.0.2.1</source_ip><count>1</count>
  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
  <identifiers><header_from>sender.tld</header_from></identifiers></record>
</feedback>`)))
	if err != nil {
		t.Fatal(err)
	}
	if fb.BIMI != nil {
		t.Error("a report with no <bimi> element produced one")
	}
	if fb.BIMIHygiene.Present != 0 || !fb.BIMIHygiene.Empty() {
		t.Errorf("hygiene = %+v, want all zero", fb.BIMIHygiene)
	}
}

// The draft says <bimi> SHOULD be last but MAY be anywhere, so the parser must
// not depend on where it appears.
func TestBIMIElementOrderDoesNotMatter(t *testing.T) {
	fb, err := ParseXML(bytes.NewReader([]byte(`<?xml version="1.0"?>
<feedback>
  <report_metadata><org_name>x</org_name><report_id>r</report_id>
  <date_range><begin>1609459200</begin><end>1609545599</end></date_range></report_metadata>
  <bimi>
    <domain aligned="sender.tld" assertion="sender.tld">
      <assertion selector="default" l="unpublished" a="">
        <errors><assertion class="perm" type="retrieval">4</assertion></errors>
      </assertion>
    </domain>
  </bimi>
  <policy_published><domain>sender.tld</domain><p>reject</p></policy_published>
  <record><row><source_ip>192.0.2.1</source_ip><count>1</count>
  <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
  <identifiers><header_from>sender.tld</header_from></identifiers></record>
</feedback>`)))
	if err != nil {
		t.Fatal(err)
	}
	if fb.BIMI == nil || len(fb.BIMI.Domains) != 1 {
		t.Fatalf("bimi = %+v", fb.BIMI)
	}
	if fb.PolicyPublished.Policy != "reject" || len(fb.Records) != 1 {
		t.Errorf("the elements after <bimi> were not parsed: %+v", fb.PolicyPublished)
	}
	// "unpublished" is a magic value, not a URI.
	if got := fb.BIMI.Domains[0].Assertions[0].L; got != models.Unpublished {
		t.Errorf("l = %q, want the magic value preserved", got)
	}
}
