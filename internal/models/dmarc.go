package models

import (
	"encoding/xml"
	"strconv"
	"strings"
)

// NamespaceDMARCbis is the XML namespace used by DMARCbis (RFC 9990) aggregate
// reports. RFC 7489 reports carry no namespace.
const NamespaceDMARCbis = "urn:ietf:params:xml:ns:dmarc-2.0"

// Feedback is the root element of a DMARC aggregate report (RFC 7489 Appendix C,
// RFC 9990 Appendix A). Elements are matched by local name, so both the
// un-namespaced RFC 7489 form and the RFC 9990 namespaced form decode into it.
type Feedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	Version         string          `xml:"version"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []Record        `xml:"record"`
	// BIMI is the <bimi> element of draft-adams-bimi-reporting-11, a
	// top-level sibling of <record>. The draft says it SHOULD be last but MAY
	// appear anywhere, so nothing here depends on ordering.
	BIMI *BIMIReport `xml:"bimi"`
	// BIMIHygiene counts what the parser had to tolerate (B19). It is not a
	// part of the document; see parser.ParseXML.
	BIMIHygiene BIMIHygiene `xml:"-"`
}

// Namespace returns the XML namespace of the root element ("" for RFC 7489 reports).
func (f *Feedback) Namespace() string { return f.XMLName.Space }

// VersionText returns the <version> element trimmed of the whitespace some
// generators pad it with.
func (f *Feedback) VersionText() string { return strings.TrimSpace(f.Version) }

// ReportMetadata describes the report itself.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
	Generator        string    `xml:"generator"`
	Errors           []string  `xml:"error"`
}

// DateRange is a Unix timestamp pair indicating the report coverage window.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
	// Malformed counts the bounds that had to be salvaged from text that is
	// not a plain integer. See UnmarshalXML.
	Malformed int `xml:"-"`
}

// dateRangeXML mirrors the element with string fields so a malformed bound can
// be salvaged instead of failing the whole report.
type dateRangeXML struct {
	Begin string `xml:"begin"`
	End   string `xml:"end"`
}

// UnmarshalXML reads the window, tolerating trailing junk on either bound.
//
// This is the one leniency taken outside the BIMI element itself, and it is
// taken because the reporting draft's own example report carries
// "<begin>1609459200M</begin>". Refusing the document outright would throw
// away every record in it over one stray character in its metadata; salvaging
// the leading digits keeps the data and counts the leniency, which is what
// Malformed is for. A bound with no digits at all stays zero.
func (r *DateRange) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var raw dateRangeXML
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	r.Begin, r.Malformed = salvageUnix(raw.Begin, r.Malformed)
	r.End, r.Malformed = salvageUnix(raw.End, r.Malformed)
	return nil
}

// salvageUnix parses a timestamp, returning the leading integer when the text
// carries anything else and bumping the malformed count when it does.
func salvageUnix(text string, malformed int) (int64, int) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return 0, malformed
	}
	if n, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return n, malformed
	}
	end := 0
	if end < len(trimmed) && (trimmed[end] == '-' || trimmed[end] == '+') {
		end++
	}
	for end < len(trimmed) && trimmed[end] >= '0' && trimmed[end] <= '9' {
		end++
	}
	n, err := strconv.ParseInt(trimmed[:end], 10, 64)
	if err != nil {
		return 0, malformed + 1
	}
	return n, malformed + 1
}

// PolicyPublished is the DMARC policy in effect during the reporting period.
//
// SubdomainPolicy, Pct and FailureOptions are optional in the XML; the
// *Present flags record whether the element was actually supplied so that
// "absent" is distinguishable from an explicit value. When absent, Pct and
// FailureOptions hold the RFC 7489 defaults (100 and "0") and SubdomainPolicy
// is empty (the RFC default is "same as p", which the caller resolves).
type PolicyPublished struct {
	Domain          string
	ADKIM           string
	ASPF            string
	Policy          string
	SubdomainPolicy string
	SPPresent       bool
	Pct             int
	PctPresent      bool
	FailureOptions  string
	FOPresent       bool
	NP              string // RFC 9989 non-existent-subdomain policy; "" when absent
	DiscoveryMethod string // RFC 9989: "psl" or "treewalk"; "" when absent
	Testing         string // RFC 9989: "y" / "n"; "" when absent
}

// policyPublishedXML mirrors the element with pointer fields so optional
// elements can be detected as absent.
type policyPublishedXML struct {
	Domain          string  `xml:"domain"`
	ADKIM           string  `xml:"adkim"`
	ASPF            string  `xml:"aspf"`
	Policy          string  `xml:"p"`
	SubdomainPolicy *string `xml:"sp"`
	Pct             *int    `xml:"pct"`
	FailureOptions  *string `xml:"fo"`
	NP              string  `xml:"np"`
	DiscoveryMethod string  `xml:"discovery_method"`
	Testing         string  `xml:"testing"`
}

// UnmarshalXML decodes <policy_published>, recording which optional elements
// were present and substituting RFC defaults for absent ones.
func (p *PolicyPublished) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var raw policyPublishedXML
	if err := d.DecodeElement(&raw, &start); err != nil {
		return err
	}
	p.Domain = strings.TrimSpace(raw.Domain)
	p.ADKIM = strings.TrimSpace(raw.ADKIM)
	p.ASPF = strings.TrimSpace(raw.ASPF)
	p.Policy = strings.TrimSpace(raw.Policy)
	p.NP = strings.TrimSpace(raw.NP)
	p.DiscoveryMethod = strings.TrimSpace(raw.DiscoveryMethod)
	p.Testing = strings.TrimSpace(raw.Testing)

	if raw.SubdomainPolicy != nil {
		p.SPPresent = true
		p.SubdomainPolicy = strings.TrimSpace(*raw.SubdomainPolicy)
	} else {
		p.SPPresent = false
		p.SubdomainPolicy = ""
	}
	if raw.Pct != nil {
		p.PctPresent = true
		p.Pct = *raw.Pct
	} else {
		p.PctPresent = false
		p.Pct = 100
	}
	if raw.FailureOptions != nil {
		p.FOPresent = true
		p.FailureOptions = strings.TrimSpace(*raw.FailureOptions)
	} else {
		p.FOPresent = false
		p.FailureOptions = "0"
	}
	return nil
}

// MarshalXML encodes the policy back to its element form (used by tests and
// tooling; absent optional elements are omitted).
func (p PolicyPublished) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	raw := policyPublishedXML{
		Domain: p.Domain, ADKIM: p.ADKIM, ASPF: p.ASPF, Policy: p.Policy,
		NP: p.NP, DiscoveryMethod: p.DiscoveryMethod, Testing: p.Testing,
	}
	if p.SPPresent {
		sp := p.SubdomainPolicy
		raw.SubdomainPolicy = &sp
	}
	if p.PctPresent {
		pct := p.Pct
		raw.Pct = &pct
	}
	if p.FOPresent {
		fo := p.FailureOptions
		raw.FailureOptions = &fo
	}
	return e.EncodeElement(raw, start)
}

// Record is a single row of auth result data for a source IP.
type Record struct {
	Row         Row         `xml:"row"`
	Identifiers Identifiers `xml:"identifiers"`
	AuthResults AuthResults `xml:"auth_results"`
}

// Row contains the source IP, message count, and evaluated policy.
type Row struct {
	SourceIP        string          `xml:"source_ip"`
	Count           int             `xml:"count"`
	PolicyEvaluated PolicyEvaluated `xml:"policy_evaluated"`
}

// PolicyEvaluated is the DMARC disposition actually applied.
type PolicyEvaluated struct {
	Disposition string                 `xml:"disposition"`
	DKIM        string                 `xml:"dkim"`
	SPF         string                 `xml:"spf"`
	Reasons     []PolicyOverrideReason `xml:"reason"`
}

// PolicyOverrideReason explains why a policy override occurred.
type PolicyOverrideReason struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}

// Identifiers holds the RFC5321/RFC5322 identifiers observed in the messages.
type Identifiers struct {
	EnvelopeTo   string `xml:"envelope_to"`
	EnvelopeFrom string `xml:"envelope_from"`
	HeaderFrom   string `xml:"header_from"`
}

// AuthResults holds the per-record DKIM and SPF authentication outcomes.
type AuthResults struct {
	DKIM []DKIMAuthResult `xml:"dkim"`
	SPF  []SPFAuthResult  `xml:"spf"`
}

// DKIMAuthResult is one DKIM signature evaluation result.
type DKIMAuthResult struct {
	Domain      string `xml:"domain"`
	Selector    string `xml:"selector"`
	Result      string `xml:"result"`
	HumanResult string `xml:"human_result"`
}

// SPFAuthResult is one SPF check result.
type SPFAuthResult struct {
	Domain string `xml:"domain"`
	Scope  string `xml:"scope"`
	Result string `xml:"result"`
}
