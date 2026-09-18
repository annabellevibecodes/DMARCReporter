package models

import (
	"encoding/xml"
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
