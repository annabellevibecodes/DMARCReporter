package models

import "encoding/xml"

// Feedback is the root element of a DMARC aggregate report (RFC 7489 Appendix C).
type Feedback struct {
	XMLName         xml.Name        `xml:"feedback"`
	ReportMetadata  ReportMetadata  `xml:"report_metadata"`
	PolicyPublished PolicyPublished `xml:"policy_published"`
	Records         []Record        `xml:"record"`
}

// ReportMetadata describes the report itself.
type ReportMetadata struct {
	OrgName          string    `xml:"org_name"`
	Email            string    `xml:"email"`
	ExtraContactInfo string    `xml:"extra_contact_info"`
	ReportID         string    `xml:"report_id"`
	DateRange        DateRange `xml:"date_range"`
	Errors           []string  `xml:"error"`
}

// DateRange is a Unix timestamp pair indicating the report coverage window.
type DateRange struct {
	Begin int64 `xml:"begin"`
	End   int64 `xml:"end"`
}

// PolicyPublished is the DMARC policy in effect during the reporting period.
type PolicyPublished struct {
	Domain          string `xml:"domain"`
	ADKIM           string `xml:"adkim"`
	ASPF            string `xml:"aspf"`
	Policy          string `xml:"p"`
	SubdomainPolicy string `xml:"sp"`
	Pct             int    `xml:"pct"`
	FailureOptions  string `xml:"fo"`
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
