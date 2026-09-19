// Package bimi reads what a domain publishes for Brand Indicators for Message
// Identification: the assertion record in DNS, and — from Phase 2 — the
// documents that record points at.
//
// The parser here is deliberately unforgiving. Core spec §4.3 says "Mail
// receivers MUST NOT attempt to fix syntactical or capitalization errors", and
// a parser that quietly repairs a record hides the exact defect the operator
// needs to see: the record would keep looking fine here while every real
// evaluator refused it. So every deviation is recorded as a Problem and
// nothing is corrected.
package bimi

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// States a domain's BIMI configuration can be in. Absent and Invalid are kept
// apart on purpose: "no record" is a domain that does not do BIMI, "invalid"
// is a domain that tried and failed, and the two call for opposite responses.
const (
	StateAbsent    = "absent"    // nothing published at this name
	StateInvalid   = "invalid"   // a record is published but must be ignored
	StateDeclined  = "declined"  // an explicit Declination to Publish (§4.3.1)
	StatePublished = "published" // a usable record
	StateError     = "error"     // the lookup itself failed; says nothing about the domain
)

// Problem severities. An error means the record cannot be used at all; a
// warning means an evaluator is permitted to refuse it; info is a remark.
const (
	SeverityError   = "error"
	SeverityWarning = "warning"
	SeverityInfo    = "info"
)

// Problem is one defect found in a record, named so the UI can list it and so
// B2 can count how often each kind occurs.
type Problem struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Record is a parsed BIMI assertion record.
//
// The *Present flags exist because BIMI gives three distinct meanings to a
// tag: absent, present-and-empty, and present-with-a-value. An empty l= is a
// deliberate declination; an absent l= is a broken record.
type Record struct {
	Raw       string    `json:"raw"`
	Version   string    `json:"version"`   // must be "BIMI1", must be the first tag
	Location  string    `json:"location"`  // l=
	Authority string    `json:"authority"` // a=
	LPS       []string  `json:"lps"`       // lps=; nil when absent, empty when present-but-empty
	AVP       string    `json:"avp"`       // avp= as published; "" when absent (means "brand")
	LPresent  bool      `json:"l_present"`
	APresent  bool      `json:"a_present"`
	Unknown   []string  `json:"unknown,omitempty"` // tags outside the registry, kept for B2
	Problems  []Problem `json:"problems,omitempty"`
}

// Parse reads one TXT record per core spec §4.3.
//
// A TXT record made of several character-strings is concatenated with nothing
// between them, which is what every resolver — including net.LookupTXT — hands
// back, so this takes the joined string and never re-splits it.
func Parse(raw string) Record {
	rec := Record{Raw: raw}
	body := strings.TrimSpace(raw)

	seen := map[string]int{}
	first := true
	for _, spec := range strings.Split(body, ";") {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue // the trailing semicolon the ABNF allows
		}
		name, value, ok := strings.Cut(spec, "=")
		if !ok {
			rec.problem(SeverityError, "malformed_tag",
				"%q is not a tag=value pair", truncate(spec, 40))
			first = false
			continue
		}
		// Tag names are matched case-sensitively, as the DKIM tag-value
		// syntax BIMI borrows requires. "L=" is not "l="; it is an unknown
		// tag, and the required tag it was meant to be is then missing.
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)

		seen[name]++
		if seen[name] == 2 {
			rec.problem(SeverityError, "duplicate_tag",
				"the %s= tag appears more than once", name)
		}

		switch name {
		case "v":
			rec.Version = value
			if !first {
				rec.problem(SeverityError, "version_not_first",
					"v= must be the first tag; the whole record is ignored")
			}
			if value != "BIMI1" {
				rec.problem(SeverityError, "version_mismatch",
					"v=%s is not BIMI1; the whole record is ignored", truncate(value, 20))
			}
		case "l":
			rec.LPresent = true
			rec.Location = value
			if value != "" {
				rec.checkURI("location", "l", value)
			}
		case "a":
			rec.APresent = true
			rec.Authority = value
			if value != "" {
				rec.checkURI("authority", "a", value)
			}
		case "lps":
			rec.LPS = parseLPS(value, &rec)
		case "avp":
			rec.AVP = value
			if value != "personal" && value != "brand" {
				rec.problem(SeverityWarning, "avp_invalid",
					"avp=%s is neither personal nor brand; evaluators must ignore it and may refuse the record",
					truncate(value, 20))
			}
		default:
			rec.Unknown = append(rec.Unknown, name)
			rec.problem(SeverityInfo, "unknown_tag",
				"%s= is not in the BIMI tag registry and is ignored by evaluators", truncate(name, 20))
		}
		first = false
	}

	if rec.Version == "" {
		rec.problem(SeverityError, "version_missing",
			"no v= tag; the whole record is ignored")
	}
	// l= is REQUIRED. An empty value is a declination, but no l= at all is a
	// record an evaluator cannot act on.
	if !rec.LPresent {
		rec.problem(SeverityError, "location_missing", "no l= tag, which is required")
	}
	return rec
}

// checkURI applies the bimi-uri rules: HTTPS only, a fully qualified domain
// name, and no unencoded comma.
func (r *Record) checkURI(what, tag, raw string) {
	u, err := url.Parse(raw)
	if err != nil {
		r.problem(SeverityError, what+"_malformed", "%s= is not a URI: %v", tag, err)
		return
	}
	if u.Scheme != "https" {
		scheme := u.Scheme
		if scheme == "" {
			scheme = "no scheme"
		}
		r.problem(SeverityError, what+"_not_https",
			"%s= uses %s; the spec allows HTTPS only", tag, scheme)
	}
	host := u.Hostname()
	switch {
	case host == "":
		r.problem(SeverityError, what+"_no_fqdn", "%s= has no host", tag)
	case net.ParseIP(host) != nil:
		r.problem(SeverityError, what+"_no_fqdn",
			"%s= names the IP address %s; the spec requires a fully qualified domain name", tag, host)
	case !strings.Contains(strings.TrimSuffix(host, "."), "."):
		r.problem(SeverityError, what+"_no_fqdn",
			"%s= names %q, which is not fully qualified", tag, host)
	}
	if strings.Contains(raw, ",") {
		r.problem(SeverityWarning, what+"_unencoded_comma",
			"%s= contains an unencoded comma, which the spec requires to be percent-encoded", tag)
	}
}

// parseLPS splits the local-part prefix list. Prefixes that break the ABNF are
// kept in the list and reported, rather than dropped: the operator needs to
// see what is published, not a cleaned-up version of it.
func parseLPS(value string, rec *Record) []string {
	if strings.TrimSpace(value) == "" {
		return []string{} // present but empty: every local-part matches
	}
	out := []string{}
	for _, prefix := range strings.Split(value, ",") {
		prefix = strings.TrimSpace(prefix)
		if prefix == "" {
			rec.problem(SeverityWarning, "lps_empty_prefix",
				"lps= contains an empty prefix between commas")
			continue
		}
		out = append(out, prefix)
		if len(prefix) > 63 {
			rec.problem(SeverityWarning, "lps_invalid_prefix",
				"the lps= prefix %q is %d characters; the limit is 63", truncate(prefix, 20), len(prefix))
			continue
		}
		if !validPrefix(prefix) {
			rec.problem(SeverityWarning, "lps_invalid_prefix",
				"the lps= prefix %q has characters outside letters, digits and '-'", truncate(prefix, 20))
		}
	}
	return out
}

func validPrefix(s string) bool {
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
		default:
			return false
		}
	}
	return true
}

// Declined reports an explicit Declination to Publish (§4.3.1): l= and a= are
// both empty. An absent a= counts as empty, which the spec states outright.
func (r Record) Declined() bool {
	return r.LPresent && r.Location == "" && r.Authority == ""
}

// Ignorable reports whether an evaluator must discard the record entirely.
func (r Record) Ignorable() bool {
	for _, p := range r.Problems {
		if p.Severity == SeverityError {
			return true
		}
	}
	return false
}

// State classifies the record for B1. A record with any fatal problem is
// invalid whatever else it says, because no evaluator will get as far as
// reading the rest of it.
func (r Record) State() string {
	switch {
	case r.Ignorable():
		return StateInvalid
	case r.Declined():
		return StateDeclined
	default:
		return StatePublished
	}
}

// AvatarPreference is the effective avp= value. An absent or invalid value
// means "brand", since the spec requires evaluators to ignore anything else.
func (r Record) AvatarPreference() string {
	if r.AVP == "personal" {
		return "personal"
	}
	return "brand"
}

// LPSPresent reports whether an lps= tag was published at all, which an empty
// prefix list ("every local-part matches") does not otherwise reveal.
func (r Record) LPSPresent() bool { return r.LPS != nil }

// RRset is the outcome of applying §7.2 steps 3, 4 and 9 to one TXT RRset.
type RRset struct {
	// Candidates holds the records that begin with a v= tag naming BIMI1.
	// More than one is a published misconfiguration, so all of them are kept
	// rather than one being chosen.
	Candidates []string `json:"candidates,omitempty"`
	// Discarded holds the records that did not, so "there is a TXT record
	// here but it is not a BIMI record" is visible rather than silent.
	Discarded []string `json:"discarded,omitempty"`
	Record    Record   `json:"record"`
	Found     bool     `json:"found"`
	Err       string   `json:"err,omitempty"`
}

// ParseRRset selects the assertion record from a TXT RRset.
//
// Step 4 discards everything that is not a BIMI1 record, and step 9 stops
// BIMI processing when what remains is not exactly one record. Two records is
// therefore a published misconfiguration, not a choice between them.
func ParseRRset(txts []string) RRset {
	var out RRset
	for _, txt := range txts {
		if hasBIMIVersion(txt) {
			out.Candidates = append(out.Candidates, txt)
			continue
		}
		if strings.TrimSpace(txt) != "" {
			out.Discarded = append(out.Discarded, txt)
		}
	}
	switch len(out.Candidates) {
	case 0:
		return out
	case 1:
		out.Found = true
		out.Record = Parse(out.Candidates[0])
		return out
	default:
		out.Err = fmt.Sprintf("%d BIMI1 records published; §7.2 step 9 requires exactly one, so evaluators perform no BIMI processing at all", len(out.Candidates))
		// The first is parsed for display only. It is not the record in use —
		// there is none — which is what State reports.
		out.Record = Parse(out.Candidates[0])
		return out
	}
}

// Ambiguous reports the §7.2 step 9 case: more than one BIMI1 record, which
// stops BIMI processing entirely rather than picking one.
func (s RRset) Ambiguous() bool { return len(s.Candidates) > 1 }

// State classifies the RRset: an ambiguous set is invalid rather than absent.
func (s RRset) State() string {
	switch {
	case s.Ambiguous():
		return StateInvalid
	case !s.Found:
		return StateAbsent
	default:
		return s.Record.State()
	}
}

// hasBIMIVersion reports whether a TXT record starts with a v= tag naming this
// version of BIMI. Whitespace around the equals sign is allowed by the ABNF;
// the value is matched exactly, since the spec says it MUST match precisely.
func hasBIMIVersion(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return false
	}
	rest := strings.TrimLeft(s[1:], " \t")
	if !strings.HasPrefix(rest, "=") {
		return false
	}
	rest = strings.TrimLeft(rest[1:], " \t")
	if !strings.HasPrefix(rest, "BIMI1") {
		return false
	}
	rest = rest[len("BIMI1"):]
	return rest == "" || rest[0] == ';' || rest[0] == ' ' || rest[0] == '\t'
}

func (r *Record) problem(severity, code, format string, args ...any) {
	r.Problems = append(r.Problems, Problem{
		Code: code, Severity: severity, Message: fmt.Sprintf(format, args...),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
