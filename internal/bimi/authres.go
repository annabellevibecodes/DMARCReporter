package bimi

import (
	"strings"
)

// Results core spec §7.7 defines for the bimi method.
const (
	VerdictPass      = "pass"      // BIMI validated; a logo was shown
	VerdictNone      = "none"      // no BIMI record present
	VerdictFail      = "fail"      // a syntax error, or a failure in discovery or validation
	VerdictTempError = "temperror" // a DNS lookup problem
	VerdictDeclined  = "declined"  // the domain owner published an explicit declination
	VerdictSkipped   = "skipped"   // the check was not performed at all
)

// Verdict is one receiver's bimi= entry from an Authentication-Results header:
// what a real mailbox provider concluded about a real message.
//
// This is the only evidence in the whole B series of what a person would
// actually have seen. Everything else says what should happen; this says what
// did — for the mail the operator sent to the seed address, and for nothing
// else.
type Verdict struct {
	// Receiver is the authserv-id: the host that performed the evaluation.
	Receiver string `json:"receiver"`
	Result   string `json:"result"`
	// Comment is the parenthesised text §7.7 allows after the result, which is
	// often the only statement of *why* — "bimi=skipped (message failed
	// DMARC)" says far more than "skipped".
	Comment string `json:"comment,omitempty"`
	// HeaderD is the domain of the assertion record evaluated, which is the
	// organizational domain when the fallback supplied the record.
	HeaderD  string `json:"header_d,omitempty"`
	Selector string `json:"selector,omitempty"`
	// Authority is policy.authority: whether the evidence document was checked
	// and validated. "none" means it was not checked, not that it failed.
	Authority    string `json:"authority,omitempty"`
	AuthorityURI string `json:"authority_uri,omitempty"`
	IndicatorURI string `json:"indicator_uri,omitempty"`
	// IndicatorHash is policy.indicator-hash: the *final* characters of the
	// SHA-256 of the raw uncompressed SVG, at least eight of them. It is a
	// suffix, not a whole hash, which is why matching compares suffixes.
	IndicatorHash  string `json:"indicator_hash,omitempty"`
	LogoPreference string `json:"logo_preference,omitempty"`
	Raw            string `json:"raw"`
}

// Displayed reports a verdict that would have shown a logo.
func (v Verdict) Displayed() bool { return v.Result == VerdictPass }

// HashMatches reports whether the truncated hash this receiver recorded is a
// suffix of the given full SHA-256 of the indicator.
//
// §7.7 truncates to "the final 8 (at least) characters", so a receiver may
// send any suffix length. Comparing suffixes is therefore the only comparison
// that can succeed; an exact match would fail against every real receiver.
func (v Verdict) HashMatches(fullSHA256 string) bool {
	h := strings.ToLower(strings.TrimSpace(v.IndicatorHash))
	if h == "" || fullSHA256 == "" {
		return false
	}
	return strings.HasSuffix(strings.ToLower(fullSHA256), h)
}

// ParseAuthResults extracts every bimi entry from a message's
// Authentication-Results headers.
//
// A message can carry several, one per host that handled it, and the results
// can disagree — that is a finding rather than a problem, so all of them are
// returned. Headers that carry no bimi method produce nothing.
func ParseAuthResults(headers []string) []Verdict {
	var out []Verdict
	for _, header := range headers {
		out = append(out, parseAuthResultsHeader(header)...)
	}
	return out
}

func parseAuthResultsHeader(header string) []Verdict {
	header = unfold(header)
	if header == "" {
		return nil
	}
	// Strip the field name when a whole header line was passed in.
	if _, rest, ok := strings.Cut(header, ":"); ok &&
		strings.EqualFold(strings.TrimSpace(header[:strings.Index(header, ":")]), "authentication-results") {
		header = rest
	}

	segments, comments := splitAuthResults(header)
	if len(segments) == 0 {
		return nil
	}
	// The first segment is the authserv-id, optionally followed by a version.
	receiver := strings.TrimSpace(segments[0])
	if fields := strings.Fields(receiver); len(fields) > 0 {
		receiver = fields[0]
	}

	var out []Verdict
	for i, seg := range segments[1:] {
		// RFC 8601 allows whitespace on either side of an equals sign, so the
		// segment is normalised before it is split on whitespace — otherwise
		// "bimi = pass" parses as two unrelated tokens.
		fields := strings.Fields(collapseEquals(seg))
		if len(fields) == 0 {
			continue
		}
		method, result, ok := strings.Cut(fields[0], "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(method), "bimi") {
			continue
		}
		v := Verdict{
			Receiver: receiver,
			Result:   strings.ToLower(strings.Trim(strings.TrimSpace(result), `"`)),
			Comment:  comments[i+1],
			Raw:      strings.TrimSpace(seg),
		}
		for _, prop := range fields[1:] {
			name, value, ok := strings.Cut(prop, "=")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"`)
			switch strings.ToLower(strings.TrimSpace(name)) {
			case "header.d":
				v.HeaderD = strings.ToLower(value)
			case "header.selector":
				v.Selector = strings.ToLower(value)
			case "policy.authority":
				v.Authority = strings.ToLower(value)
			case "policy.authority-uri":
				v.AuthorityURI = value
			case "policy.indicator-uri":
				v.IndicatorURI = value
			case "policy.indicator-hash":
				v.IndicatorHash = value
			case "policy.logo-preference":
				v.LogoPreference = strings.ToLower(value)
			}
		}
		out = append(out, v)
	}
	return out
}

// splitAuthResults splits a header into its semicolon-separated segments,
// lifting out the parenthesised comments first.
//
// Comments have to be removed before splitting, not after: §7.7's own examples
// include "bimi=fail (Invalid SVG)", and a comment is free text that may well
// contain a semicolon of its own. Each segment's comment is returned beside
// it so the explanation is not thrown away with the punctuation.
func splitAuthResults(header string) (segments []string, comments []string) {
	var (
		current strings.Builder
		comment strings.Builder
		depth   int
		quoted  bool
	)
	segments, comments = []string{}, []string{}
	flush := func() {
		segments = append(segments, current.String())
		comments = append(comments, strings.TrimSpace(comment.String()))
		current.Reset()
		comment.Reset()
	}

	for i := 0; i < len(header); i++ {
		c := header[i]
		switch {
		case quoted:
			if c == '"' {
				quoted = false
			}
			current.WriteByte(c)
		case c == '"' && depth == 0:
			quoted = true
			current.WriteByte(c)
		case c == '(':
			depth++
			if depth == 1 {
				continue
			}
			comment.WriteByte(c)
		case c == ')' && depth > 0:
			depth--
			if depth == 0 {
				continue
			}
			comment.WriteByte(c)
		case depth > 0:
			comment.WriteByte(c)
		case c == ';':
			flush()
		default:
			current.WriteByte(c)
		}
	}
	flush()
	return segments, comments
}

// collapseEquals removes the whitespace around every equals sign that is not
// inside a quoted string.
func collapseEquals(s string) string {
	var out strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			quoted = !quoted
			out.WriteByte(c)
			continue
		}
		if quoted || c != '=' {
			out.WriteByte(c)
			continue
		}
		// Drop the spaces already written before this equals sign, and the
		// ones that follow it.
		trimmed := strings.TrimRight(out.String(), " \t")
		out.Reset()
		out.WriteString(trimmed)
		out.WriteByte('=')
		for i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
			i++
		}
	}
	return out.String()
}

// unfold joins a folded header into one line.
func unfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}
