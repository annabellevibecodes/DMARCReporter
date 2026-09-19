package models

import (
	"encoding/xml"
	"strings"
)

// The <bimi> element of a DMARC aggregate report
// (draft-adams-bimi-reporting-11).
//
// It is a top-level sibling of <record>, not a child of one, because a BIMI
// evaluation is made once per (domain, selector, configuration) and not per
// source IP. Nothing here can therefore be joined to a source address, a
// disposition, or a message count: the counts below are the evaluator's own
// aggregates for the whole reporting period.

// Error element names, which are also the names of two structural elements —
// see BIMIErrors.UnmarshalXML.
const (
	BIMIErrAssertion = "assertion"
	BIMIErrEvidence  = "evidence"
	BIMIErrIndicator = "indicator"
	BIMIErrUndefined = "undefined"
)

// BIMIReport is the <bimi> element.
type BIMIReport struct {
	Domains []BIMIDomain `xml:"domain"`
}

// BIMIDomain is one <domain> element: a unique aligned:assertion tuple.
type BIMIDomain struct {
	Aligned    string          `xml:"aligned,attr"`
	Assertion  string          `xml:"assertion,attr"`
	Assertions []BIMIAssertion `xml:"assertion"`

	// AlignedPresent and AssertionPresent record whether the required
	// attributes were supplied at all, which "" alone cannot express.
	AlignedPresent   bool `xml:"-"`
	AssertionPresent bool `xml:"-"`
}

// BIMIAssertion is one <assertion> element: a unique selector:l:a tuple.
type BIMIAssertion struct {
	Selector string `xml:"selector,attr"`
	// L is the l= value the evaluator saw. The magic value "unpublished"
	// means the tag was empty — it is not a URI and must never be treated
	// as one.
	L string `xml:"l,attr"`
	A string `xml:"a,attr"`

	SelectorPresent bool `xml:"-"`
	LPresent        bool `xml:"-"`
	APresent        bool `xml:"-"`

	Evidence *BIMIEvidence `xml:"evidence"`
	Errors   *BIMIErrors   `xml:"errors"`
}

// Unpublished is the magic l= value §3.2 defines for an empty l= tag.
const Unpublished = "unpublished"

// BIMIEvidence is the <evidence> element: a null element carrying attributes
// about the evidence document the evaluator used.
type BIMIEvidence struct {
	Date   string `xml:"evidence-date,attr"`
	Issuer string `xml:"evidence-issuer,attr"`
	Type   string `xml:"evidence-type,attr"`
	URL    string `xml:"evidence-url,attr"`

	// ParsedDate is Date read as the RFC 5322 date §3.3 specifies, or 0 when
	// it is absent or unreadable. The raw text is kept either way.
	ParsedDate int64 `xml:"-"`
	// DateMalformed records that Date was supplied but could not be read.
	DateMalformed bool `xml:"-"`
}

// BIMIError is one ERROR-NAME:class:type tuple with the evaluator's count.
type BIMIError struct {
	// Element is the error element's own name: assertion, evidence,
	// indicator or undefined.
	Element     string
	Class       string
	Type        string
	Description string
	// Count is the parsed count. Raw keeps what was actually written, so a
	// count that is not a positive natural number can be reported rather than
	// silently becoming zero.
	Count int64
	Raw   string
	// ClassPresent records whether the required class attribute was supplied.
	ClassPresent bool
}

// BIMIErrors is the <errors> element.
type BIMIErrors struct {
	Entries []BIMIError
}

// UnmarshalXML reads the <errors> element's children by hand.
//
// This is the one place in the schema where element names mean two different
// things: <assertion> and <evidence> are structural elements *and* error
// element names. A struct-tag mapping would let an error element be decoded
// into the structural type, or the structural <evidence/> be counted as an
// error — in both directions silently, and in the second direction inflating
// every error total. Walking the children explicitly makes that impossible:
// nothing outside this method ever looks at the contents of <errors>, and
// nothing in here can reach outside it.
func (e *BIMIErrors) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			entry := BIMIError{Element: strings.ToLower(t.Name.Local)}
			for _, a := range t.Attr {
				switch strings.ToLower(a.Name.Local) {
				case "class":
					entry.Class = strings.ToLower(strings.TrimSpace(a.Value))
					entry.ClassPresent = true
				case "type":
					entry.Type = strings.ToLower(strings.TrimSpace(a.Value))
				case "description":
					entry.Description = a.Value
				}
			}
			var text string
			if err := d.DecodeElement(&text, &t); err != nil {
				return err
			}
			entry.Raw = strings.TrimSpace(text)
			e.Entries = append(e.Entries, entry)
		case xml.EndElement:
			if t.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
}

// UnmarshalXML records which required attributes were actually present.
//
// encoding/xml cannot express "this attribute was absent" for a string field,
// and the difference matters: an empty a="" is what §3.2 requires for a domain
// publishing no evidence document, while a missing a= is a defective report.
func (a *BIMIAssertion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type plain BIMIAssertion // shed the method to avoid recursing
	var out plain
	if err := d.DecodeElement(&out, &start); err != nil {
		return err
	}
	out.SelectorPresent = hasAttr(start, "selector")
	out.LPresent = hasAttr(start, "l")
	out.APresent = hasAttr(start, "a")
	*a = BIMIAssertion(out)
	return nil
}

// UnmarshalXML records the presence of the required <domain> attributes.
func (b *BIMIDomain) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type plain BIMIDomain
	var out plain
	if err := d.DecodeElement(&out, &start); err != nil {
		return err
	}
	out.AlignedPresent = hasAttr(start, "aligned")
	out.AssertionPresent = hasAttr(start, "assertion")
	*b = BIMIDomain(out)
	return nil
}

func hasAttr(start xml.StartElement, name string) bool {
	for _, a := range start.Attr {
		if strings.EqualFold(a.Name.Local, name) {
			return true
		}
	}
	return false
}

// BIMIHygiene counts every leniency the parser took and every rule the report
// broke (B19). A report that needed none of them scores zero across the board.
type BIMIHygiene struct {
	// Present is 1 when the report carried a <bimi> element at all, which is
	// what B18 coverage divides by.
	Present int
	// DupTuples counts violations of the draft's uniqueness MUSTs: a repeated
	// aligned:assertion, selector:l:a, or element:class:type.
	DupTuples int
	// BadCounts counts error counts that are not the positive natural number
	// §3.4 requires.
	BadCounts int
	// UnknownTypes counts class or type values outside the registry.
	UnknownTypes int
	// MissingAttrs counts required attributes that were not supplied.
	MissingAttrs int
	// MalformedFields counts report-level values salvaged from malformed text
	// — today only the date range, which the draft's own example gets wrong.
	MalformedFields int
}

// Empty reports whether nothing was found to count.
func (h BIMIHygiene) Empty() bool {
	return h.DupTuples == 0 && h.BadCounts == 0 && h.UnknownTypes == 0 &&
		h.MissingAttrs == 0 && h.MalformedFields == 0
}
