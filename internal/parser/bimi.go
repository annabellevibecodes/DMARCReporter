package parser

import (
	"net/mail"
	"strconv"
	"strings"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// The registries draft-adams-bimi-reporting-11 §3.4 defines. A value outside
// them is stored as it arrived and counted in UnknownTypes: the report is a
// record of what an evaluator said, and rewriting it to fit would destroy the
// evidence that the evaluator said something unexpected.
var (
	bimiErrorElements = map[string]bool{
		models.BIMIErrAssertion: true,
		models.BIMIErrEvidence:  true,
		models.BIMIErrIndicator: true,
		models.BIMIErrUndefined: true,
	}
	bimiClasses = map[string]bool{"temp": true, "perm": true}
	// Types are per element: §3.4.1 to §3.4.4 give each its own set, and
	// <undefined> takes none at all.
	bimiTypes = map[string]map[string]bool{
		models.BIMIErrAssertion: {"retrieval": true, "parsing": true},
		models.BIMIErrEvidence: {
			"retrieval": true, "parsing": true, "validation": true,
			"expired": true, "revoked": true, "policy": true,
		},
		models.BIMIErrIndicator: {"retrieval": true, "parsing": true, "validation": true},
		models.BIMIErrUndefined: {},
	}
)

// normalizeBIMI validates the <bimi> element against the draft's MUSTs and
// records what it found in fb.BIMIHygiene.
//
// Nothing is dropped and nothing is corrected. The draft's rules are mostly
// uniqueness and vocabulary constraints, and a report that breaks one is still
// the evaluator's account of what happened — it is just an account to be less
// confident in, which is exactly what B19 is for.
func normalizeBIMI(fb *models.Feedback) {
	fb.BIMIHygiene.MalformedFields += fb.ReportMetadata.DateRange.Malformed
	if fb.BIMI == nil {
		return
	}
	h := &fb.BIMIHygiene
	h.Present = 1

	seenDomains := map[string]bool{}
	for di := range fb.BIMI.Domains {
		d := &fb.BIMI.Domains[di]
		d.Aligned = strings.ToLower(strings.TrimSpace(d.Aligned))
		d.Assertion = strings.ToLower(strings.TrimSpace(d.Assertion))

		// §3.1: both attributes are REQUIRED.
		if !d.AlignedPresent {
			h.MissingAttrs++
		}
		if !d.AssertionPresent {
			h.MissingAttrs++
		}
		// §3.1: each <domain> MUST be a unique aligned:assertion tuple.
		if key := d.Aligned + "\x00" + d.Assertion; seenDomains[key] {
			h.DupTuples++
		} else {
			seenDomains[key] = true
		}

		seenAssertions := map[string]bool{}
		for ai := range d.Assertions {
			a := &d.Assertions[ai]
			normalizeBIMIAssertion(a, h)

			// §3.2: each <assertion> MUST be a unique selector:l:a tuple
			// within its <domain>.
			if key := a.Selector + "\x00" + a.L + "\x00" + a.A; seenAssertions[key] {
				h.DupTuples++
			} else {
				seenAssertions[key] = true
			}
		}
	}
}

func normalizeBIMIAssertion(a *models.BIMIAssertion, h *models.BIMIHygiene) {
	a.Selector = strings.ToLower(strings.TrimSpace(a.Selector))
	a.L = strings.TrimSpace(a.L)
	a.A = strings.TrimSpace(a.A)

	// §3.2: selector, l and a are all REQUIRED, and l is required to carry
	// the magic value "unpublished" rather than being left empty.
	if !a.SelectorPresent {
		h.MissingAttrs++
	}
	if !a.LPresent {
		h.MissingAttrs++
	}
	if !a.APresent {
		h.MissingAttrs++
	}
	if a.Selector == "" {
		a.Selector = "default" // §3.2's own default, not a repair
	}

	if a.Evidence != nil {
		normalizeBIMIEvidence(a.Evidence, h)
	}
	if a.Errors == nil {
		return
	}

	// §3.4: one instance of a specific ERROR-NAME:class:type tuple per report.
	seen := map[string]bool{}
	for i := range a.Errors.Entries {
		e := &a.Errors.Entries[i]

		if !bimiErrorElements[e.Element] {
			h.UnknownTypes++
		}
		if !e.ClassPresent || !bimiClasses[e.Class] {
			h.UnknownTypes++
		}
		if types, ok := bimiTypes[e.Element]; ok && e.Type != "" && !types[e.Type] {
			h.UnknownTypes++
		}
		if !e.ClassPresent {
			h.MissingAttrs++
		}

		// §3.4: the element encloses "a positive natural number".
		n, err := strconv.ParseInt(strings.TrimSpace(e.Raw), 10, 64)
		switch {
		case err != nil, n <= 0:
			h.BadCounts++
			if err != nil {
				n = 0
			}
		}
		if n < 0 {
			n = 0
		}
		e.Count = n

		if key := e.Element + "\x00" + e.Class + "\x00" + e.Type; seen[key] {
			h.DupTuples++
		} else {
			seen[key] = true
		}
	}
}

// normalizeBIMIEvidence reads the evaluation date.
//
// §3.3 specifies an RFC 5322 date, not ISO 8601 — the format mail headers use,
// which is why it is read with net/mail's parser rather than time.Parse. A
// value that will not read is kept as text and counted, never guessed at.
func normalizeBIMIEvidence(e *models.BIMIEvidence, h *models.BIMIHygiene) {
	e.Date = strings.TrimSpace(e.Date)
	e.Issuer = strings.TrimSpace(e.Issuer)
	e.Type = strings.TrimSpace(e.Type)
	e.URL = strings.TrimSpace(e.URL)
	if e.Date == "" {
		return
	}
	t, err := mail.ParseDate(e.Date)
	if err != nil {
		e.DateMalformed = true
		h.MalformedFields++
		return
	}
	e.ParsedDate = t.Unix()
}
