// Package psl resolves organisational domains for DMARC alignment checks.
//
// It wraps golang.org/x/net/publicsuffix (embedded Public Suffix List, no
// network access). Swap the implementation here if a different PSL source is
// preferred; every alignment computation in the application goes through
// OrgDomain and Align.
package psl

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Alignment classes shared by the DKIM (A3) and envelope-from (A6) breakdowns.
const (
	AlignExact      = "exact"       // auth domain == header_from
	AlignRelaxed    = "relaxed"     // same organisational domain, different label(s)
	AlignMisaligned = "misaligned"  // different organisational domain
	AlignThirdParty = "third_party" // A3 name for misaligned DKIM signers
	AlignNullSender = "null_sender" // envelope_from = <>
)

// Normalize lower-cases and trims a domain name, dropping a trailing dot.
func Normalize(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// OrgDomain returns the organisational domain of d (eTLD+1). When the PSL
// cannot determine one (bare TLD, IP literal, empty string), it falls back to
// the last two labels, or d itself when it has fewer.
func OrgDomain(d string) string {
	d = Normalize(d)
	if d == "" {
		return ""
	}
	if od, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		return od
	}
	labels := strings.Split(d, ".")
	if len(labels) <= 2 {
		return d
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// Align classifies auth against headerFrom: exact, relaxed or misaligned.
// Empty inputs are misaligned.
func Align(auth, headerFrom string) string {
	a, h := Normalize(auth), Normalize(headerFrom)
	if a == "" || h == "" {
		return AlignMisaligned
	}
	if a == h {
		return AlignExact
	}
	if OrgDomain(a) == OrgDomain(h) {
		return AlignRelaxed
	}
	return AlignMisaligned
}

// AlignEnvelope is Align for envelope_from values, recognising the null sender.
func AlignEnvelope(envelopeFrom, headerFrom string) string {
	if strings.TrimSpace(envelopeFrom) == "<>" {
		return AlignNullSender
	}
	return Align(envelopeFrom, headerFrom)
}
