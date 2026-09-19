package psl

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Resolver is the DNS surface the tree walk needs, injectable for tests.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Discovery methods, matching the values RFC 9990 §3.1.1.5 allows in
// <discovery_method> and so the values stored in reports.discovery_method.
const (
	MethodPSL      = "psl"
	MethodTreeWalk = "treewalk"
)

// maxTreeWalkQueries is the ceiling RFC 9989 §4.10 puts on one walk. It exists
// to stop an Author Domain with hundreds of labels turning every evaluation
// into a DNS amplification attack, and it is why a domain of eight or more
// labels jumps straight to its seven-label ancestor.
const maxTreeWalkQueries = 8

// TreeWalk is the outcome of resolving one domain's organisational domain.
type TreeWalk struct {
	// OrgDomain is the answer. It is never empty for a non-empty input.
	OrgDomain string `json:"org_domain"`
	// Method is how OrgDomain was arrived at: treewalk when DMARC records in
	// the DNS decided it, psl when the walk found none and the embedded
	// Public Suffix List was used instead.
	Method string `json:"method"`
	// Queried lists the names asked for, in order, so the UI can show the work.
	Queried []string `json:"queried,omitempty"`
	// Policy lists the domains that answered with exactly one valid DMARC
	// record, longest name first.
	Policy []string `json:"policy,omitempty"`
	// Err is a DNS failure that cut the walk short. OrgDomain still holds the
	// PSL answer in that case: a temporary resolver problem must not be
	// reported as "this domain has no parent".
	Err string `json:"err,omitempty"`
}

// TreeWalkOrgDomain finds a domain's Organizational Domain by the DNS tree
// walk of RFC 9989 §4.10, selecting among the records found per §4.10.2.
//
// This replaces, rather than consults, the Public Suffix List: DMARCbis lets a
// large organisation publish policy records at several points in its namespace
// and declare which of them is the organisational boundary, which no static
// list can express. When the walk finds no DMARC record anywhere — the domain
// does not do DMARC at all — the PSL answer is returned instead, because
// "the domain is its own organisational domain" is a true but useless answer
// for a caller trying to decide where else to look.
func TreeWalkOrgDomain(ctx context.Context, r Resolver, domain string) TreeWalk {
	domain = Normalize(domain)
	out := TreeWalk{OrgDomain: domain, Method: MethodTreeWalk}
	if domain == "" || r == nil {
		return TreeWalk{OrgDomain: OrgDomain(domain), Method: MethodPSL}
	}

	psd := map[string]string{}
	for _, target := range treeWalkTargets(domain) {
		name := "_dmarc." + target
		out.Queried = append(out.Queried, name)

		txts, err := r.LookupTXT(ctx, name)
		if err != nil {
			var dnsErr *net.DNSError
			if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
				continue // no record here is the ordinary case, not a failure
			}
			// A resolver failure leaves the walk unable to say anything; fall
			// back to the PSL rather than pretend the remaining names are empty.
			out.Err = err.Error()
			out.OrgDomain = OrgDomain(domain)
			out.Method = MethodPSL
			return out
		}

		rec, ok := singleDMARCRecord(txts)
		if !ok {
			continue
		}
		out.Policy = append(out.Policy, target)
		// §4.10 steps 2 and 6: an explicit psd tag ends the walk, whichever
		// way it points — the domain owner has declared the boundary.
		if v := dmarcTag(rec, "psd"); v == "y" || v == "n" {
			psd[target] = v
			break
		}
	}

	if len(out.Policy) == 0 {
		out.OrgDomain = OrgDomain(domain)
		out.Method = MethodPSL
		return out
	}

	// §4.10.2, longest name to shortest.
	for _, d := range out.Policy {
		switch psd[d] {
		case "n":
			out.OrgDomain = d
			return out
		case "y":
			if d == domain {
				continue // the starting point's own psd=y does not decide this
			}
			out.OrgDomain = oneLabelBelow(domain, d)
			return out
		}
	}
	out.OrgDomain = out.Policy[len(out.Policy)-1] // fewest labels
	return out
}

// OrgDomainFor resolves an organisational domain by the method the reporters
// for that domain declared. Only "treewalk" walks the DNS; everything else,
// including the empty value from a reporter that never said, uses the embedded
// Public Suffix List, which needs no queries.
func OrgDomainFor(ctx context.Context, r Resolver, domain, method string) TreeWalk {
	if r == nil || !strings.EqualFold(strings.TrimSpace(method), MethodTreeWalk) {
		return TreeWalk{OrgDomain: OrgDomain(domain), Method: MethodPSL}
	}
	return TreeWalkOrgDomain(ctx, r, domain)
}

// treeWalkTargets is steps 3, 4 and 7 of §4.10: the domain itself, then each
// ancestor up to the top-level domain, except that a name of eight or more
// labels skips straight to its seven-label ancestor so no walk exceeds eight
// queries.
func treeWalkTargets(domain string) []string {
	labels := strings.Split(domain, ".")
	out := []string{domain}
	start := 1
	if len(labels) >= maxTreeWalkQueries {
		start = len(labels) - (maxTreeWalkQueries - 1)
	}
	for i := start; i < len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// oneLabelBelow returns the name one label longer than parent along the path
// from start, which is what §4.10.2 means by "the domain one label below this
// one": for start=a.mail.example.com and parent=example.com it is
// mail.example.com.
func oneLabelBelow(start, parent string) string {
	sl := strings.Split(start, ".")
	pl := strings.Split(parent, ".")
	if len(sl) <= len(pl) {
		return parent
	}
	return strings.Join(sl[len(sl)-len(pl)-1:], ".")
}

// singleDMARCRecord applies §4.10 step 2: discard anything that is not a
// current-version DMARC record, and discard the lot when more than one
// survives, since that is an ambiguous configuration rather than a policy.
func singleDMARCRecord(txts []string) (string, bool) {
	var found string
	n := 0
	for _, txt := range txts {
		if !hasVersionTag(txt, "DMARC1") {
			continue
		}
		n++
		found = strings.TrimSpace(txt)
	}
	if n != 1 {
		return "", false
	}
	return found, true
}

// hasVersionTag reports whether s begins with a v= tag naming want. Whitespace
// is allowed around the equals sign; the value itself is matched exactly,
// since both DMARC and BIMI require the version to match precisely.
func hasVersionTag(s, want string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "v") {
		return false
	}
	rest := strings.TrimLeft(s[1:], " \t")
	if !strings.HasPrefix(rest, "=") {
		return false
	}
	rest = strings.TrimLeft(rest[1:], " \t")
	if !strings.HasPrefix(rest, want) {
		return false
	}
	rest = rest[len(want):]
	return rest == "" || strings.HasPrefix(rest, ";") || rest[0] == ' ' || rest[0] == '\t'
}

// dmarcTag returns the value of one tag of a DMARC record, lower-cased, or "".
func dmarcTag(record, tag string) string {
	for _, part := range strings.Split(record, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(name), tag) {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}
