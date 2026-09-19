package bimi

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/annabellevibecodes/dmarcreporter/internal/psl"
)

// DefaultSelector is the selector used when a message names none.
const DefaultSelector = "default"

// Resolver is the DNS surface this package needs, injectable for tests.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Client performs assertion record lookups. The zero value is usable and uses
// the system resolver and the Public Suffix List.
type Client struct {
	Resolver Resolver
	// Discovery is the method reporters declared for the domain being looked
	// up ("psl" or "treewalk", from reports.discovery_method). It decides how
	// the organizational domain for the §7.2 fallback is found; an unset value
	// uses the Public Suffix List and issues no extra queries.
	Discovery string
}

func (c *Client) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return systemResolver{}
}

// Result is one selector's assertion record lookup for one domain.
type Result struct {
	Domain    string `json:"domain"`   // the domain asked about
	Selector  string `json:"selector"` // the selector asked about
	QueryName string `json:"query_name"`
	// FoundAt is the domain the record actually came from, which is not the
	// domain asked about when the organizational-domain fallback supplied it.
	// B1 shows this: an operator looking at a subdomain needs to know the logo
	// is inherited rather than published there.
	FoundAt   string `json:"found_at,omitempty"`
	OrgDomain string `json:"org_domain,omitempty"`
	// OrgMethod is how OrgDomain was determined: treewalk or psl.
	OrgMethod string `json:"org_method,omitempty"`
	Fallback  bool   `json:"fallback"`
	RRset
	State string `json:"state"`
	// Error is a DNS failure. It is kept apart from every other state because
	// a resolver that timed out says nothing at all about the domain.
	Error     string `json:"error,omitempty"`
	CheckedAt int64  `json:"checked_at,omitempty"`
}

// Content is the text a snapshot diffs on. An unchanged record must produce
// byte-identical text every run or the change log fills with non-changes, so
// an ambiguous set is rendered in a stable order rather than in the order the
// resolver happened to return.
func (r Result) Content() string {
	switch {
	case r.Found:
		return strings.TrimSpace(r.Record.Raw)
	case r.Ambiguous():
		out := make([]string, 0, len(r.Candidates))
		for _, c := range r.Candidates {
			out = append(out, strings.TrimSpace(c))
		}
		sort.Strings(out)
		return strings.Join(out, "\n")
	default:
		return ""
	}
}

// Lookup queries <selector>._bimi.<domain>, falling back to the organizational
// domain per core spec §7.2 steps 6 to 8.
//
// The local-part selector derivation of steps 5 and 8 is deliberately not
// performed: it depends on the local-part of a message being evaluated, and
// probing speculative selectors would be a DNS fishing expedition against the
// operator's own zone. The published lps= prefix list is recorded instead.
func (c *Client) Lookup(ctx context.Context, domain, selector string) Result {
	domain = psl.Normalize(domain)
	selector = normaliseSelector(selector)
	out := Result{Domain: domain, Selector: selector, QueryName: QueryName(domain, selector)}

	rrset, err := c.query(ctx, out.QueryName)
	if err != nil {
		out.Error = err.Error()
		out.State = StateError
		return out
	}
	out.RRset = rrset

	// A record here, or an ambiguous set here, both end discovery: §7.2 step 9
	// terminates on multiple records rather than climbing to the parent.
	if rrset.Found || rrset.Ambiguous() {
		out.FoundAt = domain
		out.State = rrset.State()
		return out
	}

	walk := psl.OrgDomainFor(ctx, c.resolver(), domain, c.Discovery)
	out.OrgDomain, out.OrgMethod = walk.OrgDomain, walk.Method
	if walk.OrgDomain == "" || walk.OrgDomain == domain {
		out.State = rrset.State()
		return out
	}

	orgName := QueryName(walk.OrgDomain, selector)
	orgSet, err := c.query(ctx, orgName)
	if err != nil {
		// The domain itself answered "nothing"; the parent could not be
		// asked. Report the failure rather than concluding absence.
		out.Error = err.Error()
		out.State = StateError
		return out
	}
	if orgSet.Found || orgSet.Ambiguous() {
		out.RRset = orgSet
		out.FoundAt = walk.OrgDomain
		out.QueryName = orgName
		out.Fallback = true
	}
	out.State = out.RRset.State()
	return out
}

// LookupAll resolves several selectors for one domain. "default" is always
// included and always first, because that is the selector a message with no
// BIMI-Selector header uses and so the one that governs most mail.
func (c *Client) LookupAll(ctx context.Context, domain string, selectors []string) []Result {
	out := make([]Result, 0, len(selectors)+1)
	seen := map[string]bool{}
	for _, s := range append([]string{DefaultSelector}, selectors...) {
		s = normaliseSelector(s)
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, c.Lookup(ctx, domain, s))
	}
	return out
}

// query resolves one name. NXDOMAIN is an empty set, not an error: a domain
// that publishes nothing is the ordinary case.
func (c *Client) query(ctx context.Context, name string) (RRset, error) {
	txts, err := c.resolver().LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return RRset{}, nil
		}
		return RRset{}, err
	}
	return ParseRRset(txts), nil
}

// QueryName builds the DNS name an assertion record lives at. Periods inside a
// selector are label separators (§4.4), so the name is assembled by
// concatenation and never escaped.
func QueryName(domain, selector string) string {
	return normaliseSelector(selector) + "._bimi." + psl.Normalize(domain)
}

// normaliseSelector lower-cases a selector — §4.5 states selectors are case
// insensitive — and substitutes the default for an empty one.
func normaliseSelector(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.Trim(strings.TrimSpace(s), ".")))
	if s == "" {
		return DefaultSelector
	}
	return s
}

type systemResolver struct{}

func (systemResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}
