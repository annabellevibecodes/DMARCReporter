// Package spf expands a domain's SPF record into the set of networks it
// authorises, following include / redirect / a / mx / ip4 / ip6 terms with the
// RFC 7208 §4.6.4 limit of 10 DNS-querying mechanisms.
//
// Only mechanisms with the "+" (pass) qualifier contribute networks: a term
// such as "-include:x" or "~a" describes addresses that must *not* pass, so
// they are not "authorised" for the purposes of S4.
package spf

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// MaxLookups is the RFC 7208 limit on DNS-querying mechanisms per evaluation.
const MaxLookups = 10

// Resolver is the subset of net.Resolver the expander needs (mockable in tests).
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
}

// Result is the expansion of one domain's SPF record.
type Result struct {
	Domain    string   `json:"domain"`
	Record    string   `json:"record"`     // the v=spf1 record found at Domain ("" when none)
	CIDRs     []string `json:"cidrs"`      // authorised networks, normalised and de-duplicated
	Lookups   int      `json:"lookups"`    // DNS-querying mechanisms evaluated
	OverLimit bool     `json:"over_limit"` // evaluation stopped at MaxLookups (result incomplete)
	Errors    []string `json:"errors"`     // non-fatal problems (missing include, DNS errors, …)
	Includes  []string `json:"includes"`   // every domain whose record was consulted
}

// Resolve expands the SPF record of domain. A missing record is not an error:
// the Result simply has no CIDRs and Record == "".
func Resolve(ctx context.Context, r Resolver, domain string) (*Result, error) {
	if r == nil {
		r = net.DefaultResolver
	}
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return nil, fmt.Errorf("empty domain")
	}
	e := &expander{ctx: ctx, r: r, res: &Result{Domain: domain}, seen: map[string]bool{}, cidrs: map[string]netip.Prefix{}}
	if err := e.expand(domain, true); err != nil {
		return nil, err
	}
	for _, p := range e.cidrs {
		e.res.CIDRs = append(e.res.CIDRs, p.String())
	}
	sort.Strings(e.res.CIDRs)
	return e.res, nil
}

type expander struct {
	ctx   context.Context
	r     Resolver
	res   *Result
	seen  map[string]bool
	cidrs map[string]netip.Prefix
}

func (e *expander) errorf(format string, args ...any) {
	e.res.Errors = append(e.res.Errors, fmt.Sprintf(format, args...))
}

// countLookup registers a DNS-querying mechanism; false when the limit is hit.
func (e *expander) countLookup() bool {
	if e.res.OverLimit {
		return false
	}
	if e.res.Lookups >= MaxLookups {
		e.res.OverLimit = true
		e.errorf("more than %d DNS lookups; result incomplete", MaxLookups)
		return false
	}
	e.res.Lookups++
	return true
}

func (e *expander) add(p netip.Prefix) {
	p = p.Masked()
	e.cidrs[p.String()] = p
}

func (e *expander) addIP(ip net.IP, v4len, v6len int) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return
	}
	a = a.Unmap()
	bits := v6len
	if a.Is4() {
		bits = v4len
	}
	if bits < 0 || bits > a.BitLen() {
		bits = a.BitLen()
	}
	e.add(netip.PrefixFrom(a, bits))
}

// lookupRecord fetches the single v=spf1 TXT record for name.
func (e *expander) lookupRecord(name string) (string, error) {
	txts, err := e.r.LookupTXT(e.ctx, name)
	if err != nil {
		return "", err
	}
	var found []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			found = append(found, strings.TrimSpace(t))
		}
	}
	if len(found) == 0 {
		return "", nil
	}
	if len(found) > 1 {
		e.errorf("%s publishes %d SPF records (RFC 7208 permerror); using the first", name, len(found))
	}
	return found[0], nil
}

func (e *expander) expand(domain string, top bool) error {
	if e.seen[domain] {
		return nil // include loop
	}
	e.seen[domain] = true
	record, err := e.lookupRecord(domain)
	if err != nil {
		if top {
			return fmt.Errorf("lookup TXT %s: %w", domain, err)
		}
		e.errorf("include:%s: %v", domain, err)
		return nil
	}
	if record == "" {
		if !top {
			e.errorf("include:%s has no SPF record", domain)
		}
		return nil
	}
	if top {
		e.res.Record = record
	} else {
		e.res.Includes = append(e.res.Includes, domain)
	}

	terms := strings.Fields(record)[1:] // skip v=spf1
	var redirect string
	for _, term := range terms {
		t := strings.ToLower(term)
		// Modifiers.
		if strings.HasPrefix(t, "redirect=") {
			redirect = strings.TrimPrefix(t, "redirect=")
			continue
		}
		if strings.HasPrefix(t, "exp=") || strings.Contains(t, "=") && !strings.Contains(t, ":") {
			continue // unknown modifier
		}
		qualifier := byte('+')
		if len(t) > 0 && strings.ContainsRune("+-~?", rune(t[0])) {
			qualifier = t[0]
			t = t[1:]
		}
		mech, arg := t, ""
		if i := strings.IndexAny(t, ":/"); i >= 0 {
			mech, arg = t[:i], t[i:]
		}
		switch mech {
		case "all":
			// "+all" authorises everything; recorded as a catch-all prefix.
			if qualifier == '+' {
				e.add(netip.MustParsePrefix("0.0.0.0/0"))
				e.add(netip.MustParsePrefix("::/0"))
				e.errorf("%s uses +all (any sender passes)", domain)
			}
		case "ip4", "ip6":
			if qualifier != '+' {
				continue
			}
			val := strings.TrimPrefix(arg, ":")
			if !strings.Contains(val, "/") {
				if a, err := netip.ParseAddr(val); err == nil {
					e.add(netip.PrefixFrom(a, a.BitLen()))
				} else {
					e.errorf("%s: bad %s value %q", domain, mech, val)
				}
				continue
			}
			if p, err := netip.ParsePrefix(val); err == nil {
				e.add(p)
			} else {
				e.errorf("%s: bad %s value %q", domain, mech, val)
			}
		case "a", "mx":
			host, v4len, v6len := parseHostAndLengths(arg, domain)
			if !e.countLookup() {
				return nil
			}
			if qualifier != '+' {
				continue // counted, but does not authorise
			}
			if mech == "a" {
				ips, err := e.r.LookupIP(e.ctx, "ip", host)
				if err != nil {
					e.errorf("%s: a:%s: %v", domain, host, err)
					continue
				}
				for _, ip := range ips {
					e.addIP(ip, v4len, v6len)
				}
				continue
			}
			mxs, err := e.r.LookupMX(e.ctx, host)
			if err != nil {
				e.errorf("%s: mx:%s: %v", domain, host, err)
				continue
			}
			if len(mxs) > MaxLookups {
				mxs = mxs[:MaxLookups]
				e.errorf("%s: mx:%s has more than %d hosts; truncated", domain, host, MaxLookups)
			}
			for _, mx := range mxs {
				ips, err := e.r.LookupIP(e.ctx, "ip", strings.TrimSuffix(mx.Host, "."))
				if err != nil {
					e.errorf("%s: mx host %s: %v", domain, mx.Host, err)
					continue
				}
				for _, ip := range ips {
					e.addIP(ip, v4len, v6len)
				}
			}
		case "include":
			if !e.countLookup() {
				return nil
			}
			target := strings.TrimPrefix(arg, ":")
			if target == "" {
				e.errorf("%s: include without domain", domain)
				continue
			}
			if qualifier != '+' {
				continue
			}
			if err := e.expand(expandMacroDomain(target, domain), false); err != nil {
				return err
			}
			if e.res.OverLimit {
				return nil
			}
		case "exists", "ptr":
			if !e.countLookup() {
				return nil
			}
			// exists: cannot be expressed as networks; ptr: deprecated.
			e.errorf("%s: %s mechanism cannot be expanded to networks", domain, mech)
		default:
			e.errorf("%s: unknown mechanism %q", domain, term)
		}
	}
	if redirect != "" && !e.res.OverLimit {
		if !e.countLookup() {
			return nil
		}
		return e.expand(expandMacroDomain(redirect, domain), false)
	}
	return nil
}

// parseHostAndLengths splits "[:host][/v4len[//v6len]]" (the a/mx argument).
func parseHostAndLengths(arg, def string) (host string, v4len, v6len int) {
	host, v4len, v6len = def, 32, 128
	if arg == "" {
		return
	}
	rest := arg
	if strings.HasPrefix(rest, ":") {
		rest = rest[1:]
		if i := strings.Index(rest, "/"); i >= 0 {
			host, rest = rest[:i], rest[i:]
		} else {
			host, rest = rest, ""
		}
		host = expandMacroDomain(host, def)
	}
	if strings.HasPrefix(rest, "/") {
		parts := strings.SplitN(rest[1:], "//", 2)
		if parts[0] != "" {
			if n, err := strconv.Atoi(parts[0]); err == nil && n >= 0 && n <= 32 {
				v4len = n
			}
		}
		if len(parts) == 2 && parts[1] != "" {
			if n, err := strconv.Atoi(parts[1]); err == nil && n >= 0 && n <= 128 {
				v6len = n
			}
		}
	}
	return
}

// expandMacroDomain resolves the few macros that can appear in a domain-spec
// without a sender context (%{d} = current domain). Other macros are left as
// is, which makes the lookup fail and surface as an error.
func expandMacroDomain(spec, domain string) string {
	spec = strings.ReplaceAll(spec, "%{d}", domain)
	spec = strings.ReplaceAll(spec, "%%", "%")
	return strings.TrimSuffix(spec, ".")
}
