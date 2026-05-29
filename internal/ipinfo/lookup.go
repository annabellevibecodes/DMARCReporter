// Package ipinfo resolves and caches reverse DNS and WHOIS data for IP addresses.
package ipinfo

import (
	"context"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/likexian/whois"
)

var whoisClient = whois.NewClient().SetTimeout(15 * time.Second)

const cacheTTL = 7 * 24 * time.Hour

// Info holds resolved metadata for a single IP address.
type Info struct {
	IP          string
	RDNS        string
	WhoisOrg    string
	WhoisNet    string
	WhoisCountry string
	WhoisCIDR   string
	WhoisAbuse  string
	LookedUpAt  int64
}

// Get returns cached IP info, performing a live lookup if the cache is missing or stale.
func Get(db *sqlx.DB, ip string) (*Info, error) {
	info, err := load(db, ip)
	if err != nil {
		return nil, err
	}
	age := time.Since(time.Unix(info.LookedUpAt, 0))
	if info.LookedUpAt == 0 || age > cacheTTL {
		if err := resolve(info); err != nil {
			// Non-fatal: return whatever we have (may be empty).
			_ = err
		}
		info.LookedUpAt = time.Now().Unix()
		if err := save(db, info); err != nil {
			return nil, err
		}
	}
	return info, nil
}

// load reads ip_info from the database. Returns a zero-valued Info if not found.
func load(db *sqlx.DB, ip string) (*Info, error) {
	var row struct {
		IP           string `db:"ip"`
		RDNS         string `db:"rdns"`
		WhoisOrg     string `db:"whois_org"`
		WhoisNet     string `db:"whois_net"`
		WhoisCountry string `db:"whois_country"`
		WhoisCIDR    string `db:"whois_cidr"`
		WhoisAbuse   string `db:"whois_abuse"`
		LookedUpAt   int64  `db:"looked_up_at"`
	}
	err := db.Get(&row,
		`SELECT ip, rdns, whois_org, whois_net, whois_country, whois_cidr, whois_abuse, looked_up_at
		 FROM ip_info WHERE ip = ?`, ip)
	if err != nil {
		// Not found — return empty struct.
		return &Info{IP: ip}, nil
	}
	return &Info{
		IP:           row.IP,
		RDNS:         row.RDNS,
		WhoisOrg:     row.WhoisOrg,
		WhoisNet:     row.WhoisNet,
		WhoisCountry: row.WhoisCountry,
		WhoisCIDR:    row.WhoisCIDR,
		WhoisAbuse:   row.WhoisAbuse,
		LookedUpAt:   row.LookedUpAt,
	}, nil
}

// save upserts an Info record into ip_info.
func save(db *sqlx.DB, info *Info) error {
	_, err := db.Exec(`
		INSERT INTO ip_info (ip, rdns, whois_org, whois_net, whois_country, whois_cidr, whois_abuse, looked_up_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			rdns          = excluded.rdns,
			whois_org     = excluded.whois_org,
			whois_net     = excluded.whois_net,
			whois_country = excluded.whois_country,
			whois_cidr    = excluded.whois_cidr,
			whois_abuse   = excluded.whois_abuse,
			looked_up_at  = excluded.looked_up_at`,
		info.IP, info.RDNS, info.WhoisOrg, info.WhoisNet,
		info.WhoisCountry, info.WhoisCIDR, info.WhoisAbuse, info.LookedUpAt)
	return err
}

// resolve performs live rDNS and WHOIS lookups and populates info in place.
func resolve(info *Info) error {
	// Reverse DNS — 5-second timeout.
	rdnsCtx, rdnsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rdnsCancel()
	resolver := &net.Resolver{}
	if names, err := resolver.LookupAddr(rdnsCtx, info.IP); err == nil && len(names) > 0 {
		info.RDNS = strings.TrimSuffix(names[0], ".")
	}

	// WHOIS — 15-second timeout via client (set at package init).
	_ = context.Background() // context import retained for rdns above
	raw, err := whoisClient.Whois(info.IP)
	if err == nil {
		parseWhois(raw, info)
	}
	return err
}

// parseWhois extracts key fields from a raw WHOIS response.
// WHOIS formats differ across registries (ARIN, RIPE, APNIC, …) so we try
// multiple key names and take the first non-empty match.
func parseWhois(raw string, info *Info) {
	// Normalise: collapse multiple spaces, trim each line.
	lines := strings.Split(raw, "\n")

	get := func(keys ...string) string {
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "%") {
				continue
			}
			idx := strings.Index(line, ":")
			if idx < 0 {
				continue
			}
			k := strings.TrimSpace(line[:idx])
			v := strings.TrimSpace(line[idx+1:])
			if v == "" {
				continue
			}
			for _, want := range keys {
				if strings.EqualFold(k, want) {
					return v
				}
			}
		}
		return ""
	}

	// Organization / network owner.
	info.WhoisOrg = get("OrgName", "org-name", "owner", "netname", "descr")

	// Network name (separate from org when both are available).
	net := get("NetName", "netname", "inetnum", "NetRange")
	if net != info.WhoisOrg {
		info.WhoisNet = net
	}

	// Country.
	info.WhoisCountry = get("Country", "country")

	// CIDR / network range.
	info.WhoisCIDR = get("CIDR", "inetnum", "NetRange")

	// Abuse contact.
	info.WhoisAbuse = strings.TrimRight(get("OrgAbuseEmail", "abuse-mailbox", "AbuseEmail", "abuse-c"), "'\"`,;.")

	// If OrgAbuseEmail wasn't present look for any abuse@ address in the raw text.
	if info.WhoisAbuse == "" {
		re := regexp.MustCompile(`(?i)abuse[^:\s]*@[^\s]+`)
		if m := re.FindString(raw); m != "" {
			info.WhoisAbuse = strings.TrimRight(m, "'\"`,;.")
		}
	}

	// Validate the abuse contact is a syntactically valid email address.
	// Reject anything that isn't — a malicious WHOIS response could otherwise
	// inject arbitrary content into the mailto: href on the source detail page.
	if info.WhoisAbuse != "" {
		if _, err := mail.ParseAddress(info.WhoisAbuse); err != nil {
			info.WhoisAbuse = ""
		}
	}
}
