// Package tlspolicy looks up what a domain publishes for SMTP transport
// security: its TLS-RPT record, its MTA-STS policy, and the TLSA records of
// its MX hosts.
//
// These are the "what you published" half of the picture. The reports say what
// senders actually applied; comparing the two is how a botched key rollover or
// a stale cache shows up (T8).
package tlspolicy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// typeTLSA is the TLSA record type (RFC 6698 §7.1). dnsmessage has no
// constant for it and no decoder, so the query type is given here and the
// RDATA is decoded by hand below.
const typeTLSA = dnsmessage.Type(52)

// Lookup timeouts. Enrich runs in the background, but a hung nameserver or a
// black-holed HTTPS host must not stall the whole run.
const (
	dnsTimeout   = 5 * time.Second
	httpTimeout  = 10 * time.Second
	maxPolicyLen = 64 * 1024
)

// TLSRPTRecord is the parsed _smtp._tls.<domain> TXT record.
type TLSRPTRecord struct {
	// Found is true only when exactly one record beginning "v=TLSRPTv1;"
	// exists. RFC 8460 §3 says a different count means the domain does not
	// implement TLS-RPT — not that it has a broken one.
	Found bool     `json:"found"`
	Raw   string   `json:"raw,omitempty"`
	RUA   []string `json:"rua,omitempty"`
	// Extensions holds any tag beyond v= and rua=, so a record using a
	// future extension is visible rather than silently reduced.
	Extensions map[string]string `json:"extensions,omitempty"`
	// Candidates is how many v=TLSRPTv1 records were seen, for the case where
	// it is not one.
	Candidates int    `json:"candidates"`
	Error      string `json:"error,omitempty"`
}

// MTASTSPolicy is the published MTA-STS policy: the DNS record that announces
// it and the policy file itself.
type MTASTSPolicy struct {
	// DNSFound and ID come from _mta-sts.<domain>. The id changes whenever
	// the policy file changes, which is how senders know to refetch.
	DNSFound bool   `json:"dns_found"`
	ID       string `json:"id,omitempty"`
	DNSRaw   string `json:"dns_raw,omitempty"`

	// PolicyFound and the fields below come from
	// https://mta-sts.<domain>/.well-known/mta-sts.txt.
	PolicyFound bool     `json:"policy_found"`
	Version     string   `json:"version,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	MaxAge      int64    `json:"max_age,omitempty"`
	MX          []string `json:"mx,omitempty"`
	Raw         string   `json:"raw,omitempty"`

	// FetchError covers everything that stopped the policy being read,
	// including certificate failures — a policy nobody can fetch is as good
	// as absent, and the reason matters (T10).
	//
	// A domain that simply does not do MTA-STS is not an error: when neither
	// the record nor the policy host exists, NotPublished is set and
	// FetchError stays empty, so "you don't use MTA-STS" never shows up as a
	// fault in T10.
	FetchError   string `json:"fetch_error,omitempty"`
	DNSError     string `json:"dns_error,omitempty"`
	NotPublished bool   `json:"not_published,omitempty"`
}

// TLSARecord is one TLSA RR in presentation format.
type TLSARecord struct {
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Data         string `json:"data"` // hex, upper case
}

// String renders the record the way a zone file would, which is the form
// reporters quote in policy-string for a TLSA policy.
func (r TLSARecord) String() string {
	return fmt.Sprintf("%d %d %d %s", r.Usage, r.Selector, r.MatchingType, r.Data)
}

// TLSAResult is the RRset of one MX host.
type TLSAResult struct {
	Host    string       `json:"host"`
	Records []TLSARecord `json:"records"`
	Error   string       `json:"error,omitempty"`
}

// Presentation returns the RRset as sorted presentation-format lines, so two
// lookups of an unchanged RRset produce byte-identical text and only a real
// change registers as drift.
func (r TLSAResult) Presentation() string {
	lines := make([]string, 0, len(r.Records))
	for _, rec := range r.Records {
		lines = append(lines, rec.String())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// Resolver is the DNS surface this package needs, injectable for tests.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupMX(ctx context.Context, domain string) ([]*net.MX, error)
	LookupTLSA(ctx context.Context, name string) ([]TLSARecord, error)
}

// Client performs the lookups. The zero value is usable and uses the system
// resolver plus a default HTTP client.
type Client struct {
	Resolver Resolver
	HTTP     *http.Client
}

func (c *Client) resolver() Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return systemResolver{}
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{
		Timeout: httpTimeout,
		// RFC 8461 §3.3: the policy must be fetched over HTTPS with a
		// valid certificate, and redirects are not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// LookupTLSRPT reads and parses _smtp._tls.<domain>.
func (c *Client) LookupTLSRPT(ctx context.Context, domain string) TLSRPTRecord {
	var out TLSRPTRecord
	txts, err := c.resolver().LookupTXT(ctx, "_smtp._tls."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			out.Error = err.Error()
		}
		return out
	}
	return ParseTLSRPTRecords(txts)
}

// ParseTLSRPTRecords applies the RFC 8460 §3 selection rules to a TXT RRset.
//
// Records not beginning "v=TLSRPTv1;" are discarded, and if what remains is
// not exactly one record the domain does not implement TLS-RPT. Note that Go
// already joins the character-strings of one TXT record — per the RFC they
// concatenate with nothing added between them, which is what the resolver
// does, so no space must be inserted here.
func ParseTLSRPTRecords(txts []string) TLSRPTRecord {
	var out TLSRPTRecord
	var candidates []string
	for _, txt := range txts {
		if strings.HasPrefix(strings.TrimSpace(txt), "v=TLSRPTv1;") {
			candidates = append(candidates, strings.TrimSpace(txt))
		}
	}
	out.Candidates = len(candidates)
	if len(candidates) != 1 {
		if len(candidates) > 1 {
			out.Error = fmt.Sprintf("%d TLSRPTv1 records published; RFC 8460 §3 requires exactly one", len(candidates))
		}
		return out
	}

	out.Found = true
	out.Raw = candidates[0]
	out.Extensions = map[string]string{}
	for _, field := range strings.Split(out.Raw, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "v":
		case "rua":
			for _, uri := range strings.Split(value, ",") {
				if uri = strings.TrimSpace(uri); uri != "" {
					out.RUA = append(out.RUA, uri)
				}
			}
		default:
			if key != "" {
				out.Extensions[key] = value
			}
		}
	}
	if len(out.Extensions) == 0 {
		out.Extensions = nil
	}
	if len(out.RUA) == 0 {
		out.Error = "record has no rua= destination, so no reports will be sent"
	}
	return out
}

// LookupMTASTS reads the _mta-sts TXT record and fetches the policy file.
func (c *Client) LookupMTASTS(ctx context.Context, domain string) MTASTSPolicy {
	var out MTASTSPolicy

	txts, err := c.resolver().LookupTXT(ctx, "_mta-sts."+domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			out.DNSError = err.Error()
		}
	}
	for _, txt := range txts {
		if !strings.HasPrefix(strings.TrimSpace(txt), "v=STSv1") {
			continue
		}
		out.DNSFound = true
		out.DNSRaw = strings.TrimSpace(txt)
		for _, field := range strings.Split(out.DNSRaw, ";") {
			key, value, ok := strings.Cut(field, "=")
			if ok && strings.TrimSpace(key) == "id" {
				out.ID = strings.TrimSpace(value)
			}
		}
		break
	}

	// The policy file is fetched whether or not the DNS record exists: a
	// policy served without its record is a real misconfiguration, and
	// silently skipping the fetch would hide it.
	body, err := c.fetchPolicy(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if !out.DNSFound && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// No record and no policy host: the domain does not implement
			// MTA-STS, which is a state, not a failure.
			out.NotPublished = true
			return out
		}
		out.FetchError = err.Error()
		if out.DNSFound && errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			out.FetchError = "the domain announces MTA-STS but mta-sts." + domain + " does not resolve"
		}
		return out
	}
	parsePolicyFile(body, &out)
	return out
}

func (c *Client) fetchPolicy(ctx context.Context, domain string) (string, error) {
	url := "https://mta-sts." + domain + "/.well-known/mta-sts.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPolicyLen))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parsePolicyFile reads an RFC 8461 §3.2 policy body into p.
func parsePolicyFile(body string, p *MTASTSPolicy) {
	p.Raw = strings.TrimSpace(body)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "version":
			p.Version = value
		case "mode":
			p.Mode = strings.ToLower(value)
		case "max_age":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				p.MaxAge = n
			}
		case "mx":
			if value != "" {
				p.MX = append(p.MX, strings.ToLower(value))
			}
		}
	}
	p.PolicyFound = strings.EqualFold(p.Version, "STSv1")
	if !p.PolicyFound && p.FetchError == "" {
		p.FetchError = "policy file does not declare version: STSv1"
	}
}

// LookupTLSAForDomain resolves a domain's MX hosts and looks up _25._tcp.<mx>
// for each, which is where DANE for SMTP lives (RFC 7672 §3).
func (c *Client) LookupTLSAForDomain(ctx context.Context, domain string) ([]TLSAResult, error) {
	mxs, err := c.resolver().LookupMX(ctx, domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	out := make([]TLSAResult, 0, len(mxs))
	for _, mx := range mxs {
		host := strings.TrimSuffix(strings.ToLower(mx.Host), ".")
		if host == "" {
			continue
		}
		res := TLSAResult{Host: host}
		records, err := c.resolver().LookupTLSA(ctx, "_25._tcp."+host)
		if err != nil {
			res.Error = err.Error()
		}
		res.Records = records
		out = append(out, res)
	}
	return out, nil
}

// systemResolver is the production Resolver.
type systemResolver struct{}

func (systemResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func (systemResolver) LookupMX(ctx context.Context, domain string) ([]*net.MX, error) {
	return net.DefaultResolver.LookupMX(ctx, domain)
}

// LookupTLSA queries a TLSA RRset directly.
//
// Go's resolver has no API for record types outside its fixed set, so this
// builds the query with x/net/dns/dnsmessage (already a dependency) and sends
// it to the configured nameserver over UDP, retrying on TCP when the answer
// is truncated.
func (systemResolver) LookupTLSA(ctx context.Context, name string) ([]TLSARecord, error) {
	servers := nameservers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("no nameserver configured (set DNS_SERVER, or provide /etc/resolv.conf)")
	}
	var lastErr error
	for _, server := range servers {
		records, err := queryTLSA(ctx, server, name)
		if err == nil {
			return records, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// nameservers returns the resolvers to try: DNS_SERVER when set, otherwise
// whatever /etc/resolv.conf lists.
func nameservers() []string {
	if s := strings.TrimSpace(os.Getenv("DNS_SERVER")); s != "" {
		return []string{withPort(s)}
	}
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, withPort(fields[1]))
		}
	}
	return out
}

func withPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// queryTLSA sends one TLSA query and parses the answer section.
func queryTLSA(ctx context.Context, server, name string) ([]TLSARecord, error) {
	fqdn := name
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	dnsName, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: queryID(), RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  typeTLSA,
			Class: dnsmessage.ClassINET,
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	answer, truncated, err := exchange(ctx, "udp", server, packed)
	if err != nil {
		return nil, err
	}
	if truncated {
		if answer, _, err = exchange(ctx, "tcp", server, packed); err != nil {
			return nil, err
		}
	}
	return parseTLSAAnswer(answer, msg.Header.ID)
}

// exchange sends a DNS message and returns the response bytes.
func exchange(ctx context.Context, network, server string, query []byte) (resp []byte, truncated bool, err error) {
	dialer := &net.Dialer{Timeout: dnsTimeout}
	conn, err := dialer.DialContext(ctx, network, server)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()

	deadline := time.Now().Add(dnsTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if network == "tcp" {
		// RFC 1035 §4.2.2: a two-byte length prefix.
		framed := append([]byte{byte(len(query) >> 8), byte(len(query))}, query...)
		if _, err := conn.Write(framed); err != nil {
			return nil, false, err
		}
		var lengthBuf [2]byte
		if _, err := io.ReadFull(conn, lengthBuf[:]); err != nil {
			return nil, false, err
		}
		buf := make([]byte, int(lengthBuf[0])<<8|int(lengthBuf[1]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, false, err
		}
		return buf, false, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	buf = buf[:n]

	var header dnsmessage.Parser
	h, err := header.Start(buf)
	if err != nil {
		return nil, false, err
	}
	return buf, h.Truncated, nil
}

// parseTLSAAnswer extracts the TLSA records from a response.
func parseTLSAAnswer(buf []byte, wantID uint16) ([]TLSARecord, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(buf)
	if err != nil {
		return nil, err
	}
	if header.ID != wantID {
		return nil, fmt.Errorf("dns: response id %d does not match query %d", header.ID, wantID)
	}
	switch header.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil // NXDOMAIN: no TLSA, not an error
	default:
		return nil, fmt.Errorf("dns: %s", header.RCode)
	}
	if err := parser.SkipAllQuestions(); err != nil {
		return nil, err
	}

	var out []TLSARecord
	for {
		h, err := parser.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Type != typeTLSA {
			if err := parser.SkipAnswer(); err != nil {
				return nil, err
			}
			continue
		}
		// dnsmessage has no TLSA resource type, so the RDATA comes back as
		// an unknown resource and is decoded here: one byte each of usage,
		// selector and matching type, then the association data.
		res, err := parser.UnknownResource()
		if err != nil {
			return nil, err
		}
		if len(res.Data) < 4 {
			continue
		}
		out = append(out, TLSARecord{
			Usage:        res.Data[0],
			Selector:     res.Data[1],
			MatchingType: res.Data[2],
			Data:         strings.ToUpper(hexString(res.Data[3:])),
		})
	}
	return out, nil
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// queryID returns a message ID. The value only has to differ between
// in-flight queries on one connection, which these are not — each query gets
// its own socket — so the clock is sufficient.
func queryID() uint16 {
	return uint16(time.Now().UnixNano())
}
