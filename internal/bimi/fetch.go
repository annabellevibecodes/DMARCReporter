package bimi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Retrieval limits. The byte ceilings match the upload path's (10 MB fetched,
// 50 MB decompressed) so one document cannot be made to cost more memory by
// arriving over HTTPS than by being uploaded.
const (
	// DefaultMaxRedirects is the cap the guidance draft §5.6 leaves to the
	// receiver. Three is enough for the CDN hops real deployments use and few
	// enough that a redirect loop is refused rather than followed.
	DefaultMaxRedirects = 3
	// DefaultFetchTimeout bounds one document, redirects included. The Enrich
	// run walks every domain in series, so one unreachable host must not be
	// able to stall it.
	DefaultFetchTimeout = 15 * time.Second

	maxFetchBytes        = 10 * 1024 * 1024
	maxDecompressedBytes = 50 * 1024 * 1024
)

// TLSInfo describes the TLS session a document was retrieved over. Core spec
// §7.5 step 2 makes a chain that does not validate a retrieval failure, so
// this is recorded next to the HTTP result rather than buried in an error.
type TLSInfo struct {
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	Subject     string `json:"subject"`
	Issuer      string `json:"issuer"`
	NotAfter    int64  `json:"not_after"`
}

// FetchResult is one retrieval attempt, successful or not.
//
// Every field is recorded even when the fetch failed, because "which hop
// failed" is most of the diagnosis: a 404 at the end of two redirects is a
// different problem from a refusal to leave the first host.
type FetchResult struct {
	URL         string   `json:"url"`
	FinalURL    string   `json:"final_url,omitempty"`
	Status      int      `json:"status,omitempty"`
	Redirects   []string `json:"redirects,omitempty"`
	ContentType string   `json:"content_type,omitempty"`
	Bytes       int64    `json:"bytes,omitempty"`
	TLS         *TLSInfo `json:"tls,omitempty"`
	// Err is any failure: DNS, connection, TLS, HTTP status or size.
	Err string `json:"err,omitempty"`
	// TLSError is set when the failure was specifically the certificate chain
	// of the host serving the document — not the BIMI evidence document, which
	// is a separate thing entirely.
	TLSError   string `json:"tls_error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	// Body is the retrieved bytes. Never marshalled into a snapshot: the
	// snapshot stores a hash, and a JSON column is not a file store.
	Body []byte `json:"-"`
}

// OK reports a retrieval that produced a body.
func (r FetchResult) OK() bool { return r.Err == "" && r.Status == http.StatusOK && len(r.Body) > 0 }

// Fetcher retrieves the documents a BIMI record names.
//
// Those URLs come from DNS records the operator does not control, so this is
// the one place in the application that makes outbound requests to arbitrary
// hosts. Everything about it is therefore a refusal by default: HTTPS only,
// a redirect cap, a byte ceiling applied while reading rather than after, a
// timeout on every request, and an address check that runs after DNS
// resolution on every connection, redirects included.
//
// The retrieved bytes are parsed and hashed. They are never executed,
// rendered, or served back to a browser.
type Fetcher struct {
	Timeout      time.Duration
	MaxRedirects int
	MaxBytes     int64

	// allowPrivate disables the address guard and testRoots replaces the
	// system trust store. Only this package's own tests set them, so an
	// httptest server on 127.0.0.1 with a throwaway certificate can be
	// reached; there is deliberately no exported way to turn either off, and
	// no configuration value that reaches them.
	allowPrivate bool
	testRoots    *x509.CertPool

	once   sync.Once
	client *http.Client
}

func (f *Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return DefaultFetchTimeout
}

func (f *Fetcher) maxRedirects() int {
	if f.MaxRedirects > 0 {
		return f.MaxRedirects
	}
	if f.MaxRedirects < 0 {
		return 0 // explicitly "follow none"
	}
	return DefaultMaxRedirects
}

func (f *Fetcher) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return maxFetchBytes
}

// httpClient builds the guarded client once.
func (f *Fetcher) httpClient() *http.Client {
	f.once.Do(func() {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
			// Control runs after the name has been resolved, with the address
			// actually about to be connected to. Checking here rather than on
			// the hostname is what closes the DNS-rebinding gap: a name that
			// resolved publicly a moment ago cannot smuggle a private address
			// past this, and it runs again for every redirect hop.
			Control: f.guardAddress,
		}
		f.client = &http.Client{
			Timeout: f.timeout(),
			Transport: &http.Transport{
				DialContext:           dialer.DialContext,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				// No proxy: a proxy would move the connection — and the
				// address check above — out of this process.
				Proxy: nil,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    f.testRoots,
					// InsecureSkipVerify is never set. An indicator served
					// over an unverifiable chain is a finding to report, not
					// an obstacle to work around.
				},
			},
			CheckRedirect: f.checkRedirect,
		}
	})
	return f.client
}

func (f *Fetcher) guardAddress(network, address string, _ syscall.RawConn) error {
	if !strings.HasPrefix(network, "tcp") {
		return fmt.Errorf("refusing a %s connection", network)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("refusing to connect to %q: %v", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("refusing to connect to %q: not an IP address", host)
	}
	if f.allowPrivate {
		return nil
	}
	if reason := blockedAddress(ip); reason != "" {
		return fmt.Errorf("refusing to connect to %s: %s", ip, reason)
	}
	return nil
}

func (f *Fetcher) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > f.maxRedirects() {
		return fmt.Errorf("more than %d redirects", f.maxRedirects())
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("redirect to %s is not HTTPS", redactScheme(req.URL))
	}
	return nil
}

// blockedNets are the ranges no BIMI document can legitimately live in, beyond
// the ones net.IP answers for directly. Reaching any of them means the request
// has been pointed back at the host running this application or at its
// network, which is the whole shape of an SSRF attack.
var blockedNets = []struct {
	cidr   string
	reason string
	net    *net.IPNet
}{
	{cidr: "100.64.0.0/10", reason: "carrier-grade NAT space"},
	{cidr: "192.0.0.0/24", reason: "IETF protocol assignments"},
	{cidr: "192.0.2.0/24", reason: "documentation range"},
	{cidr: "198.51.100.0/24", reason: "documentation range"},
	{cidr: "203.0.113.0/24", reason: "documentation range"},
	{cidr: "198.18.0.0/15", reason: "benchmarking range"},
	{cidr: "240.0.0.0/4", reason: "reserved range"},
	{cidr: "2001:db8::/32", reason: "documentation range"},
	{cidr: "64:ff9b::/96", reason: "NAT64 range, which maps to IPv4"},
	{cidr: "2002::/16", reason: "6to4 range, which encapsulates IPv4"},
}

func init() {
	for i := range blockedNets {
		_, n, err := net.ParseCIDR(blockedNets[i].cidr)
		if err != nil {
			panic("bimi: bad blocked CIDR " + blockedNets[i].cidr)
		}
		blockedNets[i].net = n
	}
}

// blockedAddress names the reason an address must not be connected to, or "".
func blockedAddress(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // an IPv4-mapped IPv6 address is an IPv4 address
	}
	switch {
	case ip.IsUnspecified():
		return "the unspecified address"
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local (this is where cloud metadata services live)"
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "multicast"
	case ip.IsPrivate():
		return "private address space"
	case !ip.IsGlobalUnicast():
		return "not a global unicast address"
	}
	for _, b := range blockedNets {
		if b.net.Contains(ip) {
			return b.reason
		}
	}
	return ""
}

// CheckURL applies the rules that can be judged without connecting: HTTPS
// only, a fully qualified host, and a host that is not already a literal
// address in a range we would refuse to dial.
func CheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URI: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s is not HTTPS, which the spec requires", redactScheme(u))
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("no host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := blockedAddress(ip); reason != "" {
			return fmt.Errorf("%s is %s", ip, reason)
		}
		return fmt.Errorf("%s is an IP address; the spec requires a fully qualified domain name", ip)
	}
	if !strings.Contains(strings.TrimSuffix(host, "."), ".") {
		return fmt.Errorf("%q is not fully qualified", host)
	}
	return nil
}

// checkURL is CheckURL, except that a test fetcher — which talks to a server
// on 127.0.0.1 — still requires HTTPS but not a public, fully qualified host.
// Production never takes this branch: allowPrivate has no exported setter.
func (f *Fetcher) checkURL(raw string) error {
	if !f.allowPrivate {
		return CheckURL(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a URI: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%s is not HTTPS, which the spec requires", redactScheme(u))
	}
	return nil
}

// checkSignedURL is the scheme and host policy for the two self-authenticating
// artefacts — a CRL and an OCSP response — where plain HTTP is the convention
// and the signature, not the transport, is what makes the answer trustworthy.
// Everything else the address guard enforces still applies at dial time.
func (f *Fetcher) checkSignedURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("not a URI: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s is not an HTTP URI", redactScheme(u))
	}
	if f.allowPrivate {
		return nil
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if reason := blockedAddress(ip); reason != "" {
			return fmt.Errorf("%s is %s", ip, reason)
		}
		return nil
	}
	if !strings.Contains(strings.TrimSuffix(host, "."), ".") {
		return fmt.Errorf("%q is not fully qualified", host)
	}
	return nil
}

// Fetch retrieves one document. It never returns an error: a failure is part
// of the result, because "this URL does not work" is the finding.
func (f *Fetcher) Fetch(ctx context.Context, raw string) FetchResult {
	out := FetchResult{URL: raw}
	started := time.Now()
	defer func() { out.DurationMS = time.Since(started).Milliseconds() }()

	if err := f.checkURL(raw); err != nil {
		out.Err = err.Error()
		return out
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	req.Header.Set("User-Agent", "DMARCReporter BIMI validator")
	req.Header.Set("Accept", "image/svg+xml, application/pkix-cert, application/x-pem-file, */*")

	resp, err := f.httpClient().Do(req)
	if err != nil {
		out.Err = unwrapURLError(err)
		if isTLSError(err) {
			out.TLSError = out.Err
		}
		return out
	}
	defer resp.Body.Close()

	// The redirect chain is worth keeping: a logo that works only after three
	// hops is one receiver's redirect cap away from not working at all.
	out.Redirects = redirectChain(resp)
	out.Status = resp.StatusCode
	out.FinalURL = resp.Request.URL.String()
	out.ContentType = resp.Header.Get("Content-Type")
	if resp.TLS != nil {
		out.TLS = tlsInfo(resp.TLS)
	}

	// The ceiling is applied while reading. Asking Content-Length first would
	// trust a header the far end chooses.
	limit := f.maxBytes()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		out.Err = err.Error()
		return out
	}
	if int64(len(body)) > limit {
		out.Err = fmt.Sprintf("document exceeds the %d byte limit", limit)
		out.Bytes = limit + 1
		return out
	}
	out.Body = body
	out.Bytes = int64(len(body))
	if resp.StatusCode != http.StatusOK {
		out.Err = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return out
}

func tlsInfo(state *tls.ConnectionState) *TLSInfo {
	out := &TLSInfo{
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		leaf := state.PeerCertificates[0]
		out.Subject = leaf.Subject.CommonName
		out.Issuer = leaf.Issuer.CommonName
		out.NotAfter = leaf.NotAfter.Unix()
	}
	return out
}

// redirectChain reconstructs the URLs walked, oldest first, by following the
// Request.Response links net/http leaves behind after a redirect.
func redirectChain(resp *http.Response) []string {
	var out []string
	for r := resp; r != nil && r.Request != nil; r = r.Request.Response {
		out = append([]string{r.Request.URL.String()}, out...)
	}
	if len(out) <= 1 {
		return nil // no redirect happened; the single URL is already recorded
	}
	return out
}

func isTLSError(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "x509:") ||
		strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "certificate")
}

// unwrapURLError strips the "Get \"https://…\": " prefix net/http adds, which
// repeats a URL already recorded beside the error.
func unwrapURLError(err error) string {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err.Error()
	}
	return err.Error()
}

// redactScheme renders a URL's scheme for a message without echoing the whole
// URL back into the UI.
func redactScheme(u *url.URL) string {
	if u.Scheme == "" {
		return "a URL with no scheme"
	}
	return u.Scheme
}

// post sends one request body and returns the response, under the same guards
// as Fetch. It exists for OCSP, which is a POST of a DER request to a host the
// certificate names — another third-party address, and so another address the
// SSRF guard must judge.
//
// Like a CRL, an OCSP responder URL is conventionally an http:// one, and like
// a CRL the answer is signed: the caller verifies it against the issuing
// certificate before believing a word of it, so the transport adds nothing the
// signature does not. Requiring HTTPS here would not make the check safer, it
// would only stop it running at all — which is what it did until this was
// fixed, leaving every revocation check reporting "unknown".
func (f *Fetcher) post(ctx context.Context, rawURL, contentType string, body []byte) ([]byte, error) {
	if err := f.checkSignedURL(rawURL); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "DMARCReporter BIMI validator")

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s", unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	limit := f.maxBytes()
	out, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("response exceeds the %d byte limit", limit)
	}
	return out, nil
}

// getSigned retrieves a self-authenticating artefact, allowing plain HTTP.
//
// This is the one exception to the HTTPS-only rule, and it exists for exactly
// one caller: certificate revocation lists. Every mark certificate seen in the
// wild names its CRL over http://, by long convention — a CRL is signed by the
// issuing CA and verified against it before a single field is believed, so the
// transport adds nothing that the signature does not already provide. The
// address guard, the size ceiling, the redirect cap and the timeout all still
// apply; only the scheme check is relaxed, and the caller must verify the
// signature on what comes back.
func (f *Fetcher) getSigned(ctx context.Context, rawURL string) ([]byte, error) {
	if err := f.checkSignedURL(rawURL); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DMARCReporter BIMI validator")

	resp, err := f.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s", unwrapURLError(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	limit := f.maxBytes()
	out, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(out)) > limit {
		return nil, fmt.Errorf("response exceeds the %d byte limit", limit)
	}
	return out, nil
}
