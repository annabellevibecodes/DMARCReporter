package bimi

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testFetcher is a Fetcher pointed at a local test server: the address guard
// and the system trust store are the two things a test cannot satisfy, and
// they are the two things production must never relax.
func testFetcher(srv *httptest.Server) *Fetcher {
	f := &Fetcher{allowPrivate: true, Timeout: 5 * time.Second}
	if srv != nil {
		pool := x509.NewCertPool()
		pool.AddCert(srv.Certificate())
		f.testRoots = pool
	}
	return f
}

func TestBlockedAddressCoversTheRangesThatMatter(t *testing.T) {
	blocked := map[string]string{
		"127.0.0.1":        "loopback",
		"::1":              "loopback",
		"0.0.0.0":          "unspecified",
		"10.1.2.3":         "private",
		"172.16.0.1":       "private",
		"192.168.1.1":      "private",
		"fd00::1":          "private",
		"169.254.169.254":  "link-local", // the cloud metadata address
		"fe80::1":          "link-local",
		"100.64.0.1":       "CGNAT",
		"224.0.0.1":        "multicast",
		"ff02::1":          "multicast",
		"::ffff:127.0.0.1": "an IPv4-mapped loopback address",
		"192.0.2.1":        "documentation",
		"198.18.0.1":       "benchmarking",
		"240.0.0.1":        "reserved",
		"2001:db8::1":      "documentation",
		"64:ff9b::7f00:1":  "NAT64",
		"2002:7f00:1::":    "6to4",
	}
	for addr, why := range blocked {
		ip := net.ParseIP(addr)
		if ip == nil {
			t.Fatalf("bad test address %q", addr)
		}
		if reason := blockedAddress(ip); reason == "" {
			t.Errorf("%s (%s) is allowed; it must not be", addr, why)
		}
	}

	for _, addr := range []string{"1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		if reason := blockedAddress(net.ParseIP(addr)); reason != "" {
			t.Errorf("%s is blocked (%s); ordinary public addresses must be reachable", addr, reason)
		}
	}
}

func TestCheckURLRefusesWhatTheSpecForbids(t *testing.T) {
	for raw, want := range map[string]string{
		"http://example.com/logo.svg":   "not HTTPS",
		"ftp://example.com/logo.svg":    "not HTTPS",
		"https://localhost/logo.svg":    "not fully qualified",
		"https://127.0.0.1/logo.svg":    "loopback",
		"https://169.254.169.254/x.svg": "link-local",
		"https://[::1]/logo.svg":        "loopback",
		"https://93.184.216.34/l.svg":   "IP address",
	} {
		err := CheckURL(raw)
		if err == nil {
			t.Errorf("CheckURL(%q) = nil, want a refusal", raw)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("CheckURL(%q) = %v, want it to mention %q", raw, err, want)
		}
	}
	if err := CheckURL("https://example.com/logo.svg"); err != nil {
		t.Errorf("a plain HTTPS URL was refused: %v", err)
	}
}

// The guard has to hold even when the hostname looks ordinary and only the
// resolved address is private — the shape of a DNS-rebinding attack.
func TestFetchRefusesPrivateAddressesAfterResolution(t *testing.T) {
	f := &Fetcher{Timeout: 5 * time.Second} // guard on, as in production
	got := f.Fetch(context.Background(), "https://localhost.example.com./logo.svg")
	if got.Err == "" {
		t.Fatal("want a refusal")
	}

	// And directly: the dial-time control is what does the refusing.
	if err := f.guardAddress("tcp4", "169.254.169.254:443", nil); err == nil {
		t.Error("the dial guard allowed the cloud metadata address")
	}
	if err := f.guardAddress("udp", "1.1.1.1:443", nil); err == nil {
		t.Error("the dial guard allowed a non-TCP connection")
	}
}

func TestFetchReadsADocument(t *testing.T) {
	body := readFixture(t, "valid.svg")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(body)
	}))
	defer srv.Close()

	got := testFetcher(srv).Fetch(context.Background(), srv.URL+"/logo.svg")
	if !got.OK() {
		t.Fatalf("fetch failed: %+v", got)
	}
	if got.Bytes != int64(len(body)) {
		t.Errorf("bytes = %d, want %d", got.Bytes, len(body))
	}
	if got.TLS == nil || got.TLS.Version == "" {
		t.Errorf("TLS session not recorded: %+v", got.TLS)
	}
	if got.ContentType != "image/svg+xml" {
		t.Errorf("content type = %q", got.ContentType)
	}
}

func TestFetchStopsAtTheRedirectCap(t *testing.T) {
	var srv *httptest.Server
	hops := 0
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		http.Redirect(w, r, srv.URL+fmt.Sprintf("/hop%d", hops), http.StatusFound)
	}))
	defer srv.Close()

	f := testFetcher(srv)
	f.MaxRedirects = 2
	got := f.Fetch(context.Background(), srv.URL+"/logo.svg")
	if got.Err == "" {
		t.Fatal("an endless redirect chain was followed to the end")
	}
	if !strings.Contains(got.Err, "redirect") {
		t.Errorf("err = %q, want it to name the redirect cap", got.Err)
	}
	if hops > 4 {
		t.Errorf("%d hops were made for a cap of 2", hops)
	}
}

// A redirect out of HTTPS is refused: the spec allows no other transport, and
// following one would leak the request in clear.
func TestFetchRefusesARedirectOutOfHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<svg/>"))
	}))
	defer plain.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/logo.svg", http.StatusFound)
	}))
	defer srv.Close()

	got := testFetcher(srv).Fetch(context.Background(), srv.URL+"/logo.svg")
	if got.Err == "" || !strings.Contains(got.Err, "HTTPS") {
		t.Errorf("err = %q, want the scheme downgrade refused", got.Err)
	}
}

// The ceiling is applied while reading, so a server that never stops sending
// cannot exhaust memory before it is noticed.
func TestFetchStopsReadingAtTheSizeCap(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("a", 4096)
		for i := 0; i < 1000; i++ {
			if _, err := w.Write([]byte(chunk)); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	f := testFetcher(srv)
	f.MaxBytes = 8 * 1024
	got := f.Fetch(context.Background(), srv.URL+"/logo.svg")
	if got.Err == "" || !strings.Contains(got.Err, "limit") {
		t.Fatalf("err = %q, want the size limit reported", got.Err)
	}
	if len(got.Body) != 0 {
		t.Errorf("an oversized body was kept: %d bytes", len(got.Body))
	}
}

// One slow host must not be able to hold up an Enrich run.
func TestFetchTimesOut(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() { close(release); srv.Close() }()

	f := testFetcher(srv)
	f.Timeout = 300 * time.Millisecond
	started := time.Now()
	got := f.Fetch(context.Background(), srv.URL+"/logo.svg")
	if got.Err == "" {
		t.Fatal("a hanging server was waited on indefinitely")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("gave up after %s, want about the configured timeout", elapsed)
	}
}

// An unverifiable chain is recorded as a TLS failure specifically, because
// §7.5 step 2 makes it a retrieval failure rather than a warning.
func TestFetchReportsAnUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<svg/>"))
	}))
	defer srv.Close()

	f := &Fetcher{allowPrivate: true, Timeout: 5 * time.Second} // no test roots
	got := f.Fetch(context.Background(), srv.URL+"/logo.svg")
	if got.TLSError == "" {
		t.Fatalf("TLS failure not recorded: %+v", got)
	}
	if got.OK() {
		t.Error("a document served over an unverifiable chain must not count as retrieved")
	}
}

// A CRL and an OCSP responder are both named with http:// URLs in practice,
// and both answer with something signed. Refusing the scheme would not make
// the check safer — it would stop it running, which is how a revocation check
// silently becomes no check at all.
func TestSignedArtefactsMayUsePlainHTTP(t *testing.T) {
	f := &Fetcher{}
	for _, raw := range []string{
		"http://crl3.digicert.com/example.crl",
		"http://ocsp.digicert.com",
		"https://ocsp.example.com",
	} {
		if err := f.checkSignedURL(raw); err != nil {
			t.Errorf("checkSignedURL(%q) = %v, want it allowed", raw, err)
		}
	}
	// The address rules still hold: only the scheme is relaxed.
	for raw, want := range map[string]string{
		"http://127.0.0.1/x.crl":       "loopback",
		"http://169.254.169.254/x.crl": "link-local",
		"http://10.0.0.1/x.crl":        "private",
		"http://localhost/x.crl":       "not fully qualified",
		"ftp://example.com/x.crl":      "not an HTTP URI",
		"file:///etc/passwd":           "not an HTTP URI",
	} {
		err := f.checkSignedURL(raw)
		if err == nil {
			t.Errorf("checkSignedURL(%q) = nil, want a refusal", raw)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("checkSignedURL(%q) = %v, want it to mention %q", raw, err, want)
		}
	}
	// And a document fetch is still HTTPS-only: the relaxation is for signed
	// artefacts alone.
	if err := CheckURL("http://example.com/logo.svg"); err == nil {
		t.Error("the indicator fetch accepted plain HTTP")
	}
}
