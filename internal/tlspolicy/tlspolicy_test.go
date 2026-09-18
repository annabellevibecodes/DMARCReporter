package tlspolicy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeResolver serves canned answers.
type fakeResolver struct {
	txt  map[string][]string
	mx   map[string][]*net.MX
	tlsa map[string][]TLSARecord
	err  map[string]error
}

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err, ok := f.err[name]; ok {
		return nil, err
	}
	txts, ok := f.txt[name]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	return txts, nil
}

func (f fakeResolver) LookupMX(_ context.Context, domain string) ([]*net.MX, error) {
	mxs, ok := f.mx[domain]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: domain, IsNotFound: true}
	}
	return mxs, nil
}

func (f fakeResolver) LookupTLSA(_ context.Context, name string) ([]TLSARecord, error) {
	if err, ok := f.err[name]; ok {
		return nil, err
	}
	return f.tlsa[name], nil
}

// RFC 8460 §3: exactly one v=TLSRPTv1 record, or the domain does not
// implement TLS-RPT at all.
func TestParseTLSRPTRecords(t *testing.T) {
	t.Run("one valid record", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{
			"v=spf1 -all", // an unrelated record at the same name
			"v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://example.com/report",
		})
		if !rec.Found {
			t.Fatalf("record not found: %+v", rec)
		}
		if len(rec.RUA) != 2 || rec.RUA[0] != "mailto:tlsrpt@example.com" {
			t.Errorf("rua = %v", rec.RUA)
		}
		if rec.Error != "" {
			t.Errorf("unexpected error: %q", rec.Error)
		}
	})

	t.Run("two records means not implemented", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{
			"v=TLSRPTv1; rua=mailto:a@example.com",
			"v=TLSRPTv1; rua=mailto:b@example.com",
		})
		if rec.Found {
			t.Error("two records must not count as implemented")
		}
		if rec.Candidates != 2 || rec.Error == "" {
			t.Errorf("record = %+v, want 2 candidates and an explanation", rec)
		}
	})

	t.Run("no TLSRPT record", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{"v=spf1 -all"})
		if rec.Found || rec.Candidates != 0 {
			t.Errorf("record = %+v", rec)
		}
	})

	t.Run("extensions are kept", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{"v=TLSRPTv1; rua=mailto:a@example.com; future=xyz"})
		if rec.Extensions["future"] != "xyz" {
			t.Errorf("extensions = %v", rec.Extensions)
		}
	})

	t.Run("a record with no rua is flagged", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{"v=TLSRPTv1;"})
		if !rec.Found || rec.Error == "" {
			t.Errorf("record = %+v, want found with an explanation", rec)
		}
	})

	// A TXT record split into several character-strings is joined by the
	// resolver with nothing between the parts. The parser must not assume a
	// separator was added, or a split rua= would be corrupted.
	t.Run("split character-strings concatenate without a space", func(t *testing.T) {
		rec := ParseTLSRPTRecords([]string{"v=TLSRPTv1; rua=mailto:tlsrpt@exa" + "mple.com"})
		if len(rec.RUA) != 1 || rec.RUA[0] != "mailto:tlsrpt@example.com" {
			t.Errorf("rua = %v", rec.RUA)
		}
	})
}

func TestLookupTLSRPT(t *testing.T) {
	c := &Client{Resolver: fakeResolver{txt: map[string][]string{
		"_smtp._tls.example.com": {"v=TLSRPTv1; rua=mailto:tlsrpt@example.com"},
	}}}
	if rec := c.LookupTLSRPT(context.Background(), "example.com"); !rec.Found {
		t.Errorf("record = %+v", rec)
	}
	// NXDOMAIN is "no record", not an error to report.
	rec := c.LookupTLSRPT(context.Background(), "other.example")
	if rec.Found || rec.Error != "" {
		t.Errorf("missing record = %+v, want not found with no error", rec)
	}
}

// policyServer serves an MTA-STS policy over TLS with a certificate the
// returned client trusts.
func policyServer(t *testing.T, body string, status int) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/mta-sts.txt" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	serverURL := strings.TrimPrefix(srv.URL, "https://")
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"},
		// Send every request to the test server whatever host it names.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, serverURL)
		},
	}}
	return srv, client
}

func TestLookupMTASTS(t *testing.T) {
	const policy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800\n"
	_, httpClient := policyServer(t, policy, http.StatusOK)

	c := &Client{
		Resolver: fakeResolver{txt: map[string][]string{
			"_mta-sts.example.com": {"v=STSv1; id=20260918T120000;"},
		}},
		HTTP: httpClient,
	}
	got := c.LookupMTASTS(context.Background(), "example.com")
	if !got.DNSFound || got.ID != "20260918T120000" {
		t.Errorf("dns = %+v", got)
	}
	if !got.PolicyFound || got.Mode != "enforce" || got.MaxAge != 604800 {
		t.Errorf("policy = %+v", got)
	}
	if len(got.MX) != 2 || got.MX[1] != "mx2.example.com" {
		t.Errorf("mx = %v", got.MX)
	}
	if got.FetchError != "" {
		t.Errorf("unexpected fetch error: %q", got.FetchError)
	}
}

// A policy that cannot be fetched is as good as absent, and why matters (T10).
func TestLookupMTASTSFetchFailure(t *testing.T) {
	_, httpClient := policyServer(t, "", http.StatusNotFound)
	c := &Client{
		Resolver: fakeResolver{txt: map[string][]string{
			"_mta-sts.example.com": {"v=STSv1; id=1;"},
		}},
		HTTP: httpClient,
	}
	got := c.LookupMTASTS(context.Background(), "example.com")
	if !got.DNSFound {
		t.Error("the DNS record should still be recorded")
	}
	if got.PolicyFound || got.FetchError == "" {
		t.Errorf("policy = %+v, want a fetch error", got)
	}
	if !strings.Contains(got.FetchError, "404") {
		t.Errorf("fetch error should name the status: %q", got.FetchError)
	}
}

// A policy file served without its DNS record is a real misconfiguration and
// must not be skipped just because the record is missing.
func TestLookupMTASTSPolicyWithoutDNSRecord(t *testing.T) {
	_, httpClient := policyServer(t, "version: STSv1\nmode: testing\nmx: mx.example.com\nmax_age: 86400\n", http.StatusOK)
	c := &Client{Resolver: fakeResolver{}, HTTP: httpClient}

	got := c.LookupMTASTS(context.Background(), "example.com")
	if got.DNSFound {
		t.Error("there is no DNS record to find")
	}
	if !got.PolicyFound || got.Mode != "testing" {
		t.Errorf("policy = %+v, want the file read anyway", got)
	}
}

func TestLookupTLSAForDomain(t *testing.T) {
	c := &Client{Resolver: fakeResolver{
		mx: map[string][]*net.MX{
			"example.com": {{Host: "mx1.example.com.", Pref: 10}, {Host: "MX2.example.com.", Pref: 20}},
		},
		tlsa: map[string][]TLSARecord{
			"_25._tcp.mx1.example.com": {
				{Usage: 3, Selector: 1, MatchingType: 1, Data: "BBBB"},
				{Usage: 3, Selector: 1, MatchingType: 1, Data: "AAAA"},
			},
		},
	}}

	results, err := c.LookupTLSAForDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want one per MX", len(results))
	}
	if results[0].Host != "mx1.example.com" || results[1].Host != "mx2.example.com" {
		t.Errorf("hosts = %q, %q — should be lower-cased and unrooted", results[0].Host, results[1].Host)
	}
	// Presentation is sorted, so an unchanged RRset in a different answer
	// order does not read as a change.
	want := "3 1 1 AAAA\n3 1 1 BBBB"
	if got := results[0].Presentation(); got != want {
		t.Errorf("presentation = %q, want %q", got, want)
	}
	if results[1].Presentation() != "" {
		t.Errorf("host with no TLSA should present as empty, got %q", results[1].Presentation())
	}
}

func TestLookupTLSAForDomainNoMX(t *testing.T) {
	c := &Client{Resolver: fakeResolver{}}
	results, err := c.LookupTLSAForDomain(context.Background(), "nomx.example")
	if err != nil {
		t.Fatalf("a domain with no MX is not an error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("results = %v", results)
	}
}

func TestTLSARecordString(t *testing.T) {
	r := TLSARecord{Usage: 3, Selector: 0, MatchingType: 1, Data: "ABCD"}
	if got := r.String(); got != "3 0 1 ABCD" {
		t.Errorf("String() = %q", got)
	}
}

// The DNS wire decoding is exercised directly: a TLSA answer built by hand,
// since no library type covers this record.
func TestParseTLSAAnswer(t *testing.T) {
	answer := buildTLSAResponse(t, 0x1234, [][]byte{
		{3, 1, 1, 0xAB, 0xCD},
		{2, 0, 1, 0xEF},
	})
	records, err := parseTLSAAnswer(answer, 0x1234)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v, want 2", records)
	}
	if records[0].String() != "3 1 1 ABCD" || records[1].String() != "2 0 1 EF" {
		t.Errorf("records = %q / %q", records[0], records[1])
	}

	if _, err := parseTLSAAnswer(answer, 0x9999); err == nil {
		t.Error("a mismatched transaction id must be rejected")
	}
}

func TestHexString(t *testing.T) {
	if got := hexString([]byte{0x00, 0x0f, 0xff}); got != "000fff" {
		t.Errorf("hexString = %q", got)
	}
}

func TestWithPort(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":         "1.1.1.1:53",
		"1.1.1.1:5353":    "1.1.1.1:5353",
		"2001:db8::1":     "[2001:db8::1]:53",
		"[2001:db8::1]:5": "[2001:db8::1]:5",
	}
	for in, want := range cases {
		if got := withPort(in); got != want {
			t.Errorf("withPort(%q) = %q, want %q", in, got, want)
		}
	}
}

// buildTLSAResponse assembles a DNS response carrying TLSA answers.
func buildTLSAResponse(t *testing.T, id uint16, rdatas [][]byte) []byte {
	t.Helper()
	name := "_25._tcp.mx1.example.com."

	var buf []byte
	appendUint16 := func(v uint16) { buf = append(buf, byte(v>>8), byte(v)) }
	appendName := func(n string) {
		for _, label := range strings.Split(strings.TrimSuffix(n, "."), ".") {
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
		buf = append(buf, 0)
	}

	appendUint16(id)
	appendUint16(0x8180) // response, recursion available, NOERROR
	appendUint16(1)      // questions
	appendUint16(uint16(len(rdatas)))
	appendUint16(0)
	appendUint16(0)

	appendName(name)
	appendUint16(52) // TLSA
	appendUint16(1)  // IN

	for _, rdata := range rdatas {
		appendName(name)
		appendUint16(52)
		appendUint16(1)
		appendUint16(0)
		appendUint16(300) // TTL low half
		appendUint16(uint16(len(rdata)))
		buf = append(buf, rdata...)
	}
	if len(buf) == 0 {
		t.Fatal("empty response")
	}
	return buf
}

// A domain that simply does not do MTA-STS is a state, not a failure: T10
// counts fetch errors, and "not published" must not land there.
func TestLookupMTASTSNotPublished(t *testing.T) {
	// No _mta-sts record, and the policy host does not resolve.
	c := &Client{Resolver: fakeResolver{}, HTTP: &http.Client{Transport: notFoundTransport{}}}

	got := c.LookupMTASTS(context.Background(), "nostsdomain.example")
	if !got.NotPublished {
		t.Errorf("policy = %+v, want NotPublished", got)
	}
	if got.FetchError != "" {
		t.Errorf("not publishing MTA-STS must not read as an error: %q", got.FetchError)
	}
}

// Announcing MTA-STS while the policy host does not resolve is a real
// misconfiguration, and says so in plain words.
func TestLookupMTASTSAnnouncedButUnreachable(t *testing.T) {
	c := &Client{
		Resolver: fakeResolver{txt: map[string][]string{
			"_mta-sts.example.com": {"v=STSv1; id=1;"},
		}},
		HTTP: &http.Client{Transport: notFoundTransport{}},
	}
	got := c.LookupMTASTS(context.Background(), "example.com")
	if got.NotPublished {
		t.Error("a domain announcing MTA-STS is publishing it")
	}
	if !strings.Contains(got.FetchError, "does not resolve") {
		t.Errorf("fetch error = %q, want it to name the unresolvable host", got.FetchError)
	}
}

// notFoundTransport fails every request the way an unresolvable host does.
type notFoundTransport struct{}

func (notFoundTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, &net.OpError{
		Op:  "dial",
		Err: &net.DNSError{Err: "no such host", Name: r.URL.Host, IsNotFound: true},
	}
}
