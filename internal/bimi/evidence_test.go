package bimi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The ASN.1 shapes needed to *write* a logotype extension. They mirror the
// ones evidence.go reads; a fixture built with the reader's own structures
// would prove only that the code agrees with itself.
type (
	testDetails struct {
		MediaType string `asn1:"ia5"`
		Hashes    []testHash
		// A SEQUENCE OF IA5String, built by hand: encoding/asn1 refuses to
		// apply the ia5 tag to the elements of a slice when marshalling.
		URIs asn1.RawValue
	}
	testHash struct {
		Alg   pkix.AlgorithmIdentifier
		Value []byte
	}
	testImage struct{ Details testDetails }
	testData  struct{ Image []testImage }
)

// logotypeExtension builds the RFC 3709 extension a mark certificate carries:
// a subject logo, embedded directly as a gzipped data: URI, with a hash of the
// uncompressed bytes — the shape real mark certificates use.
func logotypeExtension(t *testing.T, svg []byte, corruptHash bool) pkix.Extension {
	t.Helper()

	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(svg); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256(svg)
	digest := sum[:]
	if corruptHash {
		digest = make([]byte, len(sum))
		copy(digest, sum[:])
		digest[0] ^= 0xff
	}

	uri, err := asn1.MarshalWithParams(
		"data:image/svg+xml;base64,"+base64.StdEncoding.EncodeToString(buf.Bytes()), "ia5")
	if err != nil {
		t.Fatal(err)
	}
	uris, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: uri,
	})
	if err != nil {
		t.Fatal(err)
	}

	data := testData{Image: []testImage{{Details: testDetails{
		MediaType: "image/svg+xml",
		Hashes: []testHash{{
			Alg:   pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			Value: digest,
		}},
		URIs: asn1.RawValue{FullBytes: uris},
	}}}}

	// direct [0] LogotypeData, implicitly tagged.
	direct, err := asn1.MarshalWithParams(data, "tag:0")
	if err != nil {
		t.Fatal(err)
	}
	// subjectLogo [2] EXPLICIT LogotypeInfo.
	subject, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 2, IsCompound: true, Bytes: direct,
	})
	if err != nil {
		t.Fatal(err)
	}
	extn, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: subject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidLogotype, Value: extn}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

type leafOpts struct {
	CommonName  string
	DNSNames    []string
	NotBefore   time.Time
	NotAfter    time.Time
	Mark        []byte
	CorruptHash bool
	NoLogotype  bool
}

// issue returns the PEM bundle a domain would publish at a=: the mark
// certificate first, then its issuer.
func (ca *testCA) issue(t *testing.T, opts leafOpts) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if opts.NotBefore.IsZero() {
		opts.NotBefore = time.Now().Add(-time.Hour)
	}
	if opts.NotAfter.IsZero() {
		opts.NotAfter = time.Now().AddDate(1, 0, 0)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   opts.CommonName,
			Organization: []string{"Example, Inc."},
		},
		NotBefore: opts.NotBefore,
		NotAfter:  opts.NotAfter,
		DNSNames:  opts.DNSNames,
	}
	if !opts.NoLogotype {
		mark := opts.Mark
		if mark == nil {
			t.Fatal("a mark is required unless NoLogotype is set")
		}
		tmpl.ExtraExtensions = []pkix.Extension{logotypeExtension(t, mark, opts.CorruptHash)}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for _, b := range [][]byte{der, ca.cert.Raw} {
		if err := pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: b}); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

// serve publishes a body over TLS and returns a fetcher that trusts it.
func serve(t *testing.T, contentType string, body []byte) (*httptest.Server, *Fetcher) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv, testFetcher(srv)
}

func evidenceCodes(r EvidenceResult) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasEvidenceCode(r EvidenceResult, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestFetchEvidenceHealthyDocument(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test Mark Verifying Authority")
	bundle := ca.issue(t, leafOpts{CommonName: "Example, Inc.", DNSNames: []string{"example.com"}, Mark: svg})
	srv, f := serve(t, "application/pem-certificate-chain", bundle)

	got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", ExpiryWarnDays: 30,
	})
	if !got.Valid {
		t.Fatalf("a healthy document did not validate: %v", evidenceCodes(got))
	}
	if !got.Trusted {
		t.Errorf("trusted = false: %s", got.TrustError)
	}
	if !got.CoversRecordDomain {
		t.Errorf("SANs %v did not cover example.com", got.SANs)
	}
	if got.Certificates != 2 {
		t.Errorf("certificates = %d, want the leaf and its issuer", got.Certificates)
	}
	if got.Mark == nil {
		t.Fatal("no mark extracted")
	}
	if !got.Mark.Compressed {
		t.Error("the mark was gzipped in the certificate; that should be recorded")
	}
	if !got.Mark.HashMatches {
		t.Error("the certificate's own hash of its mark did not match")
	}
	if !got.Mark.SVGPS.Valid {
		t.Errorf("the embedded mark failed SVG P/S: %v", findingCodes(got.Mark.SVGPS))
	}
	if got.DaysToExpiry < 300 {
		t.Errorf("days to expiry = %d", got.DaysToExpiry)
	}
}

func TestFetchEvidenceExpiryStates(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test MVA")

	t.Run("expired", func(t *testing.T) {
		bundle := ca.issue(t, leafOpts{
			CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg,
			NotBefore: time.Now().AddDate(-2, 0, 0), NotAfter: time.Now().AddDate(0, 0, -1),
		})
		srv, f := serve(t, "", bundle)
		got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", ExpiryWarnDays: 30,
		})
		if got.Valid || !hasEvidenceCode(got, "evidence_expired") {
			t.Errorf("findings = %v, want an expiry breach", evidenceCodes(got))
		}
		if got.DaysToExpiry >= 0 {
			t.Errorf("days to expiry = %d, want a negative runway", got.DaysToExpiry)
		}
	})

	t.Run("expiring soon", func(t *testing.T) {
		bundle := ca.issue(t, leafOpts{
			CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg,
			NotAfter: time.Now().AddDate(0, 0, 10),
		})
		srv, f := serve(t, "", bundle)
		got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", ExpiryWarnDays: 30,
		})
		if !hasEvidenceCode(got, "evidence_expiring") {
			t.Errorf("findings = %v, want the expiry runway reported", evidenceCodes(got))
		}
		// Expiring is a warning: the logo still shows today.
		if !got.Valid {
			t.Errorf("an expiring document must stay valid: %v", evidenceCodes(got))
		}
	})
}

func TestFetchEvidenceUntrustedChain(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	real, other := newTestCA(t, "Test MVA"), newTestCA(t, "Someone Else")
	bundle := other.issue(t, leafOpts{CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg})
	srv, f := serve(t, "", bundle)

	got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: real.pool, RootSource: RootsMVA, RecordDomain: "example.com",
	})
	if got.Trusted || got.Valid {
		t.Fatalf("a document from an unknown issuer was trusted: %v", evidenceCodes(got))
	}
	if !hasEvidenceCode(got, "evidence_untrusted") {
		t.Errorf("findings = %v, want the trust failure named", evidenceCodes(got))
	}
	// Against the OS bundle the message must say so, because it is a weaker
	// claim than a Mark Verifying Authority list.
	got = FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: x509.NewCertPool(), RootSource: RootsSystem, RecordDomain: "example.com",
	})
	for _, fnd := range got.Findings {
		if fnd.Code == "evidence_untrusted" && !strings.Contains(fnd.Message, "BIMI_ROOTS_PATH") {
			t.Errorf("message does not explain the weaker claim: %q", fnd.Message)
		}
	}
}

// Guidance draft §7.3: the SANs must cover the domain whose record names the
// document, which is not necessarily the domain in the subject.
func TestFetchEvidenceSANCoverage(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test MVA")
	bundle := ca.issue(t, leafOpts{
		CommonName: "Example", DNSNames: []string{"example.net", "*.example.org"}, Mark: svg,
	})
	srv, f := serve(t, "", bundle)

	got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
	})
	if got.CoversRecordDomain || !hasEvidenceCode(got, "evidence_domain_not_covered") {
		t.Errorf("findings = %v, want the uncovered domain reported", evidenceCodes(got))
	}

	// A wildcard SAN covers one label below it, as it does in TLS.
	got = FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "mail.example.org",
	})
	if !got.CoversRecordDomain {
		t.Errorf("SANs %v should cover mail.example.org", got.SANs)
	}
	// But not two labels below.
	if sansCover([]string{"*.example.org"}, "a.mail.example.org") {
		t.Error("a wildcard must cover exactly one label")
	}
}

func TestFetchEvidenceMarkProblems(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test MVA")

	t.Run("no logotype extension", func(t *testing.T) {
		bundle := ca.issue(t, leafOpts{CommonName: "Example", DNSNames: []string{"example.com"}, NoLogotype: true})
		srv, f := serve(t, "", bundle)
		got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
		})
		if got.Valid || !hasEvidenceCode(got, "evidence_no_mark") {
			t.Errorf("findings = %v, want the missing mark reported", evidenceCodes(got))
		}
	})

	t.Run("certificate disagrees with its own mark", func(t *testing.T) {
		bundle := ca.issue(t, leafOpts{
			CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg, CorruptHash: true,
		})
		srv, f := serve(t, "", bundle)
		got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
		})
		if got.Valid || !hasEvidenceCode(got, "evidence_mark_hash") {
			t.Errorf("findings = %v, want the internal hash mismatch reported", evidenceCodes(got))
		}
	})

	t.Run("the embedded mark is not SVG P/S", func(t *testing.T) {
		bundle := ca.issue(t, leafOpts{
			CommonName: "Example", DNSNames: []string{"example.com"}, Mark: readFixture(t, "raster.svg"),
		})
		srv, f := serve(t, "", bundle)
		got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
		})
		if got.Valid {
			t.Errorf("findings = %v, want the embedded mark's breach to count", evidenceCodes(got))
		}
		if !hasEvidenceCode(got, "evidence_mark_element") {
			t.Errorf("findings = %v, want the SVG finding carried through", evidenceCodes(got))
		}
	})
}

func TestFetchEvidenceUnreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()
	got := FetchEvidence(context.Background(), testFetcher(srv), srv.URL+"/vmc.pem", EvidenceOptions{})
	if got.Valid || !hasEvidenceCode(got, "evidence_unreachable") {
		t.Errorf("findings = %v, want the retrieval failure reported", evidenceCodes(got))
	}
}

// B9. The mark served at l= and the mark inside a= must be the same bytes;
// this is the failure no other check here can see.
func TestCompareMarks(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	other := bytes.Replace(svg, []byte("teal"), []byte("olive"), 1)
	ca := newTestCA(t, "Test MVA")

	bundle := ca.issue(t, leafOpts{CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg})
	certSrv, certFetcher := serve(t, "", bundle)
	evidence := FetchEvidence(context.Background(), certFetcher, certSrv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
	})
	if evidence.Mark == nil {
		t.Fatal("no mark in the evidence document")
	}

	t.Run("agreement", func(t *testing.T) {
		logoSrv, logoFetcher := serve(t, "image/svg+xml", svg)
		ind := FetchIndicator(context.Background(), logoFetcher, logoSrv.URL+"/logo.svg")
		got := CompareMarks(&ind, &evidence)
		if !got.Checked || !got.Matches {
			t.Fatalf("identical marks did not agree: %+v", got)
		}
		if _, ok := got.Finding(); ok {
			t.Error("agreement produced a finding")
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		logoSrv, logoFetcher := serve(t, "image/svg+xml", other)
		ind := FetchIndicator(context.Background(), logoFetcher, logoSrv.URL+"/logo.svg")
		got := CompareMarks(&ind, &evidence)
		if !got.Checked || got.Matches {
			t.Fatalf("a different logo was reported as matching: %+v", got)
		}
		fnd, ok := got.Finding()
		if !ok || fnd.Severity != SeverityError {
			t.Fatalf("finding = %+v, ok = %v; a mismatch is a breach", fnd, ok)
		}
		if !strings.Contains(fnd.Message, "§7.9") {
			t.Errorf("message does not cite the rule: %q", fnd.Message)
		}
	})

	t.Run("nothing to compare", func(t *testing.T) {
		logoSrv, logoFetcher := serve(t, "image/svg+xml", svg)
		ind := FetchIndicator(context.Background(), logoFetcher, logoSrv.URL+"/logo.svg")
		got := CompareMarks(&ind, nil)
		if got.Checked || got.Matches {
			t.Errorf("%+v: with no evidence document there is nothing to compare", got)
		}
		if got.Note == "" {
			t.Error("want the reason recorded")
		}
	})
}

func TestRevocationIsNotSilentlySkipped(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test MVA")
	bundle := ca.issue(t, leafOpts{CommonName: "Example", DNSNames: []string{"example.com"}, Mark: svg})
	srv, f := serve(t, "", bundle)

	// Switched off: reported as unchecked, not as good.
	got := FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com",
	})
	if got.Revocation.Status != "unchecked" || got.Revocation.Revoked {
		t.Errorf("revocation = %+v, want unchecked", got.Revocation)
	}
	if !hasEvidenceCode(got, "evidence_revocation_unchecked") {
		t.Errorf("findings = %v, want the unchecked state visible", evidenceCodes(got))
	}
	// An unchecked revocation is information, not a breach.
	if !got.Valid {
		t.Errorf("findings = %v, want the document still valid", evidenceCodes(got))
	}

	// Switched on, but the certificate names no responder: still unchecked,
	// with the reason.
	got = FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", CheckRevocation: true,
	})
	if got.Revocation.Status != "unchecked" || !strings.Contains(got.Revocation.Err, "OCSP") {
		t.Errorf("revocation = %+v, want the missing responder explained", got.Revocation)
	}
}

// crlFor builds a signed revocation list naming the given serials.
func (ca *testCA) crlFor(t *testing.T, revoked []*big.Int, nextUpdate time.Time) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, serial := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.Now().Add(-time.Hour),
			ReasonCode:     1, // key compromise
		})
	}
	// A list published in the past must still have been published before it
	// expired, which is what makes the stale case constructible at all.
	thisUpdate := time.Now().Add(-time.Hour)
	if !nextUpdate.After(thisUpdate) {
		thisUpdate = nextUpdate.Add(-24 * time.Hour)
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Mark certificates as issued today name a CRL and no OCSP responder, so the
// CRL path is the one that actually runs in production.
func TestRevocationViaCRL(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca := newTestCA(t, "Test MVA")

	// One server serves both the certificate bundle and the CRL, so the
	// certificate can name a CRL URL that resolves.
	var srv *httptest.Server
	var bundle, crl []byte
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".crl") {
			w.Write(crl)
			return
		}
		w.Write(bundle)
	}))
	defer srv.Close()
	f := testFetcher(srv)

	issue := func(revoke bool, nextUpdate time.Time) EvidenceResult {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: "Example"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			DNSNames:              []string{"example.com"},
			CRLDistributionPoints: []string{srv.URL + "/mva.crl"},
			ExtraExtensions:       []pkix.Extension{logotypeExtension(t, svg, false)},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		for _, b := range [][]byte{der, ca.cert.Raw} {
			pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b})
		}
		bundle = buf.Bytes()

		var serials []*big.Int
		if revoke {
			serials = append(serials, tmpl.SerialNumber)
		}
		crl = ca.crlFor(t, serials, nextUpdate)

		return FetchEvidence(context.Background(), f, srv.URL+"/vmc.pem", EvidenceOptions{
			Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", CheckRevocation: true,
		})
	}

	t.Run("not revoked", func(t *testing.T) {
		got := issue(false, time.Now().AddDate(0, 0, 7))
		if got.Revocation.Status != "good" || got.Revocation.Revoked {
			t.Fatalf("revocation = %+v, want good", got.Revocation)
		}
		if !got.Valid {
			t.Errorf("findings = %v", evidenceCodes(got))
		}
	})

	t.Run("revoked", func(t *testing.T) {
		got := issue(true, time.Now().AddDate(0, 0, 7))
		if !got.Revocation.Revoked || got.Revocation.Status != "revoked" {
			t.Fatalf("revocation = %+v, want revoked", got.Revocation)
		}
		if got.Valid || !hasEvidenceCode(got, "evidence_revoked") {
			t.Errorf("findings = %v, want a revoked document to be invalid", evidenceCodes(got))
		}
		if !strings.Contains(got.Revocation.Reason, "key compromise") {
			t.Errorf("reason = %q, want the code decoded", got.Revocation.Reason)
		}
	})

	// A list nobody has refreshed is not an answer, and must not read as one.
	t.Run("stale list", func(t *testing.T) {
		got := issue(false, time.Now().AddDate(0, 0, -1))
		if got.Revocation.Status != "unknown" {
			t.Fatalf("revocation = %+v, want unknown for an expired list", got.Revocation)
		}
		if !hasEvidenceCode(got, "evidence_revocation_unknown") {
			t.Errorf("findings = %v, want the uncertainty surfaced", evidenceCodes(got))
		}
	})
}

// A revocation list that is not signed by the issuer tells us nothing, and
// "nothing" must not be rounded up to "not revoked".
func TestRevocationRejectsAnUnsignedList(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	ca, impostor := newTestCA(t, "Test MVA"), newTestCA(t, "Impostor")

	var srv *httptest.Server
	var bundle, crl []byte
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".crl") {
			w.Write(crl)
			return
		}
		w.Write(bundle)
	}))
	defer srv.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		DNSNames:              []string{"example.com"},
		CRLDistributionPoints: []string{srv.URL + "/mva.crl"},
		ExtraExtensions:       []pkix.Extension{logotypeExtension(t, svg, false)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	for _, b := range [][]byte{der, ca.cert.Raw} {
		pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: b})
	}
	bundle = buf.Bytes()
	// Signed by someone else entirely, and claiming the certificate is fine.
	crl = impostor.crlFor(t, nil, time.Now().AddDate(0, 0, 7))

	got := FetchEvidence(context.Background(), testFetcher(srv), srv.URL+"/vmc.pem", EvidenceOptions{
		Roots: ca.pool, RootSource: RootsMVA, RecordDomain: "example.com", CheckRevocation: true,
	})
	if got.Revocation.Status != "unknown" || got.Revocation.Revoked {
		t.Fatalf("revocation = %+v, want unknown", got.Revocation)
	}
	if !strings.Contains(got.Revocation.Err, "not signed by") {
		t.Errorf("err = %q, want the signature failure named", got.Revocation.Err)
	}
}
