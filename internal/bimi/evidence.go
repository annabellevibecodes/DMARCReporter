package bimi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

// oidLogotype is the RFC 3709 logotype extension. A mark certificate carries
// the brand's mark inside it, which is what makes B9 — "is the logo you serve
// the logo the certificate vouches for?" — answerable at all.
var oidLogotype = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 12}

// Root-of-trust sources, reported in the UI because they are not equally
// strong claims. Receivers commonly keep a dedicated list of Mark Verifying
// Authority roots (guidance draft §10.2); "valid against the operating
// system's bundle" is a weaker statement than "valid against the roots
// receivers actually use", and must not be shown as though it were the same.
const (
	RootsMVA    = "mva"
	RootsSystem = "system"
)

// EvidenceOptions configures one evidence-document check.
type EvidenceOptions struct {
	// Roots is the pool to verify against; nil means the system pool.
	Roots      *x509.CertPool
	RootSource string
	// RecordDomain is the domain the BIMI record was found at. Guidance draft
	// §7.3: the certificate's SANs must cover it.
	RecordDomain string
	// ExpiryWarnDays is the runway below which expiry becomes a finding.
	ExpiryWarnDays int
	// CheckRevocation enables the OCSP query. It is a second outbound request
	// to a third-party host, so it is opt-in rather than assumed.
	CheckRevocation bool
	Now             time.Time
}

// EmbeddedMark is the mark carried inside the evidence document.
type EmbeddedMark struct {
	MediaType  string `json:"media_type,omitempty"`
	Bytes      int    `json:"bytes,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Compressed bool   `json:"compressed"`
	// HashAlg and HashMatches record the certificate's own hash of the mark,
	// checked against the mark actually extracted. A mismatch means the
	// certificate disagrees with itself.
	HashAlg     string      `json:"hash_alg,omitempty"`
	HashMatches bool        `json:"hash_matches"`
	SVGPS       SVGPSResult `json:"svgps"`
	Err         string      `json:"err,omitempty"`
}

// RevocationResult is what an OCSP query said, or why none was made.
type RevocationResult struct {
	Status    string `json:"status"` // good | revoked | unknown | unchecked
	Revoked   bool   `json:"revoked"`
	Reason    string `json:"reason,omitempty"`
	Responder string `json:"responder,omitempty"`
	At        int64  `json:"at,omitempty"`
	Err       string `json:"err,omitempty"`
}

// EvidenceResult is B8 for one document.
type EvidenceResult struct {
	Fetch        FetchResult `json:"fetch"`
	Certificates int         `json:"certificates"`
	Subject      string      `json:"subject,omitempty"`
	SubjectOrg   string      `json:"subject_org,omitempty"`
	Issuer       string      `json:"issuer,omitempty"`
	Serial       string      `json:"serial,omitempty"`
	NotBefore    int64       `json:"not_before,omitempty"`
	NotAfter     int64       `json:"not_after,omitempty"`
	DaysToExpiry int         `json:"days_to_expiry"`
	SANs         []string    `json:"sans,omitempty"`
	// CoversRecordDomain is guidance draft §7.3: whether the certificate's
	// SANs cover the domain the BIMI record was found at.
	CoversRecordDomain bool             `json:"covers_record_domain"`
	Fingerprint        string           `json:"fingerprint,omitempty"`
	Chain              []string         `json:"chain,omitempty"`
	Trusted            bool             `json:"trusted"`
	TrustError         string           `json:"trust_error,omitempty"`
	RootSource         string           `json:"root_source,omitempty"`
	Mark               *EmbeddedMark    `json:"mark,omitempty"`
	Revocation         RevocationResult `json:"revocation"`
	Findings           []Finding        `json:"findings,omitempty"`
	// Valid is true when nothing found is an outright breach.
	Valid bool `json:"valid"`
}

// LoadRoots reads a PEM bundle of trusted roots. An empty path returns nil,
// meaning the caller should use the system pool — and say so.
func LoadRoots(path string) (*x509.CertPool, string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, RootsSystem, nil
	}
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, RootsSystem, fmt.Errorf("read BIMI roots: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, RootsSystem, fmt.Errorf("no certificates found in %s", path)
	}
	return pool, RootsMVA, nil
}

// FetchEvidence retrieves and inspects the document at a=.
func FetchEvidence(ctx context.Context, f *Fetcher, rawURL string, opts EvidenceOptions) EvidenceResult {
	out := EvidenceResult{RootSource: opts.RootSource}
	if out.RootSource == "" {
		out.RootSource = RootsSystem
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	add := func(severity, code, format string, args ...any) {
		out.Findings = append(out.Findings, Finding{
			Code: code, Severity: severity, Message: fmt.Sprintf(format, args...),
		})
	}

	out.Fetch = f.Fetch(ctx, rawURL)
	if !out.Fetch.OK() {
		add(SeverityError, "evidence_unreachable",
			"the evidence document could not be retrieved: %s", fetchFailure(out.Fetch))
		return out
	}

	certs, err := parseCertChain(out.Fetch.Body)
	if err != nil {
		add(SeverityError, "evidence_unparseable", "%v", err)
		return out
	}
	out.Certificates = len(certs)
	leaf := certs[0]

	sum := sha256.Sum256(leaf.Raw)
	out.Fingerprint = hex.EncodeToString(sum[:])
	out.Subject = leaf.Subject.CommonName
	if len(leaf.Subject.Organization) > 0 {
		out.SubjectOrg = leaf.Subject.Organization[0]
	}
	out.Issuer = leaf.Issuer.CommonName
	out.Serial = leaf.SerialNumber.String()
	out.NotBefore = leaf.NotBefore.Unix()
	out.NotAfter = leaf.NotAfter.Unix()
	out.DaysToExpiry = int(leaf.NotAfter.Sub(now).Hours() / 24)
	out.SANs = append(out.SANs, leaf.DNSNames...)
	for _, c := range certs {
		out.Chain = append(out.Chain, describeCert(c))
	}

	switch {
	case now.After(leaf.NotAfter):
		add(SeverityError, "evidence_expired",
			"the evidence document expired on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	case now.Before(leaf.NotBefore):
		add(SeverityError, "evidence_not_yet_valid",
			"the evidence document is not valid until %s", leaf.NotBefore.UTC().Format("2006-01-02"))
	case opts.ExpiryWarnDays > 0 && out.DaysToExpiry <= opts.ExpiryWarnDays:
		add(SeverityWarning, "evidence_expiring",
			"the evidence document expires in %d day(s), on %s",
			out.DaysToExpiry, leaf.NotAfter.UTC().Format("2006-01-02"))
	}

	// Chain verification. Intermediates come from the bundle itself, which is
	// how a mark certificate is published: leaf first, then its issuers.
	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// A mark certificate carries no TLS extended key usage, so asking for
		// one would reject every valid document.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	switch {
	case err == nil:
		out.Trusted = true
	default:
		out.TrustError = err.Error()
		if out.RootSource == RootsMVA {
			add(SeverityError, "evidence_untrusted",
				"the evidence document does not chain to any root in the configured Mark Verifying Authority bundle: %v", err)
		} else {
			add(SeverityError, "evidence_untrusted",
				"the evidence document does not chain to a trusted root: %v. Note that this was checked against the operating system's bundle, not a Mark Verifying Authority list — set BIMI_ROOTS_PATH to check what receivers actually check", err)
		}
	}

	// Guidance draft §7.3: the SANs must cover the domain used in the BIMI
	// assertion record, which is not necessarily the From domain.
	if opts.RecordDomain != "" {
		out.CoversRecordDomain = sansCover(out.SANs, opts.RecordDomain)
		if !out.CoversRecordDomain {
			add(SeverityError, "evidence_domain_not_covered",
				"the certificate covers %s but not %s, the domain whose BIMI record points at it",
				orNoneList(out.SANs), opts.RecordDomain)
		}
	}

	mark, err := extractMark(leaf)
	switch {
	case err != nil:
		add(SeverityError, "evidence_no_mark",
			"no usable mark could be read from the evidence document: %v", err)
	default:
		out.Mark = mark
		if mark.Err != "" {
			add(SeverityError, "evidence_no_mark", "%s", mark.Err)
		} else {
			if !mark.HashMatches {
				add(SeverityError, "evidence_mark_hash",
					"the %s hash the certificate records for its own mark does not match the mark embedded in it",
					strings.ToUpper(mark.HashAlg))
			}
			for _, fnd := range mark.SVGPS.Findings {
				out.Findings = append(out.Findings, Finding{
					Code:     "evidence_mark_" + strings.TrimPrefix(fnd.Code, "svgps_"),
					Severity: fnd.Severity,
					Message:  "the mark inside the evidence document: " + fnd.Message,
				})
			}
		}
	}

	out.Revocation = checkRevocation(ctx, f, certs, opts)
	switch out.Revocation.Status {
	case "revoked":
		add(SeverityError, "evidence_revoked",
			"the evidence document has been revoked%s", reasonSuffix(out.Revocation.Reason))
	case "unchecked":
		add(SeverityInfo, "evidence_revocation_unchecked",
			"revocation was not checked: %s", orText(out.Revocation.Err, "no OCSP responder is available for this certificate"))
	case "unknown":
		add(SeverityWarning, "evidence_revocation_unknown",
			"the OCSP responder could not say whether this certificate is revoked: %s", out.Revocation.Err)
	}

	out.Valid = true
	for _, fnd := range out.Findings {
		if fnd.Severity == SeverityError {
			out.Valid = false
		}
	}
	return out
}

// parseCertChain reads a PEM bundle, leaf first. A DER-encoded single
// certificate is accepted too: some hosts serve the document that way, and
// refusing it would report a configuration problem that is not there.
func parseCertChain(body []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := body
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate in the bundle does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		if certs, err := x509.ParseCertificates(body); err == nil && len(certs) > 0 {
			return certs, nil
		}
		return nil, fmt.Errorf("the document contains no PEM certificate")
	}
	return out, nil
}

// RFC 3709 logotype structures.
//
// LogotypeInfo is an ASN.1 CHOICE, which encoding/asn1 cannot express as a
// struct field: it would need the alternative's tag to replace the SEQUENCE
// tag, and an optional struct field that does not match is simply left empty
// rather than reported. So the outer SEQUENCE is walked by hand (markDetails)
// and only the parts that are ordinary SEQUENCEs are unmarshalled.
type logotypeData struct {
	Image []logotypeImage `asn1:"optional"`
	Audio asn1.RawValue   `asn1:"optional,tag:1"`
}

type logotypeImage struct {
	Details   logotypeDetails
	ImageInfo asn1.RawValue `asn1:"optional"`
}

type logotypeDetails struct {
	MediaType string `asn1:"ia5"`
	Hashes    []hashAlgAndValue
	URIs      []string `asn1:"ia5"`
}

type hashAlgAndValue struct {
	Alg   pkix.AlgorithmIdentifier
	Value []byte
}

// extractMark reads the mark out of the certificate's logotype extension.
//
// The mark is carried as a data: URI whose payload is the image, gzipped in
// every certificate seen in the wild. The certificate also records a hash of
// the *uncompressed* image, which is checked here: a certificate whose own
// hash does not match its own mark is broken in a way nothing else surfaces.
func extractMark(cert *x509.Certificate) (*EmbeddedMark, error) {
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidLogotype) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("the certificate carries no logotype extension (%s), so it vouches for no mark", oidLogotype)
	}

	details, err := markDetails(raw)
	if err != nil {
		return nil, err
	}

	out := &EmbeddedMark{MediaType: details.MediaType}
	data, err := markBytes(details.URIs)
	if err != nil {
		out.Err = err.Error()
		return out, nil
	}
	if gz, ok := gunzipBytes(data); ok {
		out.Compressed = true
		data = gz
	}
	out.Bytes = len(data)
	sum := sha256.Sum256(data)
	out.SHA256 = hex.EncodeToString(sum[:])

	if len(details.Hashes) > 0 {
		h := details.Hashes[0]
		name, digest, err := digestFor(h.Alg.Algorithm, data)
		if err != nil {
			out.HashAlg = h.Alg.Algorithm.String()
			out.Err = err.Error()
		} else {
			out.HashAlg = name
			out.HashMatches = bytes.Equal(digest, h.Value)
		}
	} else {
		// Nothing to check against; saying "matches" would be a claim the
		// certificate never made.
		out.HashAlg = "none"
		out.HashMatches = true
	}

	if strings.Contains(strings.ToLower(out.MediaType), "svg") {
		out.SVGPS = ValidateSVGPS(data)
	}
	return out, nil
}

// markDetails finds the image details inside a logotype extension, preferring
// the subject logo — the brand's own mark — over the issuer's or a community
// logo, which describe the authority rather than the sender.
func markDetails(raw []byte) (logotypeDetails, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(raw, &seq); err != nil {
		return logotypeDetails{}, fmt.Errorf("the logotype extension does not decode: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return logotypeDetails{}, fmt.Errorf("the logotype extension is not a SEQUENCE")
	}

	// LogotypeExtn's four fields are context-tagged: 0 community, 1 issuer,
	// 2 subject, 3 other.
	slots := map[int][]byte{}
	for rest := seq.Bytes; len(rest) > 0; {
		var v asn1.RawValue
		next, err := asn1.Unmarshal(rest, &v)
		if err != nil {
			break
		}
		rest = next
		if v.Class == asn1.ClassContextSpecific {
			slots[v.Tag] = v.Bytes
		}
	}

	for _, tag := range []int{2, 1, 0} {
		body, ok := slots[tag]
		if !ok {
			continue
		}
		if tag == 0 {
			// communityLogos is a SEQUENCE OF LogotypeInfo.
			var inner asn1.RawValue
			if _, err := asn1.Unmarshal(body, &inner); err != nil || inner.Tag != asn1.TagSequence {
				continue
			}
			for rest := inner.Bytes; len(rest) > 0; {
				var one asn1.RawValue
				next, err := asn1.Unmarshal(rest, &one)
				if err != nil {
					break
				}
				rest = next
				if d, ok := directDetails(one.FullBytes); ok {
					return d, nil
				}
			}
			continue
		}
		if d, ok := directDetails(body); ok {
			return d, nil
		}
	}
	return logotypeDetails{}, fmt.Errorf("the logotype extension carries no directly embedded image")
}

// directDetails reads the "direct" alternative of a LogotypeInfo: an implicit
// context-0 wrapper around LogotypeData.
func directDetails(b []byte) (logotypeDetails, bool) {
	var data logotypeData
	if _, err := asn1.UnmarshalWithParams(b, &data, "tag:0"); err != nil {
		return logotypeDetails{}, false
	}
	if len(data.Image) == 0 {
		return logotypeDetails{}, false
	}
	return data.Image[0].Details, true
}

// markBytes decodes the first usable logotype URI. Only data: URIs are read:
// an http(s) URI would mean a second fetch to a host the certificate names,
// and the mark that matters for B9 is the one the certificate carries.
func markBytes(uris []string) ([]byte, error) {
	if len(uris) == 0 {
		return nil, fmt.Errorf("the logotype extension carries no URI")
	}
	for _, uri := range uris {
		if !strings.HasPrefix(strings.ToLower(uri), "data:") {
			continue
		}
		_, payload, ok := strings.Cut(uri, ",")
		if !ok {
			return nil, fmt.Errorf("the logotype data URI has no payload")
		}
		meta := strings.ToLower(uri[:strings.Index(uri, ",")])
		if strings.Contains(meta, ";base64") {
			out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
			if err != nil {
				return nil, fmt.Errorf("the logotype data URI is not valid base64: %w", err)
			}
			return out, nil
		}
		unescaped, err := url.PathUnescape(payload)
		if err != nil {
			return nil, fmt.Errorf("the logotype data URI does not decode: %w", err)
		}
		return []byte(unescaped), nil
	}
	return nil, fmt.Errorf("the logotype extension references %s rather than embedding the mark, so the certificate vouches for a mark this check cannot see",
		truncate(uris[0], 60))
}

// gunzipBytes decompresses data when it is gzipped, bounded by the same
// ceiling the upload path uses.
func gunzipBytes(data []byte) ([]byte, bool) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return nil, false
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxDecompressedBytes+1))
	if err != nil || int64(len(out)) > maxDecompressedBytes {
		return nil, false
	}
	return out, true
}

// sansCover reports whether any subject alternative name covers domain,
// honouring a single leading wildcard label as TLS does.
func sansCover(sans []string, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	for _, san := range sans {
		san = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(san), "."))
		if san == domain {
			return true
		}
		// A single leading wildcard covers exactly one label, as it does in TLS.
		if suffix, ok := strings.CutPrefix(san, "*."); ok {
			if idx := strings.IndexByte(domain, '.'); idx >= 0 && domain[idx+1:] == suffix {
				return true
			}
		}
	}
	return false
}

func describeCert(c *x509.Certificate) string {
	name := c.Subject.CommonName
	if name == "" && len(c.Subject.Organization) > 0 {
		name = c.Subject.Organization[0]
	}
	if name == "" {
		name = c.Subject.String()
	}
	return name
}

func fetchFailure(r FetchResult) string {
	switch {
	case r.Err != "":
		return r.Err
	case r.Status != 0 && r.Status != 200:
		return fmt.Sprintf("HTTP %d", r.Status)
	case len(r.Body) == 0:
		return "the response was empty"
	}
	return "unknown error"
}

func orText(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func orNoneList(v []string) string {
	if len(v) == 0 {
		return "no domains"
	}
	return strings.Join(v, ", ")
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

// Hash algorithm OIDs a logotype hash can name.
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// digestFor hashes data with the algorithm an OID names. SHA-1 is accepted
// here because RFC 3709 predates its retirement and real mark certificates
// still use it; it is only ever used to compare a certificate against its own
// contents, never to establish trust.
func digestFor(oid asn1.ObjectIdentifier, data []byte) (name string, digest []byte, err error) {
	switch {
	case oid.Equal(oidSHA1):
		sum := sha1.Sum(data)
		return "sha1", sum[:], nil
	case oid.Equal(oidSHA256):
		sum := sha256.Sum256(data)
		return "sha256", sum[:], nil
	case oid.Equal(oidSHA384):
		sum := sha512.Sum384(data)
		return "sha384", sum[:], nil
	case oid.Equal(oidSHA512):
		sum := sha512.Sum512(data)
		return "sha512", sum[:], nil
	}
	return "", nil, fmt.Errorf("the logotype hash uses algorithm %s, which this build cannot compute", oid)
}

// checkRevocation asks the certificate's OCSP responder whether it is still
// good.
//
// It needs the issuer certificate, which comes from the published bundle
// rather than from anywhere else — a mark certificate is published leaf-first
// with its issuers, so the material is usually right there. When it is not,
// the result is "unchecked", which is reported as such: an unanswered question
// is not a pass.
func checkRevocation(ctx context.Context, f *Fetcher, certs []*x509.Certificate, opts EvidenceOptions) RevocationResult {
	if !opts.CheckRevocation {
		return RevocationResult{Status: "unchecked", Err: "revocation checking is switched off (BIMI_CHECK_REVOCATION)"}
	}
	leaf := certs[0]
	if len(certs) < 2 {
		return RevocationResult{Status: "unchecked",
			Err: "the published bundle contains only the leaf certificate, so its issuer is not available to check revocation against"}
	}
	issuer := certs[1]

	// Mark certificates as issued today name a CRL and no OCSP responder, so
	// the CRL is not a fallback for exotic cases — it is the path that runs.
	if len(leaf.OCSPServer) == 0 {
		if len(leaf.CRLDistributionPoints) == 0 {
			return RevocationResult{Status: "unchecked",
				Err: "the certificate names neither an OCSP responder nor a CRL"}
		}
		return checkCRL(ctx, f, leaf, issuer)
	}
	responder := leaf.OCSPServer[0]

	req, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return RevocationResult{Status: "unchecked", Responder: responder, Err: err.Error()}
	}
	body, err := f.post(ctx, responder, "application/ocsp-request", req)
	if err != nil {
		return RevocationResult{Status: "unknown", Responder: responder, Err: err.Error()}
	}
	resp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return RevocationResult{Status: "unknown", Responder: responder, Err: err.Error()}
	}

	out := RevocationResult{Responder: responder, At: resp.ProducedAt.Unix()}
	switch resp.Status {
	case ocsp.Good:
		out.Status = "good"
	case ocsp.Revoked:
		out.Status, out.Revoked = "revoked", true
		out.Reason = ocspReason(resp.RevocationReason)
		if !resp.RevokedAt.IsZero() {
			out.Reason = strings.TrimSpace(out.Reason + " on " + resp.RevokedAt.UTC().Format("2006-01-02"))
		}
	default:
		out.Status = "unknown"
		out.Err = "the responder answered \"unknown\""
	}
	return out
}

// checkCRL downloads the certificate's revocation list and looks for its
// serial number.
//
// The list is verified against the issuing certificate before anything in it
// is believed. That verification is what makes it safe to retrieve over plain
// HTTP, which is how every mark certificate publishes it.
func checkCRL(ctx context.Context, f *Fetcher, leaf, issuer *x509.Certificate) RevocationResult {
	point := leaf.CRLDistributionPoints[0]
	out := RevocationResult{Responder: point}

	der, err := f.getSigned(ctx, point)
	if err != nil {
		out.Status, out.Err = "unknown", err.Error()
		return out
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		out.Status, out.Err = "unknown", fmt.Sprintf("the revocation list does not parse: %v", err)
		return out
	}
	if err := list.CheckSignatureFrom(issuer); err != nil {
		// An unverifiable list says nothing at all. Treating it as "not
		// revoked" would be exactly the wrong conclusion.
		out.Status = "unknown"
		out.Err = fmt.Sprintf("the revocation list is not signed by the certificate's issuer: %v", err)
		return out
	}
	out.At = list.ThisUpdate.Unix()

	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			continue
		}
		out.Status, out.Revoked = "revoked", true
		out.Reason = ocspReason(entry.ReasonCode)
		if !entry.RevocationTime.IsZero() {
			out.Reason = strings.TrimSpace(out.Reason + " on " + entry.RevocationTime.UTC().Format("2006-01-02"))
		}
		return out
	}

	out.Status = "good"
	// A list whose own next-update has passed is stale; the answer is still
	// the best available one, but the caller should know how old it is.
	if !list.NextUpdate.IsZero() && time.Now().After(list.NextUpdate) {
		out.Status = "unknown"
		out.Err = fmt.Sprintf("the revocation list expired on %s and the issuer has not published a newer one",
			list.NextUpdate.UTC().Format("2006-01-02"))
	}
	return out
}

func ocspReason(code int) string {
	switch code {
	case ocsp.Unspecified:
		return ""
	case ocsp.KeyCompromise:
		return "key compromise"
	case ocsp.CACompromise:
		return "CA compromise"
	case ocsp.AffiliationChanged:
		return "affiliation changed"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessation of operation"
	case ocsp.CertificateHold:
		return "certificate hold"
	case ocsp.RemoveFromCRL:
		return "removed from CRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilege withdrawn"
	case ocsp.AACompromise:
		return "AA compromise"
	}
	return fmt.Sprintf("reason %d", code)
}
