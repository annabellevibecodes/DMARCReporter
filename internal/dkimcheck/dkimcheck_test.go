package dkimcheck

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-msgauth/dkim"
)

// reportMail is the shape of a mailed TLS report: the RFC 8460 §5.3 submission
// headers and a JSON attachment.
const reportMail = "From: noreply-smtp-tls-reporting@reporter.example\r\n" +
	"To: tlsrpt@example.com\r\n" +
	"Subject: Report Domain: example.com Submitter: reporter.example\r\n" +
	"Date: Thu, 10 Sep 2026 03:04:05 +0000\r\n" +
	"TLS-Report-Domain: example.com\r\n" +
	"TLS-Report-Submitter: reporter.example\r\n" +
	"Message-ID: <report-1@reporter.example>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain\r\n" +
	"\r\n" +
	"{\"report-id\":\"1\"}\r\n"

// signedFixture signs reportMail and returns the message plus a resolver that
// publishes the matching key record. serviceTag is the s= tag to publish
// ("" for none).
func signedFixture(t *testing.T, domain, selector, serviceTag string) ([]byte, func(string) ([]string, error)) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var signed bytes.Buffer
	if err := dkim.Sign(&signed, strings.NewReader(reportMail), &dkim.SignOptions{
		Domain:   domain,
		Selector: selector,
		Signer:   key,
	}); err != nil {
		t.Fatalf("sign: %v", err)
	}

	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	record := "v=DKIM1;k=rsa;"
	if serviceTag != "" {
		record += "s=" + serviceTag + ";"
	}
	record += "p=" + base64.StdEncoding.EncodeToString(pub)

	want := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	lookup := func(name string) ([]string, error) {
		if strings.EqualFold(strings.TrimSuffix(name, "."), want) {
			return []string{record}, nil
		}
		return nil, fmt.Errorf("no TXT record for %s", name)
	}
	return signed.Bytes(), lookup
}

// RFC 8460 §3's own example key record carries s=tlsrpt, and that tag has to
// be read from the same lookup the signature check already made.
func TestVerifyValidSignatureWithTLSRPTServiceTag(t *testing.T) {
	msg, lookup := signedFixture(t, "reporter.example", "sel1", "tlsrpt")

	res := Verify(msg, &Options{LookupTXT: lookup})
	if res.Status != StatusValid {
		t.Fatalf("status = %q (%s), want valid", res.Status, res.Detail)
	}
	if res.Domain != "reporter.example" || res.Selector != "sel1" {
		t.Errorf("domain/selector = %q / %q", res.Domain, res.Selector)
	}
	if !res.ServiceTLSRPT {
		t.Error("s=tlsrpt in the key record was not detected")
	}
}

// A key record with no s= tag defaults to all service types. That is not the
// same as the reporter publishing s=tlsrpt, and must not be reported as if it
// were — the tag is a claim about the key, and we record what was published.
func TestVerifyValidSignatureWithoutServiceTag(t *testing.T) {
	msg, lookup := signedFixture(t, "reporter.example", "sel1", "")

	res := Verify(msg, &Options{LookupTXT: lookup})
	if res.Status != StatusValid {
		t.Fatalf("status = %q (%s), want valid", res.Status, res.Detail)
	}
	if res.ServiceTLSRPT {
		t.Error("absent s= tag reported as an explicit s=tlsrpt")
	}
}

// A key record listing several service types still counts when tlsrpt is one.
func TestVerifyServiceTagList(t *testing.T) {
	msg, lookup := signedFixture(t, "reporter.example", "sel1", "email:tlsrpt")

	if res := Verify(msg, &Options{LookupTXT: lookup}); !res.ServiceTLSRPT {
		t.Error("s=email:tlsrpt should count as tlsrpt")
	}
}

// An unsigned report is the case RFC 8460 §3 tells receivers to ignore. It
// must be visibly absent, not silently treated as unverifiable.
func TestVerifyUnsignedMessage(t *testing.T) {
	res := Verify([]byte(reportMail), &Options{
		LookupTXT: func(string) ([]string, error) { return nil, fmt.Errorf("should not be queried") },
	})
	if res.Status != StatusAbsent {
		t.Errorf("status = %q, want absent", res.Status)
	}
}

// The l= tag lets an attacker append to a signed report, so RFC 8460 §3
// forbids it. It disqualifies the signature whether or not it verifies.
func TestVerifyRejectsLTag(t *testing.T) {
	msg, lookup := signedFixture(t, "reporter.example", "sel1", "tlsrpt")
	// Add l= to the existing signature's tag list.
	withL := bytes.Replace(msg, []byte("DKIM-Signature: "), []byte("DKIM-Signature: l=10; "), 1)
	if bytes.Equal(withL, msg) {
		t.Fatal("fixture: could not inject the l= tag")
	}

	res := Verify(withL, &Options{LookupTXT: lookup})
	if res.Status != StatusLTagPresent {
		t.Errorf("status = %q, want l_tag_present", res.Status)
	}
	if res.Detail == "" {
		t.Error("an l= rejection should say why")
	}
}

// A signature that does not verify is invalid, and the reason is kept so the
// operator can see what was wrong with it.
func TestVerifyTamperedBody(t *testing.T) {
	msg, lookup := signedFixture(t, "reporter.example", "sel1", "tlsrpt")
	tampered := bytes.Replace(msg, []byte(`{"report-id":"1"}`), []byte(`{"report-id":"2"}`), 1)
	if bytes.Equal(tampered, msg) {
		t.Fatal("fixture: body was not modified")
	}

	res := Verify(tampered, &Options{LookupTXT: lookup})
	if res.Status != StatusInvalid {
		t.Errorf("status = %q, want invalid", res.Status)
	}
	if res.Detail == "" {
		t.Error("an invalid signature should carry the verifier's reason")
	}
}

// A DNS failure means "we could not tell", which is not the same as "the
// report is unsigned" and must not exclude the report on its own.
func TestVerifyResolverFailureIsUnknown(t *testing.T) {
	msg, _ := signedFixture(t, "reporter.example", "sel1", "tlsrpt")

	res := Verify(msg, &Options{
		LookupTXT: func(string) ([]string, error) { return nil, fmt.Errorf("server misbehaving") },
	})
	if res.Status != StatusUnknown && res.Status != StatusInvalid {
		t.Errorf("status = %q, want unknown (temp fail) or invalid (perm fail)", res.Status)
	}
	if res.Status == StatusValid {
		t.Error("a report must never be counted as valid when the key could not be fetched")
	}
}

func TestVerifyEmptyMessage(t *testing.T) {
	if res := Verify(nil, nil); res.Status != StatusUnknown {
		t.Errorf("status = %q, want unknown", res.Status)
	}
}

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		signing, contact string
		want             bool
	}{
		{"reporter.example", "sts-reporting@reporter.example", true},
		{"reporter.example", "reporter.example", true},
		{"reporter.example", "sts@mail.reporter.example", true}, // organisational parent
		{"reporter.example", "sts@other.example", false},
		{"reporter.example", "sts@evil-reporter.example", false}, // suffix, not a subdomain
		{"", "sts@reporter.example", false},
		{"reporter.example", "", false},
	}
	for _, tc := range cases {
		if got := DomainMatches(tc.signing, tc.contact); got != tc.want {
			t.Errorf("DomainMatches(%q, %q) = %v, want %v", tc.signing, tc.contact, got, tc.want)
		}
	}
}

// Header parsing has to survive folded fields, since a DKIM-Signature is
// almost always wrapped across lines.
func TestParseSignatureHeadersUnfolds(t *testing.T) {
	msg := "From: a@b.example\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; d=reporter.example;\r\n" +
		"\ts=sel1; l=42;\r\n" +
		"\tbh=abc; b=def\r\n" +
		"\r\n" +
		"body\r\n"
	sigs := parseSignatureHeaders([]byte(msg))
	if len(sigs) != 1 {
		t.Fatalf("signatures = %d, want 1", len(sigs))
	}
	if sigs[0]["d"] != "reporter.example" || sigs[0]["s"] != "sel1" || sigs[0]["l"] != "42" {
		t.Errorf("tags = %v", sigs[0])
	}
}
