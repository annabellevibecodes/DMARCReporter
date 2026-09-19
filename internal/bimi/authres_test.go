package bimi

import (
	"testing"
)

func TestParseAuthResultsGmailStyle(t *testing.T) {
	header := `Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=s1 header.b=abc123;
       spf=pass (google.com: domain of bounce@example.com designates 192.0.2.1 as permitted sender) smtp.mailfrom=bounce@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com;
       bimi=pass header.d=example.com header.selector=default policy.authority=pass policy.authority-uri=https://example.com/vmc.pem policy.indicator-uri=https://example.com/logo.svg policy.indicator-hash=8fd3c0a1`

	got := ParseAuthResults([]string{header})
	if len(got) != 1 {
		t.Fatalf("verdicts = %d, want 1: %+v", len(got), got)
	}
	v := got[0]
	if v.Receiver != "mx.google.com" {
		t.Errorf("receiver = %q", v.Receiver)
	}
	if v.Result != VerdictPass || !v.Displayed() {
		t.Errorf("result = %q", v.Result)
	}
	if v.HeaderD != "example.com" || v.Selector != "default" {
		t.Errorf("header.d/selector = %q/%q", v.HeaderD, v.Selector)
	}
	if v.Authority != "pass" || v.AuthorityURI != "https://example.com/vmc.pem" {
		t.Errorf("authority = %q %q", v.Authority, v.AuthorityURI)
	}
	if v.IndicatorURI != "https://example.com/logo.svg" || v.IndicatorHash != "8fd3c0a1" {
		t.Errorf("indicator = %q %q", v.IndicatorURI, v.IndicatorHash)
	}
}

// §7.7 lets the MTA put a comment after the result, and that comment is often
// the only statement of *why* — so it must survive parsing, and a semicolon
// inside it must not split the header.
func TestParseAuthResultsKeepsComments(t *testing.T) {
	cases := map[string]struct{ result, comment string }{
		`mx.example.net; bimi=skipped (message failed DMARC)`:      {VerdictSkipped, "message failed DMARC"},
		`mx.example.net; bimi=fail (Invalid SVG)`:                  {VerdictFail, "Invalid SVG"},
		`mx.example.net; bimi=fail (Invalid SVG; retried once)`:    {VerdictFail, "Invalid SVG; retried once"},
		`mx.example.net; bimi=skipped (sender not trusted)`:        {VerdictSkipped, "sender not trusted"},
		`mx.example.net; bimi=declined (domain owner declined)`:    {VerdictDeclined, "domain owner declined"},
		`mx.example.net; bimi=temperror (DNS timeout for _bimi)`:   {VerdictTempError, "DNS timeout for _bimi"},
		`mx.example.net; bimi=none`:                                {VerdictNone, ""},
		`mx.example.net; dmarc=pass; bimi=pass header.d=a.example`: {VerdictPass, ""},
	}
	for header, want := range cases {
		got := ParseAuthResults([]string{header})
		if len(got) != 1 {
			t.Errorf("%q: verdicts = %d", header, len(got))
			continue
		}
		if got[0].Result != want.result {
			t.Errorf("%q: result = %q, want %q", header, got[0].Result, want.result)
		}
		if got[0].Comment != want.comment {
			t.Errorf("%q: comment = %q, want %q", header, got[0].Comment, want.comment)
		}
	}
}

// A header with no bimi method produces nothing — most mail is like this.
func TestParseAuthResultsIgnoresOtherMethods(t *testing.T) {
	got := ParseAuthResults([]string{
		`mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=example.com; dmarc=pass header.from=example.com`,
		``,
		`spf=fail smtp.mailfrom=example.com`,
	})
	if len(got) != 0 {
		t.Errorf("verdicts = %+v, want none", got)
	}
}

// A message can carry one header per host that handled it, and they can
// disagree. All of them are kept: the disagreement is the finding.
func TestParseAuthResultsAcrossSeveralHeaders(t *testing.T) {
	got := ParseAuthResults([]string{
		`mx.first.example; bimi=pass header.d=example.com header.selector=default`,
		`mx.second.example; bimi=fail (could not retrieve indicator) header.d=example.com`,
	})
	if len(got) != 2 {
		t.Fatalf("verdicts = %d, want one per header", len(got))
	}
	if got[0].Receiver != "mx.first.example" || got[0].Result != VerdictPass {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Receiver != "mx.second.example" || got[1].Result != VerdictFail {
		t.Errorf("second = %+v", got[1])
	}
	if got[1].Comment == "" {
		t.Error("the second receiver's explanation was dropped")
	}
}

// A folded header is one header, whatever the line breaks say.
func TestParseAuthResultsUnfolds(t *testing.T) {
	got := ParseAuthResults([]string{"mx.example.net;\r\n\tbimi=pass\r\n  header.d=example.com\r\n  header.selector=winter"})
	if len(got) != 1 {
		t.Fatalf("verdicts = %d", len(got))
	}
	if got[0].Selector != "winter" || got[0].HeaderD != "example.com" {
		t.Errorf("verdict = %+v", got[0])
	}
}

// §7.7 truncates the indicator hash to "the final 8 (at least) characters", so
// the comparison is a suffix match. An exact comparison would never succeed.
func TestVerdictHashMatches(t *testing.T) {
	const full = "215d5054ca31f6d7aea6a316edc8824e45828fc18678fce20c8c886cb4252d22"
	for _, suffix := range []string{"b4252d22", "6cb4252d22", "886cb4252d22", full} {
		v := Verdict{IndicatorHash: suffix}
		if !v.HashMatches(full) {
			t.Errorf("hash %q did not match the full digest", suffix)
		}
	}
	// Case is not significant; a different logo is.
	if !(Verdict{IndicatorHash: "B4252D22"}).HashMatches(full) {
		t.Error("hash comparison must be case-insensitive")
	}
	if (Verdict{IndicatorHash: "deadbeef"}).HashMatches(full) {
		t.Error("a different hash matched")
	}
	// Nothing to compare is not a match.
	if (Verdict{}).HashMatches(full) || (Verdict{IndicatorHash: "b4252d22"}).HashMatches("") {
		t.Error("an absent hash must not count as a match")
	}
}

// Quoted values and odd spacing turn up in real headers.
func TestParseAuthResultsTolerance(t *testing.T) {
	got := ParseAuthResults([]string{
		`  mx.example.net 1 ;  bimi = pass  header.d="example.com"  header.selector="default"  `,
	})
	if len(got) != 1 {
		t.Fatalf("verdicts = %d", len(got))
	}
	if got[0].Receiver != "mx.example.net" {
		t.Errorf("receiver = %q, want the authserv-id without its version", got[0].Receiver)
	}
	if got[0].HeaderD != "example.com" || got[0].Selector != "default" {
		t.Errorf("quoted values not unquoted: %+v", got[0])
	}
}

// The whole header line, field name included, is accepted — that is how it
// arrives from a mail parser.
func TestParseAuthResultsAcceptsTheFullHeaderLine(t *testing.T) {
	got := ParseAuthResults([]string{"Authentication-Results: mx.example.net; bimi=pass header.d=example.com"})
	if len(got) != 1 || got[0].Receiver != "mx.example.net" {
		t.Fatalf("verdicts = %+v", got)
	}
}
