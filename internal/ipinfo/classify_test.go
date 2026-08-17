package ipinfo

import "testing"

func TestProviderFromRDNS(t *testing.T) {
	cases := map[string]string{
		"mail-ed1-f52.google.com.":              "Google / Gmail",
		"mail-am6eur05on2137.outbound.protection.outlook.com": "Microsoft 365",
		"a1-23.smtp-out.amazonses.com":          "Amazon SES",
		"o1.email.sendgrid.net":                 "SendGrid",
		"unknown-host.example.org":              "",
		"":                                      "",
		"totally-not-a-domain":                  "",
	}
	for rdns, want := range cases {
		if got := ProviderFromRDNS(rdns); got != want {
			t.Errorf("ProviderFromRDNS(%q) = %q, want %q", rdns, got, want)
		}
	}
}
