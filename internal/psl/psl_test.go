package psl

import "testing"

func TestOrgDomain(t *testing.T) {
	cases := map[string]string{
		"example.com": "example.com", "mail.example.com": "example.com", "a.b.example.co.uk": "example.co.uk",
		"EXAMPLE.COM.": "example.com", "com": "com", "": "", "localhost": "localhost",
		"foo.github.io": "foo.github.io", // private suffix list entry
	}
	for in, want := range cases {
		if got := OrgDomain(in); got != want {
			t.Errorf("OrgDomain(%q) = %q want %q", in, got, want)
		}
	}
}

func TestAlign(t *testing.T) {
	cases := []struct{ a, h, want string }{
		{"example.com", "example.com", AlignExact},
		{"mail.example.com", "example.com", AlignRelaxed},
		{"example.com", "news.example.com", AlignRelaxed},
		{"sendgrid.net", "example.com", AlignMisaligned},
		{"", "example.com", AlignMisaligned},
		{"a.example.co.uk", "b.example.co.uk", AlignRelaxed},
		{"other.co.uk", "example.co.uk", AlignMisaligned},
	}
	for _, c := range cases {
		if got := Align(c.a, c.h); got != c.want {
			t.Errorf("Align(%q,%q) = %q want %q", c.a, c.h, got, c.want)
		}
	}
	if AlignEnvelope("<>", "example.com") != AlignNullSender {
		t.Error("null sender not recognised")
	}
}
