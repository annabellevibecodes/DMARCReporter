package bimi

import (
	"context"
	"net"
	"testing"
)

type fakeResolver struct {
	txt   map[string][]string
	err   map[string]error
	asked []string
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.asked = append(f.asked, name)
	if err, ok := f.err[name]; ok {
		return nil, err
	}
	if txts, ok := f.txt[name]; ok {
		return txts, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func TestQueryName(t *testing.T) {
	for in, want := range map[[2]string]string{
		{"Example.COM", "default"}:      "default._bimi.example.com",
		{"example.com.", ""}:            "default._bimi.example.com",
		{"example.com", "Marketing"}:    "marketing._bimi.example.com",
		{"example.com", "brand.winter"}: "brand.winter._bimi.example.com",
	} {
		if got := QueryName(in[0], in[1]); got != want {
			t.Errorf("QueryName(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

func TestLookupFindsThePublishedRecord(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}
	got := (&Client{Resolver: r}).Lookup(context.Background(), "example.com", "")
	if got.State != StatePublished {
		t.Fatalf("state = %q, want published (%v)", got.State, got.Error)
	}
	if got.FoundAt != "example.com" || got.Fallback {
		t.Errorf("found at %q (fallback %v), want the domain itself", got.FoundAt, got.Fallback)
	}
	if got.Content() != "v=BIMI1; l=https://example.com/logo.svg" {
		t.Errorf("content = %q", got.Content())
	}
}

func TestLookupFallsBackToTheOrganizationalDomain(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}
	got := (&Client{Resolver: r}).Lookup(context.Background(), "mail.example.com", "")
	if got.State != StatePublished {
		t.Fatalf("state = %q, want published", got.State)
	}
	if !got.Fallback || got.FoundAt != "example.com" {
		t.Errorf("found at %q (fallback %v), want example.com by fallback", got.FoundAt, got.Fallback)
	}
	// B1 has to be able to say the subdomain publishes nothing of its own.
	if got.Domain != "mail.example.com" {
		t.Errorf("domain = %q, want the domain asked about", got.Domain)
	}
	if got.OrgMethod != "psl" {
		t.Errorf("org method = %q, want psl when no reporter said otherwise", got.OrgMethod)
	}
}

// A subdomain declining to publish must not be overridden by its parent's
// logo — that is the whole point of §4.3.1.
func TestSubdomainDeclinationWins(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"default._bimi.mail.example.com": {"v=BIMI1; l=; a=;"},
		"default._bimi.example.com":      {"v=BIMI1; l=https://example.com/logo.svg"},
	}}
	got := (&Client{Resolver: r}).Lookup(context.Background(), "mail.example.com", "")
	if got.State != StateDeclined {
		t.Errorf("state = %q, want %q", got.State, StateDeclined)
	}
	for _, name := range r.asked {
		if name == "default._bimi.example.com" {
			t.Error("the parent was queried although the subdomain answered")
		}
	}
}

func TestLookupDoesNotClimbPastAnAmbiguousSet(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"default._bimi.mail.example.com": {
			"v=BIMI1; l=https://example.com/a.svg",
			"v=BIMI1; l=https://example.com/b.svg",
		},
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}
	got := (&Client{Resolver: r}).Lookup(context.Background(), "mail.example.com", "")
	if got.State != StateInvalid {
		t.Errorf("state = %q, want %q", got.State, StateInvalid)
	}
	if got.Fallback {
		t.Error("§7.2 step 9 terminates discovery; it must not fall back")
	}
	// Both records must be diffable, in a stable order.
	if got.Content() != "v=BIMI1; l=https://example.com/a.svg\nv=BIMI1; l=https://example.com/b.svg" {
		t.Errorf("content = %q, want both records sorted", got.Content())
	}
}

func TestLookupSeparatesAbsenceFromFailure(t *testing.T) {
	absent := (&Client{Resolver: &fakeResolver{}}).Lookup(context.Background(), "example.com", "")
	if absent.State != StateAbsent || absent.Error != "" {
		t.Errorf("state = %q err = %q, want a clean absence", absent.State, absent.Error)
	}

	broken := &fakeResolver{err: map[string]error{
		"default._bimi.example.com": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
	}}
	got := (&Client{Resolver: broken}).Lookup(context.Background(), "example.com", "")
	if got.State != StateError || got.Error == "" {
		t.Errorf("state = %q err = %q, want the resolver failure reported as such", got.State, got.Error)
	}
	// An unanswerable lookup must not overwrite a stored record with "absent".
	if got.Content() != "" {
		t.Errorf("content = %q, want empty", got.Content())
	}
}

// A parent that cannot be queried is also a failure, not an absence: the
// subdomain genuinely has no record, but whether it inherits one is unknown.
func TestFallbackFailureIsReportedAsError(t *testing.T) {
	r := &fakeResolver{err: map[string]error{
		"default._bimi.example.com": &net.DNSError{Err: "timeout", IsTimeout: true},
	}}
	got := (&Client{Resolver: r}).Lookup(context.Background(), "mail.example.com", "")
	if got.State != StateError {
		t.Errorf("state = %q, want %q", got.State, StateError)
	}
}

func TestLookupUsesTheTreeWalkWhenReportersDeclareIt(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		// The tree walk finds the policy boundary at mail.example.com, so the
		// BIMI fallback asks there rather than at example.com.
		"_dmarc.mail.example.com":        {"v=DMARC1; p=reject; psd=n"},
		"default._bimi.mail.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
	}}
	got := (&Client{Resolver: r, Discovery: "treewalk"}).Lookup(context.Background(), "news.mail.example.com", "")
	if got.OrgMethod != "treewalk" {
		t.Errorf("org method = %q, want treewalk", got.OrgMethod)
	}
	if got.FoundAt != "mail.example.com" || !got.Fallback {
		t.Errorf("found at %q (fallback %v), want mail.example.com by fallback", got.FoundAt, got.Fallback)
	}
}

func TestLookupAllAlwaysCoversDefaultFirst(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"default._bimi.example.com": {"v=BIMI1; l=https://example.com/logo.svg"},
		"winter._bimi.example.com":  {"v=BIMI1; l=https://example.com/winter.svg"},
	}}
	got := (&Client{Resolver: r}).LookupAll(context.Background(), "example.com", []string{"winter", "Winter", "default"})
	if len(got) != 2 {
		t.Fatalf("%d results, want 2 (duplicates and case variants collapse)", len(got))
	}
	if got[0].Selector != DefaultSelector {
		t.Errorf("first selector = %q, want %q", got[0].Selector, DefaultSelector)
	}
	if got[1].Selector != "winter" || got[1].State != StatePublished {
		t.Errorf("second result = %q/%q", got[1].Selector, got[1].State)
	}
}
