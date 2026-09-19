package psl

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"
)

// fakeResolver answers from a map; anything absent is NXDOMAIN, which is what
// the walk must treat as "no record here" rather than as a failure.
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

func TestTreeWalkTargetsHonourTheEightQueryCeiling(t *testing.T) {
	got := treeWalkTargets("a.b.c.d.e.f.g.h.i.j.mail.example.com")
	want := []string{
		"a.b.c.d.e.f.g.h.i.j.mail.example.com",
		"g.h.i.j.mail.example.com",
		"h.i.j.mail.example.com",
		"i.j.mail.example.com",
		"j.mail.example.com",
		"mail.example.com",
		"example.com",
		"com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("targets =\n%v\nwant\n%v", got, want)
	}
	if len(got) > maxTreeWalkQueries {
		t.Errorf("%d targets, the RFC allows %d", len(got), maxTreeWalkQueries)
	}

	// Short names walk every ancestor down to the TLD.
	if got, want := treeWalkTargets("a.mail.example.com"),
		[]string{"a.mail.example.com", "mail.example.com", "example.com", "com"}; !reflect.DeepEqual(got, want) {
		t.Errorf("targets = %v, want %v", got, want)
	}
}

func TestTreeWalkPicksTheFewestLabels(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.mail.example.com": {"v=DMARC1; p=reject"},
		"_dmarc.example.com":      {"v=DMARC1; p=none; rua=mailto:x@example.com"},
	}}
	got := TreeWalkOrgDomain(context.Background(), r, "a.mail.example.com")
	if got.OrgDomain != "example.com" {
		t.Errorf("org domain = %q, want example.com", got.OrgDomain)
	}
	if got.Method != MethodTreeWalk {
		t.Errorf("method = %q, want %q", got.Method, MethodTreeWalk)
	}
	if want := []string{"mail.example.com", "example.com"}; !reflect.DeepEqual(got.Policy, want) {
		t.Errorf("policy domains = %v, want %v", got.Policy, want)
	}
}

func TestTreeWalkStopsAtPSDn(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.mail.example.com": {"v=DMARC1; p=reject; psd=n"},
		"_dmarc.example.com":      {"v=DMARC1; p=none"},
	}}
	got := TreeWalkOrgDomain(context.Background(), r, "a.mail.example.com")
	if got.OrgDomain != "mail.example.com" {
		t.Errorf("org domain = %q, want mail.example.com", got.OrgDomain)
	}
	// The walk must stop rather than keep climbing past a declared boundary.
	for _, name := range r.asked {
		if name == "_dmarc.example.com" {
			t.Error("walk continued past psd=n")
		}
	}
}

func TestTreeWalkPSDyTakesTheDomainOneLabelBelow(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.example.com": {"v=DMARC1; p=none; psd=y"},
	}}
	got := TreeWalkOrgDomain(context.Background(), r, "a.mail.example.com")
	if got.OrgDomain != "mail.example.com" {
		t.Errorf("org domain = %q, want mail.example.com", got.OrgDomain)
	}
}

func TestTreeWalkDiscardsAmbiguousAndForeignRecords(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		// Two DMARC records at one name are discarded together (§4.10 step 2).
		"_dmarc.mail.example.com": {"v=DMARC1; p=reject", "v=DMARC1; p=none"},
		// Not a DMARC record at all.
		"_dmarc.example.com": {"some-verification-token=abc123"},
		"_dmarc.com":         {"v=DMARC1; p=none; psd=y"},
	}}
	got := TreeWalkOrgDomain(context.Background(), r, "a.mail.example.com")
	if len(got.Policy) != 1 || got.Policy[0] != "com" {
		t.Fatalf("policy domains = %v, want [com]", got.Policy)
	}
	if got.OrgDomain != "example.com" {
		t.Errorf("org domain = %q, want example.com", got.OrgDomain)
	}
}

func TestTreeWalkWithoutDMARCFallsBackToThePSL(t *testing.T) {
	r := &fakeResolver{}
	got := TreeWalkOrgDomain(context.Background(), r, "a.mail.example.co.uk")
	if got.OrgDomain != "example.co.uk" {
		t.Errorf("org domain = %q, want example.co.uk", got.OrgDomain)
	}
	if got.Method != MethodPSL {
		t.Errorf("method = %q, want %q", got.Method, MethodPSL)
	}
	if got.Err != "" {
		t.Errorf("err = %q, want none: an empty DNS is not a failure", got.Err)
	}
}

func TestTreeWalkDNSFailureIsNotTreatedAsAbsence(t *testing.T) {
	r := &fakeResolver{err: map[string]error{
		"_dmarc.mail.example.com": &net.DNSError{Err: "server misbehaving", IsTemporary: true},
	}}
	got := TreeWalkOrgDomain(context.Background(), r, "mail.example.com")
	if got.Err == "" {
		t.Error("want the resolver error recorded")
	}
	if got.OrgDomain != "example.com" || got.Method != MethodPSL {
		t.Errorf("org domain = %q via %q, want example.com via the PSL", got.OrgDomain, got.Method)
	}
}

func TestOrgDomainForOnlyWalksWhenReportersSaidTreewalk(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"_dmarc.mail.example.com": {"v=DMARC1; p=reject; psd=n"},
	}}
	if got := OrgDomainFor(context.Background(), r, "a.mail.example.com", MethodPSL); got.OrgDomain != "example.com" {
		t.Errorf("psl org domain = %q, want example.com", got.OrgDomain)
	}
	if len(r.asked) != 0 {
		t.Errorf("the PSL path made %d DNS queries, want none", len(r.asked))
	}
	if got := OrgDomainFor(context.Background(), r, "a.mail.example.com", ""); len(r.asked) != 0 {
		t.Errorf("an unstated method queried DNS: %v (org=%s)", r.asked, got.OrgDomain)
	}
	if got := OrgDomainFor(context.Background(), r, "a.mail.example.com", MethodTreeWalk); got.OrgDomain != "mail.example.com" {
		t.Errorf("treewalk org domain = %q, want mail.example.com", got.OrgDomain)
	}
}

func TestHasVersionTagIsExact(t *testing.T) {
	cases := map[string]bool{
		"v=DMARC1; p=none":   true,
		"v = DMARC1; p=n":    true,
		"v=DMARC1":           true,
		"v=DMARC1234":        false, // must not prefix-match a longer version
		"V=DMARC1; p=none":   false, // capitalisation is not repaired
		"p=none; v=DMARC1":   false, // the version tag must come first
		"v=spf1 -all":        false,
		"":                   false,
		" v=DMARC1 ; p=none": true,
	}
	for in, want := range cases {
		if got := hasVersionTag(in, "DMARC1"); got != want {
			t.Errorf("hasVersionTag(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestOneLabelBelow(t *testing.T) {
	if got := oneLabelBelow("a.mail.example.com", "example.com"); got != "mail.example.com" {
		t.Errorf("= %q, want mail.example.com", got)
	}
	// A parent that is not shorter than the start has nothing below it.
	if got := oneLabelBelow("example.com", "example.com"); got != "example.com" {
		t.Errorf("= %q, want example.com", got)
	}
	if strings.Count(oneLabelBelow("a.b.c.example.com", "example.com"), ".") != 2 {
		t.Error("want exactly one label added to the parent")
	}
}
