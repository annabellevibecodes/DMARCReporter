package spf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

type fakeResolver struct {
	txt map[string][]string
	a   map[string][]string
	mx  map[string][]string
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func (f *fakeResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	v, ok := f.a[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []net.IP
	for _, s := range v {
		out = append(out, net.ParseIP(s))
	}
	return out, nil
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	v, ok := f.mx[name]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []*net.MX
	for _, h := range v {
		out = append(out, &net.MX{Host: h + "."})
	}
	return out, nil
}

func TestResolveExpandsMechanisms(t *testing.T) {
	r := &fakeResolver{
		txt: map[string][]string{
			"example.com":           {"v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.net include:_spf.google.com -ip4:198.51.100.1 ~all"},
			"_spf.google.com":       {"some other txt", "v=spf1 include:_netblocks.google.com redirect=_spf2.google.com"},
			"_netblocks.google.com": {"v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all"},
			"_spf2.google.com":      {"v=spf1 ip6:2607:f8b0:4000::/36 a:host.example.org/24//64 ~all"},
		},
		a:  map[string][]string{"example.com": {"203.0.113.10", "2001:db8:1::10"}, "mx1.example.net": {"203.0.113.25"}, "host.example.org": {"198.51.100.200", "2001:db8:2::1"}},
		mx: map[string][]string{"mail.example.net": {"mx1.example.net"}},
	}
	res, err := Resolve(context.Background(), r, "Example.com.")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"192.0.2.0/24", "2001:db8::/32", // direct
		"203.0.113.10/32", "2001:db8:1::10/128", // a
		"203.0.113.25/32",                    // mx
		"35.190.247.0/24", "64.233.160.0/19", // nested include
		"2607:f8b0:4000::/36",                // redirect
		"198.51.100.0/24", "2001:db8:2::/64", // a with dual-cidr
	}
	got := strings.Join(res.CIDRs, " ")
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s in %v", w, res.CIDRs)
		}
	}
	if strings.Contains(got, "198.51.100.1/32") {
		t.Error("-ip4 must not authorise")
	}
	// Lookups: a, mx, include:_spf.google.com, include:_netblocks, redirect, a:host = 6
	if res.Lookups != 6 || res.OverLimit {
		t.Errorf("lookups = %d overLimit=%v errors=%v", res.Lookups, res.OverLimit, res.Errors)
	}
	if len(res.Includes) != 3 {
		t.Errorf("includes = %v", res.Includes)
	}
	if res.Record == "" || len(res.Errors) != 0 {
		t.Errorf("record=%q errors=%v", res.Record, res.Errors)
	}
}

func TestResolveLookupLimit(t *testing.T) {
	txt := map[string][]string{"loop.example": {"v=spf1 include:i1 include:i2 include:i3 include:i4 include:i5 include:i6 include:i7 include:i8 include:i9 include:i10 include:i11 ip4:10.0.0.0/8 -all"}}
	for i := 1; i <= 11; i++ {
		txt["i"+itoa(i)] = []string{"v=spf1 ip4:192.0." + itoa(i) + ".0/24 -all"}
	}
	res, err := Resolve(context.Background(), &fakeResolver{txt: txt}, "loop.example")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OverLimit || res.Lookups != MaxLookups {
		t.Errorf("overLimit=%v lookups=%d", res.OverLimit, res.Lookups)
	}
	if len(res.CIDRs) != MaxLookups { // 10 includes resolved, the 11th and the trailing ip4 were cut off
		t.Errorf("cidrs = %v", res.CIDRs)
	}
}

func TestResolveMissingAndLoops(t *testing.T) {
	r := &fakeResolver{txt: map[string][]string{
		"none.example": {"not spf"},
		"loop.example": {"v=spf1 include:loop.example include:missing.example ip4:192.0.2.1 -all"},
		"plus.example": {"v=spf1 +all"},
	}}
	res, err := Resolve(context.Background(), r, "none.example")
	if err != nil || res.Record != "" || len(res.CIDRs) != 0 {
		t.Errorf("no record: %+v %v", res, err)
	}
	res, err = Resolve(context.Background(), r, "loop.example")
	if err != nil || len(res.CIDRs) != 1 || res.CIDRs[0] != "192.0.2.1/32" || len(res.Errors) != 1 {
		t.Errorf("loop: %+v %v", res, err)
	}
	res, _ = Resolve(context.Background(), r, "plus.example")
	if len(res.CIDRs) != 2 || len(res.Errors) != 1 {
		t.Errorf("+all: %+v", res)
	}
	if _, err := Resolve(context.Background(), r, "nxdomain.example"); err == nil {
		t.Error("top-level DNS failure must be an error")
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}
