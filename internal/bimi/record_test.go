package bimi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// codes lists the problem codes a parse produced, for compact assertions.
func codes(r Record) []string {
	out := []string{}
	for _, p := range r.Problems {
		out = append(out, p.Code)
	}
	return out
}

func TestParse(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		state    string
		location string
		codes    []string
	}{
		{
			name:     "valid minimal",
			raw:      "v=BIMI1; l=https://example.com/logo.svg",
			state:    StatePublished,
			location: "https://example.com/logo.svg",
			codes:    []string{},
		},
		{
			name:  "valid with evidence and trailing semicolon",
			raw:   "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;",
			state: StatePublished,
			codes: []string{},
		},
		{
			name:  "whitespace around the tag separators is legal",
			raw:   "  v = BIMI1 ;  l = https://example.com/logo.svg  ",
			state: StatePublished,
			codes: []string{},
		},
		{
			name:  "declination to publish",
			raw:   "v=BIMI1; l=; a=;",
			state: StateDeclined,
			codes: []string{},
		},
		{
			name:  "declination with an absent a= is still a declination",
			raw:   "v=BIMI1; l=;",
			state: StateDeclined,
			codes: []string{},
		},
		{
			name:  "declination that still enables local-part selectors",
			raw:   "v=BIMI1; l=; a=; lps=brand-indicators-;",
			state: StateDeclined,
			codes: []string{},
		},
		{
			name:  "missing l= is not a declination",
			raw:   "v=BIMI1; a=https://example.com/vmc.pem",
			state: StateInvalid,
			codes: []string{"location_missing"},
		},
		{
			name:  "v= is not first",
			raw:   "l=https://example.com/logo.svg; v=BIMI1",
			state: StateInvalid,
			codes: []string{"version_not_first"},
		},
		{
			name:  "v= missing entirely",
			raw:   "l=https://example.com/logo.svg",
			state: StateInvalid,
			codes: []string{"version_missing"},
		},
		{
			name:  "v= names another version",
			raw:   "v=BIMI2; l=https://example.com/logo.svg",
			state: StateInvalid,
			codes: []string{"version_mismatch"},
		},
		{
			name:  "capitalisation is not repaired",
			raw:   "V=BIMI1; L=https://example.com/logo.svg",
			state: StateInvalid,
			// Both tags fall outside the registry, so the required ones are missing.
			codes: []string{"unknown_tag", "unknown_tag", "version_missing", "location_missing"},
		},
		{
			name:  "l= over plain HTTP",
			raw:   "v=BIMI1; l=http://example.com/logo.svg",
			state: StateInvalid,
			codes: []string{"location_not_https"},
		},
		{
			name:  "l= without a fully qualified host",
			raw:   "v=BIMI1; l=https://localhost/logo.svg",
			state: StateInvalid,
			codes: []string{"location_no_fqdn"},
		},
		{
			name:  "l= naming an IP address",
			raw:   "v=BIMI1; l=https://192.0.2.10/logo.svg",
			state: StateInvalid,
			codes: []string{"location_no_fqdn"},
		},
		{
			name:  "a= over plain HTTP",
			raw:   "v=BIMI1; l=https://example.com/logo.svg; a=http://example.com/vmc.pem",
			state: StateInvalid,
			codes: []string{"authority_not_https"},
		},
		{
			name:  "unencoded comma in a URI",
			raw:   "v=BIMI1; l=https://example.com/logo,1.svg",
			state: StatePublished,
			codes: []string{"location_unencoded_comma"},
		},
		{
			name:  "unknown tag is recorded but not fatal",
			raw:   "v=BIMI1; l=https://example.com/logo.svg; x=1",
			state: StatePublished,
			codes: []string{"unknown_tag"},
		},
		{
			name:  "duplicate tag",
			raw:   "v=BIMI1; l=https://example.com/a.svg; l=https://example.com/b.svg",
			state: StateInvalid,
			codes: []string{"duplicate_tag"},
		},
		{
			name:  "avp with an invalid value",
			raw:   "v=BIMI1; l=https://example.com/logo.svg; avp=maybe",
			state: StatePublished,
			codes: []string{"avp_invalid"},
		},
		{
			name:  "a tag-value pair without an equals sign",
			raw:   "v=BIMI1; l=https://example.com/logo.svg; nonsense",
			state: StateInvalid,
			codes: []string{"malformed_tag"},
		},
		{
			name:  "empty record",
			raw:   "",
			state: StateInvalid,
			codes: []string{"version_missing", "location_missing"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw)
			if got.State() != tc.state {
				t.Errorf("state = %q, want %q (problems: %v)", got.State(), tc.state, codes(got))
			}
			if !reflect.DeepEqual(codes(got), tc.codes) {
				t.Errorf("problems = %v, want %v", codes(got), tc.codes)
			}
			if tc.location != "" && got.Location != tc.location {
				t.Errorf("l = %q, want %q", got.Location, tc.location)
			}
			if got.Raw != tc.raw {
				t.Errorf("raw was altered: %q", got.Raw)
			}
		})
	}
}

// The three meanings of a tag — absent, present-and-empty, present-with-value
// — are the whole reason the record model exists, so they get their own test.
func TestPresenceIsDistinctFromEmptiness(t *testing.T) {
	absent := Parse("v=BIMI1; l=https://example.com/logo.svg")
	if absent.APresent {
		t.Error("a= reported present when the record has none")
	}
	if absent.Declined() {
		t.Error("a published logo must not read as a declination")
	}

	empty := Parse("v=BIMI1; l=https://example.com/logo.svg; a=")
	if !empty.APresent || empty.Authority != "" {
		t.Errorf("a= present-but-empty not recorded: present=%v value=%q", empty.APresent, empty.Authority)
	}
	if empty.Ignorable() {
		t.Error("an empty a= is explicitly allowed and must not be fatal")
	}
}

func TestParseLPSVariants(t *testing.T) {
	// §4.5's own examples.
	cases := []struct {
		raw     string
		present bool
		want    []string
		codes   []string
	}{
		{"v=BIMI1; l=https://example.com/l.svg", false, nil, []string{}},
		{"v=BIMI1; l=https://example.com/l.svg; lps=", true, []string{}, []string{}},
		{"v=BIMI1; l=https://example.com/l.svg; lps=brand-indicator-", true, []string{"brand-indicator-"}, []string{}},
		{
			"v=BIMI1; l=https://example.com/l.svg; lps = brand-one-noreply , brand-two-noreply",
			true, []string{"brand-one-noreply", "brand-two-noreply"}, []string{},
		},
		{
			"v=BIMI1; l=https://example.com/l.svg; lps=brand_one",
			true, []string{"brand_one"}, []string{"lps_invalid_prefix"},
		},
		{
			"v=BIMI1; l=https://example.com/l.svg; lps=a,,b",
			true, []string{"a", "b"}, []string{"lps_empty_prefix"},
		},
		{
			"v=BIMI1; l=https://example.com/l.svg; lps=" + strings.Repeat("a", 64),
			true, []string{strings.Repeat("a", 64)}, []string{"lps_invalid_prefix"},
		},
	}
	for _, tc := range cases {
		got := Parse(tc.raw)
		if got.LPSPresent() != tc.present {
			t.Errorf("%q: lps present = %v, want %v", tc.raw, got.LPSPresent(), tc.present)
		}
		if !reflect.DeepEqual(got.LPS, tc.want) {
			t.Errorf("%q: lps = %#v, want %#v", tc.raw, got.LPS, tc.want)
		}
		if !reflect.DeepEqual(codes(got), tc.codes) {
			t.Errorf("%q: problems = %v, want %v", tc.raw, codes(got), tc.codes)
		}
		// A bad prefix list must not stop the logo being served.
		if len(tc.codes) > 0 && got.State() != StatePublished {
			t.Errorf("%q: state = %q, want a warning not a rejection", tc.raw, got.State())
		}
	}
}

func TestAvatarPreferenceFallsBackToBrand(t *testing.T) {
	for raw, want := range map[string]string{
		"v=BIMI1; l=https://example.com/l.svg":               "brand",
		"v=BIMI1; l=https://example.com/l.svg; avp=brand":    "brand",
		"v=BIMI1; l=https://example.com/l.svg; avp=personal": "personal",
		"v=BIMI1; l=https://example.com/l.svg; avp=Personal": "brand", // case-sensitive per the ABNF
		"v=BIMI1; l=https://example.com/l.svg; avp=nonsense": "brand",
	} {
		if got := Parse(raw).AvatarPreference(); got != want {
			t.Errorf("%q: avatar preference = %q, want %q", raw, got, want)
		}
	}
}

// A TXT record split into several character-strings is concatenated with
// nothing between them by the resolver, and a long a= URI is exactly where
// that split lands in practice.
func TestMultiStringTXTIsAlreadyConcatenated(t *testing.T) {
	long := "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/" + strings.Repeat("x", 200) + "/vmc.pem"
	joined := strings.Join([]string{long[:255], long[255:]}, "")
	got := Parse(joined)
	if got.State() != StatePublished {
		t.Fatalf("state = %q, want published (problems %v)", got.State(), codes(got))
	}
	if !strings.HasSuffix(got.Authority, "/vmc.pem") {
		t.Errorf("a = %q, want the whole URI", got.Authority)
	}
}

func TestParseRRsetSelection(t *testing.T) {
	// Step 4: anything that is not a BIMI1 record is discarded, not an error.
	set := ParseRRset([]string{"some-site-verification=abc", "v=BIMI1; l=https://example.com/l.svg"})
	if !set.Found || set.State() != StatePublished {
		t.Errorf("found=%v state=%q, want a published record", set.Found, set.State())
	}
	if len(set.Discarded) != 1 {
		t.Errorf("discarded = %v, want the verification token recorded", set.Discarded)
	}

	// An empty set is absence, which is not a fault.
	if got := ParseRRset(nil).State(); got != StateAbsent {
		t.Errorf("empty rrset state = %q, want %q", got, StateAbsent)
	}
	if got := ParseRRset([]string{"google-site-verification=x"}).State(); got != StateAbsent {
		t.Errorf("non-BIMI rrset state = %q, want %q", got, StateAbsent)
	}

	// Step 9: two records stop BIMI processing altogether.
	two := ParseRRset([]string{"v=BIMI1; l=https://example.com/a.svg", "v=BIMI1; l=https://example.com/b.svg"})
	if !two.Ambiguous() || two.Found {
		t.Errorf("ambiguous=%v found=%v, want ambiguous and not found", two.Ambiguous(), two.Found)
	}
	if two.State() != StateInvalid {
		t.Errorf("state = %q, want %q", two.State(), StateInvalid)
	}
	if two.Err == "" {
		t.Error("want an explanation of why two records is not a choice")
	}
}

// The parsed record is stored as JSON in bimi_snapshots.detail, so the
// absent/empty distinction has to survive the round trip.
func TestRecordJSONRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"v=BIMI1; l=https://example.com/l.svg",
		"v=BIMI1; l=https://example.com/l.svg; lps=",
		"v=BIMI1; l=; a=;",
	} {
		in := Parse(raw)
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %q: %v", raw, err)
		}
		var out Record
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %q: %v", raw, err)
		}
		if out.LPSPresent() != in.LPSPresent() {
			t.Errorf("%q: lps presence lost in the round trip", raw)
		}
		if out.State() != in.State() {
			t.Errorf("%q: state %q became %q", raw, in.State(), out.State())
		}
	}
}
