package bimi

import (
	"os"
	"strings"
	"testing"
	"time"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

// findingCodes lists the codes a validation produced.
func findingCodes(r SVGPSResult) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasCode(r SVGPSResult, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// The draft's own example document (§5) must validate. If this ever fails,
// the validator has become stricter than the profile it implements.
func TestValidateSVGPSAcceptsTheDraftExample(t *testing.T) {
	got := ValidateSVGPS(readFixture(t, "valid.svg"))
	if !got.Valid {
		t.Errorf("the draft's own example did not validate: %v", findingCodes(got))
	}
	if len(got.Findings) != 0 {
		t.Errorf("findings = %v, want none", findingCodes(got))
	}
	if got.Title != "Example, Inc." {
		t.Errorf("title = %q", got.Title)
	}
	if len(got.Colors) < 2 {
		t.Errorf("colours = %v, want the rule to see at least two", got.Colors)
	}
}

// CVE-2003-1564. The guidance draft calls this out by name, and the defence is
// that encoding/xml expands no entity outside the five predefined ones — so
// the document fails to parse rather than expanding to gigabytes.
func TestValidateSVGPSRefusesBillionLaughs(t *testing.T) {
	done := make(chan SVGPSResult, 1)
	go func() { done <- ValidateSVGPS(readFixture(t, "billion_laughs.svg")) }()

	select {
	case got := <-done:
		if got.Valid {
			t.Fatal("a billion-laughs document validated")
		}
		if !hasCode(got, "svgps_doctype") {
			t.Errorf("findings = %v, want the DOCTYPE itself reported", findingCodes(got))
		}
		if !hasCode(got, "svgps_not_xml") {
			t.Errorf("findings = %v, want the entity reference to fail the parse", findingCodes(got))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("validation did not finish: the entity expansion was not contained")
	}
}

// An external entity must not be fetched. encoding/xml has no mechanism to do
// so, and the reference fails as an unknown entity; the DOCTYPE is reported
// either way, because its presence is the signal.
func TestValidateSVGPSRefusesExternalEntities(t *testing.T) {
	got := ValidateSVGPS(readFixture(t, "xxe.svg"))
	if got.Valid {
		t.Fatal("a document with an external entity validated")
	}
	if !hasCode(got, "svgps_doctype") {
		t.Errorf("findings = %v, want the DOCTYPE reported", findingCodes(got))
	}
}

// §2.3 excludes the image element, which is the only way to smuggle a raster
// into a vector logo.
func TestValidateSVGPSRejectsEmbeddedRaster(t *testing.T) {
	got := ValidateSVGPS(readFixture(t, "raster.svg"))
	if got.Valid {
		t.Fatal("a document embedding a raster validated")
	}
	if !hasCode(got, "svgps_element") {
		t.Fatalf("findings = %v, want the image element reported", findingCodes(got))
	}
	for _, f := range got.Findings {
		if f.Code == "svgps_element" && !strings.Contains(f.Message, "raster") {
			t.Errorf("message does not explain the rule: %q", f.Message)
		}
	}
}

// One document that breaks many rules at once: every breach is reported, not
// just the first, because an operator fixing a logo wants the whole list.
func TestValidateSVGPSReportsEveryBreach(t *testing.T) {
	got := ValidateSVGPS(readFixture(t, "scripted.svg"))
	if got.Valid {
		t.Fatal("a scripted document validated")
	}
	for _, want := range []string{
		"svgps_root_xy",          // §6.2 Illustrator's x/y on the root
		"svgps_version",          // version="1.1"
		"svgps_base_profile",     // baseProfile="tiny"
		"svgps_attribute",        // zoomAndPan="magnify", externalResourcesRequired="true"
		"svgps_element",          // script, a, animate
		"svgps_event_attribute",  // onload=
		"svgps_external_referen", // the href on <a>
		"svgps_title",            // two titles, the first empty
		"svgps_desc_empty",       // <desc></desc>
	} {
		found := false
		for _, code := range findingCodes(got) {
			if strings.HasPrefix(code, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("no %s* finding; got %v", want, findingCodes(got))
		}
	}
}

func TestValidateSVGPSSizeAndColourRules(t *testing.T) {
	// §2.4: a document over 32 kB is a warning, not a breach — the draft says
	// SHOULD NOT, and a logo that is merely large still renders.
	big := strings.Replace(string(readFixture(t, "valid.svg")),
		"</svg>", "<desc>"+strings.Repeat("x", 33*1024)+"</desc></svg>", 1)
	got := ValidateSVGPS([]byte(big))
	if !hasCode(got, "svgps_size") {
		t.Errorf("findings = %v, want the size rule", findingCodes(got))
	}
	if !got.Valid {
		t.Errorf("an oversized document must stay valid: %v", findingCodes(got))
	}

	// §2.4: at least two colours. One colour is a warning with its method
	// spelled out, because the count cannot see a stylesheet.
	oneColour := `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>One colour</title><rect width="10" height="10" fill="red"/></svg>`
	got = ValidateSVGPS([]byte(oneColour))
	if !hasCode(got, "svgps_colors") {
		t.Errorf("findings = %v, want the colour rule", findingCodes(got))
	}
	if !got.Valid {
		t.Errorf("one colour is a warning, not a breach: %v", findingCodes(got))
	}
}

// Metadata may carry arbitrary namespaced XML, so element names inside it are
// not checked. A real logo exported by design software depends on this.
func TestValidateSVGPSAllowsForeignXMLInsideMetadata(t *testing.T) {
	doc := `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps">
  <title>With metadata</title>
  <metadata>
    <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
      <rdf:Description><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">x</dc:title></rdf:Description>
    </rdf:RDF>
  </metadata>
  <rect width="10" height="10" fill="red" stroke="blue"/>
</svg>`
	got := ValidateSVGPS([]byte(doc))
	if !got.Valid {
		t.Errorf("findings = %v, want metadata contents left alone", findingCodes(got))
	}
}

// The two lists together are the contract the UI shows: what ran, and what did
// not. Neither may be silently empty.
func TestSVGPSCheckListsAreDocumented(t *testing.T) {
	if len(SVGPSChecks) == 0 || len(SVGPSUnchecked) == 0 {
		t.Fatal("both check lists must be populated")
	}
	seen := map[string]bool{}
	for _, c := range append(append([]SVGPSCheck{}, SVGPSChecks...), SVGPSUnchecked...) {
		if c.Code == "" || c.Rule == "" {
			t.Errorf("incomplete entry: %+v", c)
		}
		if seen[c.Code] {
			t.Errorf("duplicate check code %q", c.Code)
		}
		seen[c.Code] = true
	}
	// Every code a validation can emit must be documented in SVGPSChecks.
	for _, name := range []string{"scripted.svg", "raster.svg", "xxe.svg"} {
		for _, code := range findingCodes(ValidateSVGPS(readFixture(t, name))) {
			if !seen[code] {
				t.Errorf("%s produced undocumented finding code %q", name, code)
			}
		}
	}
}
