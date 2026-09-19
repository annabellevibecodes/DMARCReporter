package bimi

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SVG Tiny Portable/Secure validation, per draft-svg-tiny-ps-abrotman-09.
//
// Every rule below cites the section it comes from. Rules the draft states
// that this code does not check are listed in SVGPSUnchecked rather than
// silently omitted: a validator that quietly skips a rule reads exactly like
// one that passed it, and an operator cannot tell the difference.

// Parsing bounds. An indicator is a logo of a few kilobytes; anything that
// needs more structure than this is not a logo, and the limits exist so a
// hostile document cannot turn one Enrich run into an outage.
const (
	maxSVGDepth  = 64
	maxSVGTokens = 200_000
	// svgpsSizeLimit is the 32 kB the draft §2.4 says a document SHOULD NOT
	// exceed, measured uncompressed.
	svgpsSizeLimit = 32 * 1024
)

// Finding is one named check result. The code is stable and machine-readable;
// the message explains it to a person looking at the domain page.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// SVGPSCheck documents one rule this implementation actually enforces.
type SVGPSCheck struct {
	Code string `json:"code"`
	Rule string `json:"rule"`
}

// SVGPSChecks is what a clean B7 result means: these rules ran and passed.
var SVGPSChecks = []SVGPSCheck{
	{"svgps_not_xml", "the document parses as XML at all"},
	{"svgps_doctype", "§3: no DOCTYPE declaration (the vehicle for entity-expansion and external-entity attacks)"},
	{"svgps_depth", "nesting stays within a bound this implementation sets"},
	{"svgps_root", "§2.1: the root element is <svg>"},
	{"svgps_namespace", `§2.1: xmlns="http://www.w3.org/2000/svg"`},
	{"svgps_version", `§2.1: version="1.2"`},
	{"svgps_base_profile", `§2.1: baseProfile="tiny-ps"`},
	{"svgps_root_xy", "§6.2: no x or y attribute on the root element"},
	{"svgps_title", "§2.1: exactly one non-empty <title> as a child of <svg>"},
	{"svgps_title_long", "§2.1: the title SHOULD be at most 64 characters"},
	{"svgps_desc_empty", "§2.1: a <desc>, if present, is not empty"},
	{"svgps_element", "§2.3 and §7: only elements the profile's RNC grammar permits"},
	{"svgps_attribute", "§2.3: zoomAndPan, externalResourcesRequired, focusable, snapshotTime, playbackOrder and timelineBegin hold their required values"},
	{"svgps_event_attribute", "§2.3 sections 13 and 15: no event-handler attributes"},
	{"svgps_external_reference", "§2.3 section 14: no references outside the document"},
	{"svgps_size", "§2.4: the uncompressed document SHOULD NOT exceed 32 kB"},
	{"svgps_colors", "§2.4: at least two colours are rendered"},
}

// SVGPSUnchecked is the honest other half: rules the draft states that this
// implementation does not verify. A document can satisfy every check above and
// still breach one of these.
var SVGPSUnchecked = []SVGPSCheck{
	{"animation_attributes", "§2.2: that d, pathLength, x, y, width, height, rx, ry, rotate and the painting attributes are not animated — the animation *elements* that would do so are rejected outright, so this is only reachable through a mechanism already refused"},
	{"rnc_attribute_grammar", "§7: the full per-element attribute grammar of the RNC. Element names are checked against it; attribute names within an element are not"},
	{"font_subsetting", "§2.4 section 17: that an embedded font contains only the glyphs it renders"},
	{"render_semantics", "§2.4: anything that needs the document to be rendered, including whether transparency produces a usable mark"},
}

// svgpsElements is the element set the draft's RelaxNG grammar (§7) permits.
// Everything else — image, a, script, switch, the animation and multimedia
// elements — is outside the profile by construction, which is why there is no
// separate blocklist to keep in step with the draft.
var svgpsElements = map[string]bool{
	"svg": true, "g": true, "defs": true, "title": true, "desc": true,
	"use": true, "rect": true, "circle": true, "ellipse": true, "line": true,
	"polyline": true, "polygon": true, "path": true, "text": true,
	"textArea": true, "linearGradient": true, "radialGradient": true,
	"stop": true, "solidColor": true, "font": true, "font-face": true,
	"glyph": true, "hkern": true, "metadata": true,
}

// svgpsAttrValues are the attributes §2.3 allows only at one value.
var svgpsAttrValues = map[string]string{
	"zoomAndPan":                "disable",
	"externalResourcesRequired": "false",
	"focusable":                 "false",
	"snapshotTime":              "none",
	"playbackOrder":             "all",
	"timelineBegin":             "onLoad",
}

// svgEntities is the set of entities the parser will expand: the five
// predefined ones and nothing else. A non-nil map is what disables custom
// entity expansion in encoding/xml, which is what makes a billion-laughs
// document fail to parse instead of consuming the process.
var svgEntities = map[string]string{
	"amp": "&", "apos": "'", "quot": `"`, "lt": "<", "gt": ">",
}

// SVGPSResult is B7 for one document.
type SVGPSResult struct {
	// Valid is true when no finding is an outright breach of the profile.
	Valid    bool      `json:"valid"`
	Title    string    `json:"title,omitempty"`
	Bytes    int       `json:"bytes"`
	Elements []string  `json:"elements,omitempty"`
	Colors   []string  `json:"colors,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// ValidateSVGPS checks an uncompressed SVG document against the profile.
//
// The document is parsed, never rendered and never executed. The parser is the
// hardened one: custom entities are refused, nesting and token count are
// bounded, and external entities are unreachable because encoding/xml has no
// mechanism to fetch them.
func ValidateSVGPS(data []byte) SVGPSResult {
	out := SVGPSResult{Bytes: len(data)}
	add := func(severity, code, format string, args ...any) {
		out.Findings = append(out.Findings, Finding{
			Code: code, Severity: severity, Message: fmt.Sprintf(format, args...),
		})
	}

	if len(data) > svgpsSizeLimit {
		add(SeverityWarning, "svgps_size",
			"the document is %d bytes uncompressed; §2.4 says it should not exceed %d",
			len(data), svgpsSizeLimit)
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Entity = svgEntities
	dec.Strict = true

	var (
		depth       int
		tokens      int
		root        bool
		titles      int
		metadataAt  = -1 // depth at which a <metadata> subtree began
		elements    = map[string]bool{}
		colours     = map[string]bool{}
		inTitle     bool
		inDesc      bool
		titleText   strings.Builder
		descText    strings.Builder
		titleDepth  int
		descDepth   int
		depthFlag   bool
		elementFlag = map[string]bool{}
	)

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			add(SeverityError, "svgps_not_xml", "the document does not parse as XML: %v", err)
			out.Valid = false
			return out
		}
		if tokens++; tokens > maxSVGTokens {
			add(SeverityError, "svgps_not_xml",
				"the document has more than %d XML tokens, which no brand indicator needs", maxSVGTokens)
			out.Valid = false
			return out
		}

		switch t := tok.(type) {
		case xml.Directive:
			if name := directiveName(t); strings.EqualFold(name, "DOCTYPE") {
				add(SeverityError, "svgps_doctype",
					"the document carries a DOCTYPE declaration; it is where entity-expansion and external-entity attacks live, and a brand indicator has no use for one")
			}

		case xml.ProcInst:
			// The XML declaration is fine; anything else is a processing
			// instruction the profile has no element for.
			if t.Target != "xml" {
				add(SeverityError, "svgps_element",
					"the document carries a <?%s?> processing instruction", t.Target)
			}

		case xml.StartElement:
			depth++
			if depth > maxSVGDepth && !depthFlag {
				depthFlag = true
				add(SeverityError, "svgps_depth",
					"the document nests more than %d elements deep", maxSVGDepth)
			}
			name := t.Name.Local

			if !root {
				root = true
				checkSVGRoot(t, add)
				if name != "svg" {
					add(SeverityError, "svgps_root", "the root element is <%s>, not <svg>", name)
				}
			}
			elements[name] = true

			// A <metadata> subtree may carry arbitrary namespaced XML (RDF and
			// the like), so element names inside it are not the profile's
			// business. Depth and token bounds still apply.
			if metadataAt < 0 && name == "metadata" {
				metadataAt = depth
			}
			if metadataAt < 0 {
				if !svgpsElements[name] && !elementFlag[name] {
					elementFlag[name] = true
					add(SeverityError, "svgps_element",
						"<%s> is not in the profile's grammar (§7)%s", name, elementNote(name))
				}
				checkSVGAttrs(t, add, colours)
			}

			switch {
			case name == "title" && depth == 2:
				titles++
				inTitle, titleDepth = true, depth
				titleText.Reset()
			case name == "desc" && depth == 2:
				inDesc, descDepth = true, depth
			}

		case xml.EndElement:
			if metadataAt == depth {
				metadataAt = -1
			}
			if inTitle && depth == titleDepth {
				inTitle = false
			}
			if inDesc && depth == descDepth {
				inDesc = false
			}
			depth--

		case xml.CharData:
			if inTitle {
				titleText.Write(t)
			}
			if inDesc {
				descText.Write(t)
			}
		}
	}

	out.Title = strings.TrimSpace(titleText.String())
	switch {
	case titles == 0:
		add(SeverityError, "svgps_title", "there is no <title> element; §2.1 requires one")
	case titles > 1:
		add(SeverityError, "svgps_title",
			"there are %d <title> elements directly under <svg>; §2.1 allows exactly one", titles)
	case out.Title == "":
		add(SeverityError, "svgps_title", "the <title> element is empty; §2.1 requires content")
	case len(out.Title) > 64:
		add(SeverityWarning, "svgps_title_long",
			"the title is %d characters; §2.1 says it should be at most 64", len(out.Title))
	}
	if inDescSeen(descText.String(), elements) {
		add(SeverityError, "svgps_desc_empty", "the <desc> element is present but empty; §2.1 requires content when it is used")
	}

	if len(colours) < 2 {
		add(SeverityWarning, "svgps_colors",
			"only %d distinct colour value(s) were found; §2.4 requires at least two when rendered. Colours are counted from fill, stroke, stop-color, color and solid-color values, so a document that sets its colours through a stylesheet or through currentColor may satisfy the rule without being counted here",
			len(colours))
	}

	out.Elements = sortedKeys(elements)
	out.Colors = sortedKeys(colours)
	out.Valid = true
	for _, f := range out.Findings {
		if f.Severity == SeverityError {
			out.Valid = false
		}
	}
	return out
}

// checkSVGRoot applies the §2.1 requirements that live on the root element.
func checkSVGRoot(t xml.StartElement, add func(string, string, string, ...any)) {
	var ns, version, profile string
	for _, a := range t.Attr {
		switch {
		case a.Name.Local == "xmlns" && a.Name.Space == "":
			ns = a.Value
		case a.Name.Local == "version":
			version = a.Value
		case a.Name.Local == "baseProfile":
			profile = a.Value
		case a.Name.Local == "x" || a.Name.Local == "y":
			// §6.2: Illustrator adds these, and they are not permitted.
			add(SeverityError, "svgps_root_xy",
				"the root element has an %s attribute, which the profile does not permit (§6.2)", a.Name.Local)
		}
	}
	// encoding/xml resolves xmlns into the element's namespace rather than
	// leaving it as an attribute, so fall back to that when it is absent.
	if ns == "" {
		ns = t.Name.Space
	}
	if ns != "http://www.w3.org/2000/svg" {
		add(SeverityError, "svgps_namespace",
			`the SVG namespace is %q; §2.1 requires "http://www.w3.org/2000/svg"`, ns)
	}
	if version != "1.2" {
		add(SeverityError, "svgps_version",
			`version=%q; §2.1 requires "1.2"`, version)
	}
	if profile != "tiny-ps" {
		add(SeverityError, "svgps_base_profile",
			`baseProfile=%q; §2.1 requires "tiny-ps"`, profile)
	}
}

// checkSVGAttrs applies the per-attribute rules and collects colour values.
func checkSVGAttrs(t xml.StartElement, add func(string, string, string, ...any), colours map[string]bool) {
	for _, a := range t.Attr {
		name := a.Name.Local

		if want, ok := svgpsAttrValues[name]; ok && a.Value != want {
			add(SeverityError, "svgps_attribute",
				`<%s %s=%q>: §2.3 allows this attribute only with the value %q`,
				t.Name.Local, name, a.Value, want)
		}
		if len(name) > 2 && strings.HasPrefix(name, "on") {
			add(SeverityError, "svgps_event_attribute",
				"<%s> carries the event-handler attribute %s; §2.3 excludes interactivity and scripting",
				t.Name.Local, name)
		}
		if name == "href" || (a.Name.Space == "xlink" && name == "href") {
			if ref := strings.TrimSpace(a.Value); ref != "" && !strings.HasPrefix(ref, "#") {
				add(SeverityError, "svgps_external_reference",
					"<%s> references %s, which is outside the document; §2.3 excludes linking",
					t.Name.Local, truncate(ref, 60))
			}
		}
		if lower := strings.ToLower(a.Value); strings.Contains(lower, "javascript:") {
			add(SeverityError, "svgps_event_attribute",
				"<%s %s> contains a javascript: URI", t.Name.Local, name)
		}

		switch name {
		case "fill", "stroke", "stop-color", "color", "solid-color":
			if v := normaliseColour(a.Value); v != "" {
				colours[v] = true
			}
		case "style":
			for _, decl := range strings.Split(a.Value, ";") {
				prop, value, ok := strings.Cut(decl, ":")
				if !ok {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(prop)) {
				case "fill", "stroke", "stop-color", "color", "solid-color":
					if v := normaliseColour(value); v != "" {
						colours[v] = true
					}
				}
			}
		}
	}
}

// normaliseColour returns a comparable colour value, or "" for the values that
// paint nothing and so cannot count towards the two-colour rule.
func normaliseColour(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch v {
	case "", "none", "transparent", "inherit", "currentcolor":
		return ""
	}
	if strings.HasPrefix(v, "url(") {
		return "" // a paint server; its own stops are counted where they are defined
	}
	return v
}

// inDescSeen reports a <desc> element that exists but has no content.
func inDescSeen(text string, elements map[string]bool) bool {
	return elements["desc"] && strings.TrimSpace(text) == ""
}

// elementNote names the rule behind the better-known exclusions, so a finding
// explains itself without the operator going to the draft.
func elementNote(name string) string {
	switch name {
	case "image":
		return " — §2.3 excludes the image element, so a logo cannot embed a raster"
	case "script", "handler":
		return " — §2.3 excludes scripting"
	case "a":
		return " — §2.3 excludes linking"
	case "switch":
		return " — §2.3 excludes conditional processing"
	case "animate", "animateColor", "animateMotion", "animateTransform", "set", "discard", "mpath":
		return " — §2.3 excludes animation"
	case "audio", "video", "animation":
		return " — §2.3 excludes multimedia"
	case "foreignObject":
		return " — the profile has no element for foreign content"
	}
	return ""
}

func directiveName(d xml.Directive) string {
	fields := strings.Fields(string(d))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
