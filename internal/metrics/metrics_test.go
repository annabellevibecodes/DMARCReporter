package metrics

import (
	"strings"
	"testing"
)

func TestCatalogueIsComplete(t *testing.T) {
	counts := map[string]int{"C": 8, "S": 6, "A": 8, "P": 6, "R": 8, "T": 15, "X": 19}
	for letter, n := range counts {
		for i := 1; i <= n; i++ {
			id := letter + itoa(i)
			m, ok := Get(id)
			if !ok {
				t.Errorf("%s is missing from the catalogue", id)
				continue
			}
			if m.Name == "" || m.Summary == "" || m.Href == "" {
				t.Errorf("%s has an incomplete entry: %+v", id, m)
			}
			if !strings.HasSuffix(m.Summary, ".") {
				t.Errorf("%s summary should be a sentence: %q", id, m.Summary)
			}
			if len(m.Summary) > 140 {
				t.Errorf("%s summary is %d chars, too long for a tooltip", id, len(m.Summary))
			}
		}
	}
	if len(All) != 8+6+8+6+8+15+19 {
		t.Errorf("catalogue has %d entries, want %d", len(All), 8+6+8+6+8+15+19)
	}
}

func itoa(n int) string {
	if n < 10 {
		return string(rune('0' + n))
	}
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}

func TestTagRendersLinkAndTooltip(t *testing.T) {
	got := string(Tag("C5"))
	for _, want := range []string{`class="metric-id"`, `href="/help/metrics#compliance"`, "title=", ">C5</a>"} {
		if !strings.Contains(got, want) {
			t.Errorf("Tag(C5) = %q, missing %q", got, want)
		}
	}
	if !strings.Contains(got, "Authentication matrix") {
		t.Errorf("Tag(C5) tooltip lacks the metric name: %q", got)
	}
	// Alert rules point at the alerts help page instead.
	if !strings.Contains(string(Tag("X11")), "/help/alerts") {
		t.Error("alert rule should link to the alerts help page")
	}
	// Lower case and padding are tolerated.
	if string(Tag(" c5 ")) != string(Tag("C5")) {
		t.Error("Get should normalise case and whitespace")
	}
}

func TestTagUnknownIDIsPlainText(t *testing.T) {
	if got := string(Tag("Z9")); got != "Z9" {
		t.Errorf("unknown id = %q, want plain text", got)
	}
	// An unknown id must not be able to inject markup.
	if got := string(Tag(`<img src=x onerror=alert(1)>`)); strings.Contains(got, "<img") {
		t.Errorf("unknown id was not escaped: %q", got)
	}
}

func TestRangeTag(t *testing.T) {
	got := string(RangeTag("A1", "A8"))
	if !strings.Contains(got, ">A1–A8</a>") {
		t.Errorf("RangeTag = %q, want the range as its label", got)
	}
	if !strings.Contains(got, "/help/metrics#auth") {
		t.Errorf("RangeTag = %q, want the family anchor", got)
	}
	if got := string(RangeTag("Z1", "Z9")); got != "Z1–Z9" {
		t.Errorf("unknown family = %q, want plain text", got)
	}
}

func TestIDsAreOrderedByFamily(t *testing.T) {
	ids := IDs()
	if len(ids) != len(All) {
		t.Fatalf("IDs() returned %d, want %d", len(ids), len(All))
	}
	if ids[0] != "C1" {
		t.Errorf("first id = %q, want C1", ids[0])
	}
	if ids[len(ids)-1] != "X19" {
		t.Errorf("last id = %q, want X19", ids[len(ids)-1])
	}
	// X10 must sort after X9, not between X1 and X2.
	var x9, x10 int
	for i, id := range ids {
		switch id {
		case "X9":
			x9 = i
		case "X10":
			x10 = i
		}
	}
	if x10 < x9 {
		t.Error("X10 sorted before X9")
	}
}
