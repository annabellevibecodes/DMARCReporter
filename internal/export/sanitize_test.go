package export

import "testing"

func TestEscapeFormula(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"Example Org", "Example Org"},
		{"admin@example.com", "admin@example.com"},
		{"@example.com", "'@example.com"},
		{"=cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"},
		{"+1+1", "'+1+1"},
		{"-1", "'-1"},
		{"@SUM(1,1)", "'@SUM(1,1)"},
		{"\ttabbed", "'\ttabbed"},
		{"normal-value", "normal-value"},
	}
	for _, c := range cases {
		if got := escapeFormula(c.in); got != c.want {
			t.Errorf("escapeFormula(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
