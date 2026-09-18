package handlers

import "testing"

func TestSafeRedirect(t *testing.T) {
	ok := []string{"/", "/sources", "/sources/1.2.3.4?period=7d", "/alerts?state=open&x=%2F%2Fevil"}
	bad := []string{"", "sources", "//evil.com", `/\evil.com`, `\\evil.com`, "https://evil.com/x", "javascript:alert(1)", "/foo\\bar", "///evil.com"}
	for _, s := range ok {
		if !safeRedirect(s) {
			t.Errorf("safeRedirect(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if safeRedirect(s) {
			t.Errorf("safeRedirect(%q) = true, want false", s)
		}
	}
}
