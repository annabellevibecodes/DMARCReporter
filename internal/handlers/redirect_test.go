package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

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

// The second character is what CWE-601 turns on: browsers read "//host" as an
// absolute URL and normalise "/\host" to "//host". "/" itself must stay valid
// — the usual "len(s) > 1" spelling of this guard rejects it by accident.
func TestSafeRedirectChecksSecondCharacter(t *testing.T) {
	for _, s := range []string{"//evil.com", `/\evil.com`, "//", `/\`, `//\evil.com`, `/\/evil.com`} {
		if safeRedirect(s) {
			t.Errorf("safeRedirect(%q) = true, want false (leaves the site)", s)
		}
	}
	for _, s := range []string{"/", "/a", "/?x=1", "/#frag"} {
		if !safeRedirect(s) {
			t.Errorf("safeRedirect(%q) = false, want true (same-origin)", s)
		}
	}
}

// The theme switcher bounces back to the Referer, so a hostile one must not
// steer it off-site — including a Referer whose own path starts "//", which
// passes a leading-slash test but is an absolute URL once redirected to.
func TestSetThemeRefererCannotLeaveSite(t *testing.T) {
	cases := []struct{ referer, want string }{
		{"https://dmarc.example.com/sources?period=30d", "/sources?period=30d"},
		{"https://dmarc.example.com/sources/1.2.3.4", "/sources/1.2.3.4"},
		{"https://evil.com/x", "/x"},
		{"https://evil.com//evil.com", "/"},
		// EscapedPath encodes the backslash, and a percent-encoded one is not
		// decoded before the browser fixes the authority — so this stays a
		// (404) path on our own origin rather than becoming "//evil.com".
		{`https://evil.com/\evil.com`, "/%5Cevil.com"},
		{"https://evil.com", "/"},
		{"//evil.com", "/"},
		{"", "/"},
	}

	app := fiber.New()
	a := &App{}
	app.Get("/theme", a.HandleSetTheme)

	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/theme?t=pink", nil)
		req.Header.Set("Referer", tc.referer)
		resp, err := app.Test(req)
		if err != nil {
			t.Fatalf("Test(referer=%q): %v", tc.referer, err)
		}
		got := resp.Header.Get("Location")
		if got != tc.want {
			t.Errorf("Referer %q redirected to %q, want %q", tc.referer, got, tc.want)
		}
		if !safeRedirect(got) {
			t.Errorf("Referer %q redirected to %q, which safeRedirect rejects", tc.referer, got)
		}
	}
}

// currentPath must stay a path safeRedirect accepts, so the inline forms come
// back to the page instead of falling through to their JSON response. A proxy
// forwarding the request URI in absolute form used to break exactly that.
func TestCurrentPathIsAlwaysRedirectable(t *testing.T) {
	cases := []struct{ requestURI, want string }{
		{"/alerts", "/alerts"},
		{"/alerts?state=open&severity=critical", "/alerts?state=open&severity=critical"},
		{"http://localhost:8199/alerts", "/alerts"},
		{"https://dmarc.example.com/sources/1.2.3.4?period=30d", "/sources/1.2.3.4?period=30d"},
		{"//evil.com/alerts", "/"},
	}

	app := fiber.New()
	for _, tc := range cases {
		fctx := &fasthttp.RequestCtx{}
		fctx.Request.Header.SetHost("dmarc.example.com")
		fctx.Request.SetRequestURI(tc.requestURI)
		c := app.AcquireCtx(fctx)
		got := currentPath(c)
		app.ReleaseCtx(c)

		if got != tc.want {
			t.Errorf("currentPath for request URI %q = %q, want %q", tc.requestURI, got, tc.want)
		}
		if !safeRedirect(got) {
			t.Errorf("currentPath for request URI %q = %q, which safeRedirect rejects", tc.requestURI, got)
		}
	}
}

// Key and Domain come from report data, so a "/" in either must not move the
// link to a different page.
func TestContextHrefEscapesReportData(t *testing.T) {
	cases := []struct {
		al   database.Alert
		want string
	}{
		{database.Alert{Rule: "new_failing_source", Key: "1.2.3.4"}, "/sources/1.2.3.4"},
		{database.Alert{Rule: "new_failing_source", Key: "x/../../admin"}, "/sources/x%2F..%2F..%2Fadmin"},
		{database.Alert{Rule: "policy_changed", Domain: "example.com"}, "/domains/example.com"},
		{database.Alert{Rule: "policy_changed", Domain: "a/b?c=d"}, "/domains/a%2Fb%3Fc=d"},
		{database.Alert{Rule: "reporter_silent", Key: "GMX"}, "/reporters"},
	}
	for _, tc := range cases {
		if got := contextHref(tc.al); got != tc.want {
			t.Errorf("contextHref(%+v) = %q, want %q", tc.al, got, tc.want)
		}
	}
}
