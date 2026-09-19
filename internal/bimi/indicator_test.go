package bimi

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func indicatorCodes(r IndicatorResult) []string {
	out := []string{}
	for _, f := range r.Findings {
		out = append(out, f.Code)
	}
	return out
}

func hasIndicatorCode(r IndicatorResult, code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestFetchIndicatorHealthy(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	srv, f := serve(t, "image/svg+xml", svg)

	got := FetchIndicator(context.Background(), f, srv.URL+"/logo.svg")
	if !got.Valid {
		t.Fatalf("a conforming logo did not validate: %v", indicatorCodes(got))
	}
	if got.Bytes != len(svg) || got.SHA256 == "" {
		t.Errorf("bytes = %d hash = %q", got.Bytes, got.SHA256)
	}
	if got.Compressed {
		t.Error("an uncompressed document was recorded as compressed")
	}
	if !got.SVGPS.Valid || got.SVGPS.Title != "Example, Inc." {
		t.Errorf("profile result = %+v", got.SVGPS)
	}
}

// An SVGZ hashes as its uncompressed contents, so the same logo served both
// ways is the same mark — which is what B9 has to be able to conclude.
func TestFetchIndicatorHandlesSVGZ(t *testing.T) {
	svg := readFixture(t, "valid.svg")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(svg)
	zw.Close()

	plainSrv, plainFetcher := serve(t, "image/svg+xml", svg)
	plain := FetchIndicator(context.Background(), plainFetcher, plainSrv.URL+"/logo.svg")

	// Served as a .svgz file with gzipped bytes in the body.
	zSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(buf.Bytes())
	}))
	defer zSrv.Close()
	got := FetchIndicator(context.Background(), testFetcher(zSrv), zSrv.URL+"/logo.svgz")

	if !got.Compressed {
		t.Error("the gzipped document was not recognised")
	}
	if got.SHA256 != plain.SHA256 {
		t.Errorf("svgz hash %s != svg hash %s; the hash must be over the uncompressed bytes",
			got.SHA256, plain.SHA256)
	}
	if !got.Valid {
		t.Errorf("findings = %v", indicatorCodes(got))
	}
}

// §4.3.2: a URI ending in another image format is a permanent error, decided
// before anything is fetched.
func TestFetchIndicatorRejectsNonSVGSuffix(t *testing.T) {
	png := readFixture(t, "valid.svg") // contents do not matter; the suffix decides
	srv, f := serve(t, "image/png", png)

	got := FetchIndicator(context.Background(), f, srv.URL+"/logo.png")
	if got.Valid || !hasIndicatorCode(got, "indicator_format") {
		t.Errorf("findings = %v, want the format rejected", indicatorCodes(got))
	}
	if imageSuffix("https://example.com/logo.svg") != "" {
		t.Error("an .svg URI must not be rejected")
	}
	if imageSuffix("https://example.com/logo.png?v=2") != ".png" {
		t.Error("a query string must not hide the suffix")
	}
}

func TestFetchIndicatorReportsTransportProblems(t *testing.T) {
	svg := readFixture(t, "valid.svg")

	t.Run("wrong content type", func(t *testing.T) {
		srv, f := serve(t, "text/plain", svg)
		got := FetchIndicator(context.Background(), f, srv.URL+"/logo.svg")
		if !hasIndicatorCode(got, "indicator_content_type") {
			t.Errorf("findings = %v, want the media type reported", indicatorCodes(got))
		}
		// A wrong media type is a warning: receivers generally still render it.
		if !got.Valid {
			t.Errorf("findings = %v, want it to stay valid", indicatorCodes(got))
		}
	})

	t.Run("redirects", func(t *testing.T) {
		var srv *httptest.Server
		srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/logo.svg" {
				http.Redirect(w, r, srv.URL+"/real.svg", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Write(svg)
		}))
		defer srv.Close()

		got := FetchIndicator(context.Background(), testFetcher(srv), srv.URL+"/logo.svg")
		if !hasIndicatorCode(got, "indicator_redirects") {
			t.Errorf("findings = %v, want the redirect reported", indicatorCodes(got))
		}
		if !got.Valid {
			t.Errorf("findings = %v, want a redirect to stay a warning", indicatorCodes(got))
		}
	})

	t.Run("not found", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "gone", http.StatusNotFound)
		}))
		defer srv.Close()
		got := FetchIndicator(context.Background(), testFetcher(srv), srv.URL+"/logo.svg")
		if got.Valid || !hasIndicatorCode(got, "indicator_unreachable") {
			t.Errorf("findings = %v, want the retrieval failure", indicatorCodes(got))
		}
	})

	t.Run("untrusted TLS chain", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(svg)
		}))
		defer srv.Close()
		f := &Fetcher{allowPrivate: true} // no test roots: the chain will not verify
		got := FetchIndicator(context.Background(), f, srv.URL+"/logo.svg")
		if got.Valid || !hasIndicatorCode(got, "indicator_tls") {
			t.Errorf("findings = %v, want the TLS failure reported as its own finding", indicatorCodes(got))
		}
	})
}

// A logo that breaks the profile is reported with the profile's findings, each
// carried through under an indicator_ code so the UI can group them.
func TestFetchIndicatorCarriesProfileFindings(t *testing.T) {
	srv, f := serve(t, "image/svg+xml", readFixture(t, "raster.svg"))
	got := FetchIndicator(context.Background(), f, srv.URL+"/logo.svg")
	if got.Valid {
		t.Fatalf("findings = %v, want the profile breach to count", indicatorCodes(got))
	}
	found := false
	for _, code := range indicatorCodes(got) {
		if strings.HasPrefix(code, "indicator_") && strings.Contains(code, "element") {
			found = true
		}
	}
	if !found {
		t.Errorf("findings = %v, want the profile finding carried through", indicatorCodes(got))
	}
}

// A billion-laughs document served as a logo must fail the same way it does
// from a file, and must not hold up the run.
func TestFetchIndicatorContainsHostileDocuments(t *testing.T) {
	srv, f := serve(t, "image/svg+xml", readFixture(t, "billion_laughs.svg"))
	got := FetchIndicator(context.Background(), f, srv.URL+"/logo.svg")
	if got.Valid {
		t.Fatal("a billion-laughs document validated")
	}
	if !hasIndicatorCode(got, "indicator_doctype") {
		t.Errorf("findings = %v, want the DOCTYPE reported", indicatorCodes(got))
	}
}
