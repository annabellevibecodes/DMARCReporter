package bimi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
)

// rasterSuffixes are the image formats core spec §4.3.2 makes a permanent
// error: only SVG and SVGZ are in the BIMI-formats registry today, and a URI
// that ends in another image suffix is to be treated as a failure without
// even fetching it.
var rasterSuffixes = []string{".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".ico", ".avif", ".heic"}

// IndicatorResult is B6 and B7 for one indicator: how retrieval went, and
// whether what came back is a conforming SVG Tiny P/S document.
type IndicatorResult struct {
	Fetch FetchResult `json:"fetch"`
	// SHA256 is over the *uncompressed* document, so an SVGZ and the SVG
	// inside it hash the same. B9 compares this against the mark inside the
	// evidence document, which is never compressed once extracted.
	SHA256     string      `json:"sha256,omitempty"`
	Bytes      int         `json:"bytes,omitempty"`
	Compressed bool        `json:"compressed"`
	SVGPS      SVGPSResult `json:"svgps"`
	Findings   []Finding   `json:"findings,omitempty"`
	Valid      bool        `json:"valid"`
}

// FetchIndicator retrieves the document at l= and validates it.
func FetchIndicator(ctx context.Context, f *Fetcher, rawURL string) IndicatorResult {
	var out IndicatorResult
	add := func(severity, code, format string, args ...any) {
		out.Findings = append(out.Findings, Finding{
			Code: code, Severity: severity, Message: fmt.Sprintf(format, args...),
		})
	}

	// §4.3.2: the suffix alone can settle it, before anything is fetched.
	if suffix := imageSuffix(rawURL); suffix != "" {
		add(SeverityError, "indicator_format",
			"the l= URI ends in %s; §4.3.2 makes any format outside the BIMI-formats registry a permanent error, and only SVG is registered today", suffix)
	}

	out.Fetch = f.Fetch(ctx, rawURL)
	switch {
	case out.Fetch.TLSError != "":
		// §7.5 step 2: a chain that does not validate is a retrieval failure,
		// not a warning — the indicator is not displayed.
		add(SeverityError, "indicator_tls",
			"the TLS certificate of the host serving the indicator did not validate: %s", out.Fetch.TLSError)
		return finishIndicator(out)
	case !out.Fetch.OK():
		add(SeverityError, "indicator_unreachable",
			"the indicator could not be retrieved: %s", fetchFailure(out.Fetch))
		return finishIndicator(out)
	}

	if n := len(out.Fetch.Redirects); n > 1 {
		add(SeverityWarning, "indicator_redirects",
			"the indicator was reached after %d redirect(s), ending at %s. Guidance draft §5.6 lets a receiver follow few or none, so each hop is a receiver that may not arrive",
			n-1, out.Fetch.FinalURL)
	}
	if ct := mediaType(out.Fetch.ContentType); ct != "" && ct != "image/svg+xml" {
		add(SeverityWarning, "indicator_content_type",
			"the indicator is served as %s rather than image/svg+xml", ct)
	}

	body := out.Fetch.Body
	if raw, ok := gunzipBytes(body); ok {
		out.Compressed = true
		body = raw
	}
	out.Bytes = len(body)
	sum := sha256.Sum256(body)
	out.SHA256 = hex.EncodeToString(sum[:])

	out.SVGPS = ValidateSVGPS(body)
	for _, fnd := range out.SVGPS.Findings {
		out.Findings = append(out.Findings, Finding{
			Code:     "indicator_" + strings.TrimPrefix(fnd.Code, "svgps_"),
			Severity: fnd.Severity,
			Message:  fnd.Message,
		})
	}
	return finishIndicator(out)
}

// Retrieved reports that bytes came back and were hashed.
//
// It is deliberately not expressed in terms of the fetch result: the retrieved
// body is never stored in a snapshot, so FetchResult.OK() is false for every
// result read back from the database, and a caller that asked it there would
// quietly conclude that no logo had ever been retrieved.
func (r IndicatorResult) Retrieved() bool { return r.SHA256 != "" }

func finishIndicator(out IndicatorResult) IndicatorResult {
	out.Valid = true
	for _, f := range out.Findings {
		if f.Severity == SeverityError {
			out.Valid = false
		}
	}
	return out
}

// AgreementResult is B9: whether the mark served at l= is the mark the
// evidence document vouches for.
//
// Core spec §7.9 requires an MTA to make this comparison when both tags are
// present, so a mismatch is not a nicety — it is the receiver refusing to show
// a logo that every other check here would call healthy.
type AgreementResult struct {
	Checked       bool   `json:"checked"`
	Matches       bool   `json:"matches"`
	IndicatorHash string `json:"indicator_hash,omitempty"`
	EvidenceHash  string `json:"evidence_hash,omitempty"`
	// Note explains why no comparison was made, when Checked is false.
	Note string `json:"note,omitempty"`
}

// CompareMarks performs the §7.9 comparison. Either side being absent means
// there is nothing to compare, which is reported as such rather than as
// agreement.
func CompareMarks(indicator *IndicatorResult, evidence *EvidenceResult) AgreementResult {
	switch {
	case indicator == nil || indicator.SHA256 == "":
		return AgreementResult{Note: "no indicator was retrieved, so there is nothing to compare"}
	case evidence == nil:
		return AgreementResult{Note: "the record publishes no evidence document, so §7.9 does not apply"}
	case evidence.Mark == nil || evidence.Mark.SHA256 == "":
		return AgreementResult{
			IndicatorHash: indicator.SHA256,
			Note:          "no mark could be read out of the evidence document, so there is nothing to compare",
		}
	}
	return AgreementResult{
		Checked:       true,
		Matches:       indicator.SHA256 == evidence.Mark.SHA256,
		IndicatorHash: indicator.SHA256,
		EvidenceHash:  evidence.Mark.SHA256,
	}
}

// Finding renders the comparison as a finding, or false when there is none to
// report.
func (a AgreementResult) Finding() (Finding, bool) {
	if !a.Checked || a.Matches {
		return Finding{}, false
	}
	return Finding{
		Code:     "mark_mismatch",
		Severity: SeverityError,
		Message: fmt.Sprintf(
			"the mark served at l= (%s…) is not the mark inside the evidence document (%s…). Core spec §7.9 requires the receiver to check this, so the logo will not be shown however healthy everything else looks",
			shortHash(a.IndicatorHash), shortHash(a.EvidenceHash)),
	}, true
}

// imageSuffix returns the non-SVG image suffix a URI ends in, or "".
func imageSuffix(rawURL string) string {
	cut := rawURL
	if i := strings.IndexAny(cut, "?#"); i >= 0 {
		cut = cut[:i]
	}
	ext := strings.ToLower(path.Ext(cut))
	for _, s := range rasterSuffixes {
		if ext == s {
			return ext
		}
	}
	return ""
}

// mediaType strips any parameters from a Content-Type header.
func mediaType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	return strings.ToLower(strings.TrimSpace(ct))
}

func shortHash(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
