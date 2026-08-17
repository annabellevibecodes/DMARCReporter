package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// IsTLSRPTFile returns true if the filename looks like an SMTP TLS report
// (RFC 8460): JSON, optionally gzip-compressed.
func IsTLSRPTFile(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".json.gz")
}

// TLSReport is the RFC 8460 JSON report structure (subset).
type TLSReport struct {
	OrganizationName string `json:"organization-name"`
	DateRange        struct {
		Start time.Time `json:"start-datetime"`
		End   time.Time `json:"end-datetime"`
	} `json:"date-range"`
	ContactInfo string `json:"contact-info"`
	ReportID    string `json:"report-id"`
	Policies    []struct {
		Policy struct {
			PolicyType   string `json:"policy-type"`
			PolicyDomain string `json:"policy-domain"`
		} `json:"policy"`
		Summary struct {
			TotalSuccess int64 `json:"total-successful-session-count"`
			TotalFailure int64 `json:"total-failure-session-count"`
		} `json:"summary"`
	} `json:"policies"`
}

// Domains returns the distinct policy domains covered by the report.
func (r *TLSReport) Domains() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range r.Policies {
		d := p.Policy.PolicyDomain
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// Totals returns the summed successful and failed session counts.
func (r *TLSReport) Totals() (success, failure int64) {
	for _, p := range r.Policies {
		success += p.Summary.TotalSuccess
		failure += p.Summary.TotalFailure
	}
	return success, failure
}

// ParseTLSRPT decompresses (if needed) and parses an RFC 8460 TLS report,
// returning the parsed report and the raw JSON bytes.
func ParseTLSRPT(filename string, r io.Reader) (*TLSReport, []byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxDecompressedSize))
	if err != nil {
		return nil, nil, fmt.Errorf("read %q: %w", filename, err)
	}
	if strings.HasSuffix(strings.ToLower(filename), ".gz") || looksGzip(data) {
		jr, err := gunzip(data)
		if err != nil {
			return nil, nil, fmt.Errorf("gunzip %q: %w", filename, err)
		}
		data, err = io.ReadAll(jr)
		if err != nil {
			return nil, nil, err
		}
	}
	var report TLSReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, nil, fmt.Errorf("parse tlsrpt %q: %w", filename, err)
	}
	if report.ReportID == "" {
		return nil, nil, fmt.Errorf("invalid TLS report %q: missing report-id", filename)
	}
	return &report, data, nil
}

func looksGzip(data []byte) bool {
	return bytes.HasPrefix(data, []byte{0x1f, 0x8b})
}
