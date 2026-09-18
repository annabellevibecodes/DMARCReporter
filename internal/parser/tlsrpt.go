package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// IsTLSRPTFile returns true if the filename looks like an SMTP TLS report
// (RFC 8460): JSON, optionally gzip-compressed.
func IsTLSRPTFile(filename string) bool {
	lower := strings.ToLower(filename)
	return strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".json.gz")
}

// TLSReport is the RFC 8460 JSON report structure.
type TLSReport struct {
	OrganizationName string `json:"organization-name"`
	DateRange        struct {
		Start time.Time `json:"start-datetime"`
		End   time.Time `json:"end-datetime"`
	} `json:"date-range"`
	ContactInfo string      `json:"contact-info"`
	ReportID    string      `json:"report-id"`
	Policies    []TLSPolicy `json:"policies"`
}

// TLSPolicy is one entry of the report's `policies` array: the policy that was
// applied, the session counts under it, and the per-failure detail rows.
type TLSPolicy struct {
	Policy struct {
		PolicyType string `json:"policy-type"`
		// PolicyString is the policy as the sender saw it, verbatim. RFC 8460
		// defines it as an array of lines; some reporters send a single string.
		PolicyString FlexStrings `json:"policy-string"`
		PolicyDomain string      `json:"policy-domain"`
		// MXHost is the mx-host pattern list. Same array-or-string variance.
		MXHost FlexStrings `json:"mx-host"`
	} `json:"policy"`
	Summary struct {
		TotalSuccess int64 `json:"total-successful-session-count"`
		TotalFailure int64 `json:"total-failure-session-count"`
	} `json:"summary"`
	FailureDetails []TLSFailureDetail `json:"failure-details"`
}

// TLSFailureDetail is one entry of a policy's `failure-details` array. Every
// field except result-type and failed-session-count is optional in RFC 8460,
// so an empty string here means "the reporter did not say", not "empty".
type TLSFailureDetail struct {
	ResultType            string `json:"result-type"`
	SendingMTAIP          string `json:"sending-mta-ip"`
	ReceivingMXHostname   string `json:"receiving-mx-hostname"`
	ReceivingMXHelo       string `json:"receiving-mx-helo"`
	ReceivingIP           string `json:"receiving-ip"`
	FailedSessionCount    int64  `json:"failed-session-count"`
	AdditionalInformation string `json:"additional-information"`
	FailureReasonCode     string `json:"failure-reason-code"`
}

// FlexStrings decodes a JSON field that is an array of strings in RFC 8460 but
// which some reporters send as a single string. Both spellings land as a slice
// so callers never have to care which arrived.
type FlexStrings []string

// UnmarshalJSON accepts a string, an array of strings, or null.
func (f *FlexStrings) UnmarshalJSON(b []byte) error {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*f = nil
		return nil
	}
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err != nil {
			return err
		}
		*f = FlexStrings{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(trimmed, &ss); err != nil {
		return err
	}
	*f = FlexStrings(ss)
	return nil
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
//
// The sum is the report's own arithmetic and is what the legacy TLS report
// list shows. It double-counts a report that describes the same sessions under
// two policy entries (an MTA-STS policy and a TLSA record, say); the rollup
// that collapses those is applied at query time — see database.TLSSessionTotals.
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

// TLSRPTFilenameRange extracts the date range encoded in an RFC 8460 §5.3
// report filename:
//
//	sender-domain!policy-domain!begin-timestamp!end-timestamp[!unique-id].json[.gz]
//
// ok is false when the filename does not follow the convention. The body's
// date-range always wins (§5.6); this exists only so a disagreement between
// the two can be counted as a hygiene finding rather than silently ignored.
func TLSRPTFilenameRange(filename string) (begin, end int64, ok bool) {
	name := filename
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".json.gz"):
		name = name[:len(name)-len(".json.gz")]
	case strings.HasSuffix(lower, ".json"):
		name = name[:len(name)-len(".json")]
	case strings.HasSuffix(lower, ".gz"):
		name = name[:len(name)-len(".gz")]
	}
	parts := strings.Split(name, "!")
	if len(parts) < 4 {
		return 0, 0, false
	}
	begin, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	end, err = strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return begin, end, true
}
