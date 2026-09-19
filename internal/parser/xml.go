package parser

import (
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// standardEntities contains the five predefined XML entities.
// Setting dec.Entity to a non-nil map disables custom entity expansion
// (preventing billion-laughs / XXE attacks) while still allowing these
// standard entities which are used in normal XML documents.
var standardEntities = map[string]string{
	"amp":  "&",
	"apos": "'",
	"quot": "\"",
	"lt":   "<",
	"gt":   ">",
}

// ParseXML decodes a DMARC aggregate report XML from r.
func ParseXML(r io.Reader) (*models.Feedback, error) {
	// Limit decompressed XML to 50 MB regardless of input size.
	limited := io.LimitReader(r, maxDecompressedSize)
	var fb models.Feedback
	dec := xml.NewDecoder(limited)
	// Allow only the 5 standard XML entities; any custom entity declaration
	// (billion laughs, XXE) will be rejected with an unknown-entity error.
	dec.Entity = standardEntities
	if err := dec.Decode(&fb); err != nil {
		return nil, fmt.Errorf("xml decode: %w", err)
	}
	if fb.ReportMetadata.ReportID == "" {
		return nil, fmt.Errorf("invalid DMARC report: missing report_id")
	}
	normalizeRecords(&fb)
	normalizeBIMI(&fb)
	return &fb, nil
}

// normalizeRecords drops records whose source_ip is not an IP address and
// clamps negative message counts. Report content is attacker-controlled
// (anyone can mail a report to the monitored mailbox), and source_ip is later
// handed to reverse-DNS/WHOIS lookups and used as a URL path segment, so only
// well-formed addresses are stored. Whitespace padding is tolerated.
func normalizeRecords(fb *models.Feedback) {
	kept := fb.Records[:0]
	for _, rec := range fb.Records {
		ip := net.ParseIP(strings.TrimSpace(rec.Row.SourceIP))
		if ip == nil {
			continue
		}
		rec.Row.SourceIP = ip.String()
		if rec.Row.Count < 0 {
			rec.Row.Count = 0
		}
		kept = append(kept, rec)
	}
	fb.Records = kept
}
