package parser

import (
	"encoding/xml"
	"fmt"
	"io"

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
	return &fb, nil
}
