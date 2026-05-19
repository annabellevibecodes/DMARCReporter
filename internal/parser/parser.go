package parser

import (
	"bytes"
	"fmt"
	"io"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// Parse detects the file format, decompresses if needed, parses the DMARC XML,
// and returns both the parsed report and the raw decompressed XML bytes.
func Parse(filename string, r io.Reader) (*models.Feedback, []byte, error) {
	xmlReader, err := DetectAndDecompress(filename, r)
	if err != nil {
		return nil, nil, fmt.Errorf("decompress %q: %w", filename, err)
	}
	xmlBytes, err := io.ReadAll(xmlReader)
	if err != nil {
		return nil, nil, fmt.Errorf("read xml %q: %w", filename, err)
	}
	fb, err := ParseXML(bytes.NewReader(xmlBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("parse %q: %w", filename, err)
	}
	return fb, xmlBytes, nil
}
