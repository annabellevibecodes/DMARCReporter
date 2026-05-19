package parser

import (
	"bytes"
	"fmt"
	"io"

	"github.com/emersion/go-message/mail"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// ParseEML parses an RFC 2822 email and returns all DMARC report feedbacks
// found as attachments within it, along with each attachment's filename and
// the raw decompressed XML bytes for each attachment.
func ParseEML(r io.Reader) ([]*models.Feedback, []string, [][]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read eml: %w", err)
	}

	mr, err := mail.CreateReader(bytes.NewReader(data))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse mail: %w", err)
	}

	var feedbacks []*models.Feedback
	var filenames []string
	var rawXMLs [][]byte

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		var filename string
		switch h := part.Header.(type) {
		case *mail.AttachmentHeader:
			filename, _ = h.Filename()
		case *mail.InlineHeader:
			_, params, _ := h.ContentDisposition()
			filename = params["filename"]
			if filename == "" {
				_, params, _ = h.ContentType()
				filename = params["name"]
			}
		default:
			continue
		}

		if !IsDMARCFile(filename) {
			continue
		}

		attData, err := io.ReadAll(io.LimitReader(part.Body, maxDecompressedSize+1))
		if err != nil {
			continue
		}

		fb, xmlBytes, err := Parse(filename, bytes.NewReader(attData))
		if err != nil {
			continue
		}

		feedbacks = append(feedbacks, fb)
		filenames = append(filenames, filename)
		rawXMLs = append(rawXMLs, xmlBytes)
	}

	if len(feedbacks) == 0 {
		return nil, nil, nil, fmt.Errorf("no DMARC report attachments found in email")
	}
	return feedbacks, filenames, rawXMLs, nil
}

