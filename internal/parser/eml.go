package parser

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/emersion/go-message/mail"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
)

// maxAttachmentSize caps a single report attachment (before decompression).
const maxAttachmentSize = 10 * 1024 * 1024

// EMLAttachment is one report attachment extracted from an RFC 2822 message.
type EMLAttachment struct {
	Filename string
	Data     []byte
	// ReceivedAt is the message's Date header as Unix seconds (0 when absent
	// or unparseable). It is the same for every attachment of one message.
	ReceivedAt int64
}

// ExtractEMLAttachments parses an RFC 2822 message and returns every part whose
// filename looks like a DMARC aggregate report or a TLS-RPT report, together
// with the message Date header. Parts that are too large or unreadable are
// skipped; debug, when non-nil, receives a line per examined part.
func ExtractEMLAttachments(raw []byte, debug func(format string, args ...any)) ([]EMLAttachment, time.Time, error) {
	if debug == nil {
		debug = func(string, ...any) {}
	}
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("parse mail: %w", err)
	}
	var date time.Time
	if d, err := mr.Header.Date(); err == nil {
		date = d
	}
	var receivedAt int64
	if !date.IsZero() {
		receivedAt = date.Unix()
	}

	var out []EMLAttachment
	partNum := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			debug("eml: NextPart error: %v", err)
			break
		}
		partNum++

		// Accept both attachment and inline parts — many DMARC senders use
		// Content-Disposition: inline or text/xml without a disposition header,
		// which the mail library classifies as InlineHeader (no Filename helper).
		var filename string
		switch h := part.Header.(type) {
		case *mail.AttachmentHeader:
			filename, _ = h.Filename()
			debug("eml: part #%d type=AttachmentHeader filename=%q", partNum, filename)
		case *mail.InlineHeader:
			_, params, _ := h.ContentDisposition()
			filename = params["filename"]
			if filename == "" {
				_, params, _ = h.ContentType()
				filename = params["name"]
			}
			ct, _, _ := h.ContentType()
			debug("eml: part #%d type=InlineHeader content-type=%q filename=%q", partNum, ct, filename)
		default:
			debug("eml: part #%d type=%T — skipping", partNum, part.Header)
			continue
		}

		if !IsDMARCFile(filename) && !IsTLSRPTFile(filename) {
			debug("eml: part #%d filename=%q — not a report attachment, skipping", partNum, filename)
			continue
		}

		data, err := io.ReadAll(io.LimitReader(part.Body, maxAttachmentSize+1))
		if err != nil {
			debug("eml: part #%d filename=%q read error: %v", partNum, filename, err)
			continue
		}
		if int64(len(data)) > maxAttachmentSize {
			debug("eml: part #%d filename=%q exceeds %d byte limit, skipping", partNum, filename, maxAttachmentSize)
			continue
		}
		debug("eml: part #%d filename=%q size=%d bytes — accepted", partNum, filename, len(data))
		out = append(out, EMLAttachment{Filename: filename, Data: data, ReceivedAt: receivedAt})
	}
	return out, date, nil
}

// ParseEML parses an RFC 2822 email and returns all DMARC report feedbacks
// found as attachments within it, along with each attachment's filename and
// the raw decompressed XML bytes for each attachment. TLS-RPT attachments are
// ignored here; use ExtractEMLAttachments to obtain both kinds.
func ParseEML(r io.Reader) ([]*models.Feedback, []string, [][]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read eml: %w", err)
	}
	atts, _, err := ExtractEMLAttachments(data, nil)
	if err != nil {
		return nil, nil, nil, err
	}

	var feedbacks []*models.Feedback
	var filenames []string
	var rawXMLs [][]byte
	for _, att := range atts {
		if !IsDMARCFile(att.Filename) {
			continue
		}
		fb, xmlBytes, err := Parse(att.Filename, bytes.NewReader(att.Data))
		if err != nil {
			continue
		}
		feedbacks = append(feedbacks, fb)
		filenames = append(filenames, att.Filename)
		rawXMLs = append(rawXMLs, xmlBytes)
	}

	if len(feedbacks) == 0 {
		return nil, nil, nil, fmt.Errorf("no DMARC report attachments found in email")
	}
	return feedbacks, filenames, rawXMLs, nil
}
