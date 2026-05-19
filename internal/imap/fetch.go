package imap

import (
	"bytes"
	"fmt"
	"io"

	imapc "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/mail"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// Attachment holds the raw bytes and filename of a DMARC report attachment.
type Attachment struct {
	Filename string
	Data     []byte
}

// FetchUnseen fetches all messages from the source mailbox, extracts
// DMARC report attachments, and moves processed messages to processedMailbox.
// Processed messages are identified by being moved out of the mailbox, not by
// the \Seen flag — any message still present is treated as unprocessed.
func FetchUnseen(c *imapclient.Client, srcMailbox, processedMailbox string) ([]Attachment, error) {
	audit.Debug("imap: selecting mailbox %q", srcMailbox)
	if _, err := c.Select(srcMailbox, nil).Wait(); err != nil {
		return nil, fmt.Errorf("select %q: %w", srcMailbox, err)
	}

	// Fetch ALL messages in the mailbox — processed ones are moved to the
	// processed mailbox, so anything remaining here needs to be imported.
	audit.Debug("imap: searching for all messages in mailbox")
	searchData, err := c.UIDSearch(&imapc.SearchCriteria{}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("search all: %w", err)
	}

	if searchData.All == nil {
		audit.Debug("imap: search returned nil result set — mailbox is empty")
		return nil, nil
	}
	uidSet, ok := searchData.All.(imapc.UIDSet)
	if !ok || len(uidSet) == 0 {
		audit.Debug("imap: search result type=%T len=%d — mailbox is empty", searchData.All, len(uidSet))
		return nil, nil
	}
	audit.Debug("imap: found %d UID range(s): %v", len(uidSet), uidSet)

	// Fetch the full body of each message without marking as \Seen (BODY.PEEK[]).
	// The \Seen flag is implicitly set by the server when BODY[] is used; using
	// Peek prevents that so a failed move or parse leaves the message retryable.
	fetchOpts := &imapc.FetchOptions{
		BodySection: []*imapc.FetchItemBodySection{{Peek: true}},
		UID:         true,
	}
	audit.Debug("imap: fetching message bodies (BODY.PEEK[])")
	fetchCmd := c.Fetch(uidSet, fetchOpts)
	defer fetchCmd.Close()

	var (
		attachments  []Attachment
		processedSet imapc.UIDSet
		msgCount     int
	)

	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		msgCount++
		buf, err := msg.Collect()
		if err != nil {
			audit.Debug("imap: msg #%d collect error: %v", msgCount, err)
			continue
		}
		audit.Debug("imap: msg #%d uid=%d", msgCount, buf.UID)

		// Find the BODY[] section.
		var bodyBytes []byte
		for _, section := range buf.BodySection {
			bodyBytes = section.Bytes
			break
		}
		if len(bodyBytes) == 0 {
			audit.Debug("imap: msg #%d uid=%d — empty body, skipping", msgCount, buf.UID)
			continue
		}
		audit.Debug("imap: msg #%d uid=%d body_size=%d bytes", msgCount, buf.UID, len(bodyBytes))

		atts, err := extractAttachments(bodyBytes)
		if err != nil {
			audit.Debug("imap: msg #%d uid=%d extractAttachments error: %v", msgCount, buf.UID, err)
			continue
		}
		audit.Debug("imap: msg #%d uid=%d extracted %d DMARC attachment(s)", msgCount, buf.UID, len(atts))
		if len(atts) == 0 {
			continue
		}

		attachments = append(attachments, atts...)
		if buf.UID != 0 {
			processedSet = append(processedSet, imapc.UIDRange{Start: buf.UID, Stop: buf.UID})
		}
	}

	audit.Debug("imap: fetched %d message(s), %d had DMARC attachments, moving %d to %q",
		msgCount, len(attachments), len(processedSet), processedMailbox)

	// Move processed messages to the processed mailbox.
	if len(processedSet) > 0 {
		audit.Debug("imap: moving UIDs %v to %q", processedSet, processedMailbox)
		if _, err := c.Move(processedSet, processedMailbox).Wait(); err != nil {
			return attachments, fmt.Errorf("move to %q: %w", processedMailbox, err)
		}
		audit.Debug("imap: move completed successfully")
	}

	return attachments, nil
}

// extractAttachments parses an RFC 2822 message and returns DMARC report attachments.
func extractAttachments(raw []byte) ([]Attachment, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse mail: %w", err)
	}

	var attachments []Attachment
	partNum := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			audit.Debug("imap: extractAttachments NextPart error: %v", err)
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
			audit.Debug("imap: part #%d type=AttachmentHeader filename=%q", partNum, filename)
		case *mail.InlineHeader:
			// Extract filename from Content-Disposition, then fall back to
			// the Content-Type "name" parameter (both are commonly used).
			_, params, _ := h.ContentDisposition()
			filename = params["filename"]
			if filename == "" {
				_, params, _ = h.ContentType()
				filename = params["name"]
			}
			ct, _, _ := h.ContentType()
			audit.Debug("imap: part #%d type=InlineHeader content-type=%q filename=%q", partNum, ct, filename)
		default:
			audit.Debug("imap: part #%d type=%T — skipping", partNum, part.Header)
			continue
		}

		if !parser.IsDMARCFile(filename) {
			audit.Debug("imap: part #%d filename=%q — not a DMARC attachment, skipping", partNum, filename)
			continue
		}

		const maxAttachmentSize = 10 * 1024 * 1024
		data, err := io.ReadAll(io.LimitReader(part.Body, maxAttachmentSize+1))
		if err != nil {
			audit.Debug("imap: part #%d filename=%q read error: %v", partNum, filename, err)
			continue
		}
		if int64(len(data)) > maxAttachmentSize {
			audit.Debug("imap: part #%d filename=%q exceeds %d byte limit, skipping", partNum, filename, maxAttachmentSize)
			continue
		}
		audit.Debug("imap: part #%d filename=%q size=%d bytes — accepted", partNum, filename, len(data))
		attachments = append(attachments, Attachment{
			Filename: filename,
			Data:     data,
		})
	}
	return attachments, nil
}

