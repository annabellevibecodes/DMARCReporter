package imap

import (
	"fmt"

	imapc "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/importer"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// Attachment holds the raw bytes and filename of a report attachment
// (DMARC aggregate XML or TLS-RPT JSON, possibly compressed). It is the
// importer's Attachment type; the alias keeps the Graph fetcher and older
// callers compiling.
type Attachment = importer.Attachment

// candidateMediaTypes are MIME types under which report attachments arrive
// when the filename alone is not conclusive.
var candidateMediaTypes = map[string]bool{
	"application/gzip":             true,
	"application/x-gzip":           true,
	"application/zip":              true,
	"application/x-zip-compressed": true,
	"text/xml":                     true,
	"application/xml":              true,
	"application/tlsrpt+json":      true,
	"application/tlsrpt+gzip":      true,
}

// FetchReports fetches messages from srcMailbox that have not been examined
// before, extracts report attachments, moves messages carrying reports to
// processedMailbox, and records report-free messages in the seen-UID cache so
// they are never downloaded again.
//
// The examination is two-phase: a cheap BODYSTRUCTURE fetch identifies
// messages with candidate attachment parts, and only those get a full body
// download.
func FetchReports(c *imapclient.Client, db *sqlx.DB, accountID int64, srcMailbox, processedMailbox string) ([]Attachment, error) {
	audit.Debug("imap: selecting mailbox %q", srcMailbox)
	selData, err := c.Select(srcMailbox, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("select %q: %w", srcMailbox, err)
	}

	seen, err := database.GetSeenUIDs(db, accountID, selData.UIDValidity)
	if err != nil {
		return nil, fmt.Errorf("load seen uids: %w", err)
	}

	searchData, err := c.UIDSearch(&imapc.SearchCriteria{}, nil).Wait()
	if err != nil {
		return nil, fmt.Errorf("search all: %w", err)
	}
	if searchData.All == nil {
		audit.Debug("imap: mailbox is empty")
		return nil, nil
	}
	uidSet, ok := searchData.All.(imapc.UIDSet)
	if !ok || len(uidSet) == 0 {
		audit.Debug("imap: search result type=%T — mailbox is empty", searchData.All)
		return nil, nil
	}

	// Expand ranges and drop UIDs already examined in a previous run.
	var unseen imapc.UIDSet
	var unseenCount int
	for _, r := range uidSet {
		for u := r.Start; u <= r.Stop; u++ {
			if !seen[uint32(u)] {
				unseen = append(unseen, imapc.UIDRange{Start: u, Stop: u})
				unseenCount++
			}
			if u == r.Stop { // avoid overflow wraparound on max uint32
				break
			}
		}
	}
	audit.Debug("imap: %d message(s) in mailbox, %d not yet examined", countUIDs(uidSet), unseenCount)
	if unseenCount == 0 {
		return nil, nil
	}

	// Phase 1: BODYSTRUCTURE only — find messages with candidate report parts.
	structOpts := &imapc.FetchOptions{
		BodyStructure: &imapc.FetchItemBodyStructure{Extended: true},
		UID:           true,
	}
	structCmd := c.Fetch(unseen, structOpts)
	var (
		candidates  imapc.UIDSet
		noCandidate []uint32
	)
	for {
		msg := structCmd.Next()
		if msg == nil {
			break
		}
		buf, err := msg.Collect()
		if err != nil {
			audit.Debug("imap: bodystructure collect error: %v", err)
			continue
		}
		if buf.UID == 0 {
			continue
		}
		if hasCandidatePart(buf.BodyStructure) {
			candidates = append(candidates, imapc.UIDRange{Start: buf.UID, Stop: buf.UID})
		} else {
			noCandidate = append(noCandidate, uint32(buf.UID))
		}
	}
	if err := structCmd.Close(); err != nil {
		return nil, fmt.Errorf("bodystructure fetch: %w", err)
	}
	audit.Debug("imap: %d candidate message(s), %d without report parts", len(candidates), len(noCandidate))

	var attachments []Attachment
	var processedSet imapc.UIDSet

	// Phase 2: full body download for candidates only.
	if len(candidates) > 0 {
		fetchOpts := &imapc.FetchOptions{
			// BODY.PEEK[] keeps the message retryable if the move fails.
			BodySection: []*imapc.FetchItemBodySection{{Peek: true}},
			UID:         true,
		}
		fetchCmd := c.Fetch(candidates, fetchOpts)
		for {
			msg := fetchCmd.Next()
			if msg == nil {
				break
			}
			buf, err := msg.Collect()
			if err != nil {
				audit.Debug("imap: body collect error: %v", err)
				continue
			}
			var bodyBytes []byte
			for _, section := range buf.BodySection {
				bodyBytes = section.Bytes
				break
			}
			if len(bodyBytes) == 0 {
				audit.Debug("imap: uid=%d empty body, skipping", buf.UID)
				continue
			}
			atts, err := extractAttachments(bodyBytes)
			if err != nil {
				audit.Debug("imap: uid=%d extractAttachments error: %v", buf.UID, err)
			}
			if len(atts) == 0 {
				// BODYSTRUCTURE looked promising but nothing usable inside.
				if buf.UID != 0 {
					noCandidate = append(noCandidate, uint32(buf.UID))
				}
				continue
			}
			attachments = append(attachments, atts...)
			if buf.UID != 0 {
				processedSet = append(processedSet, imapc.UIDRange{Start: buf.UID, Stop: buf.UID})
			}
		}
		if err := fetchCmd.Close(); err != nil {
			return nil, fmt.Errorf("body fetch: %w", err)
		}
	}

	// Move messages that carried reports to the processed mailbox.
	if len(processedSet) > 0 {
		audit.Debug("imap: moving %d message(s) to %q", len(processedSet), processedMailbox)
		if _, err := c.Move(processedSet, processedMailbox).Wait(); err != nil {
			return attachments, fmt.Errorf("move to %q: %w", processedMailbox, err)
		}
	}

	// Remember report-free messages so the next run skips them entirely.
	if err := database.MarkUIDsSeen(db, accountID, selData.UIDValidity, noCandidate); err != nil {
		return attachments, fmt.Errorf("mark uids seen: %w", err)
	}

	audit.Debug("imap: fetch complete — %d attachment(s), %d moved, %d cached as report-free",
		len(attachments), len(processedSet), len(noCandidate))
	return attachments, nil
}

func countUIDs(set imapc.UIDSet) int {
	n := 0
	for _, r := range set {
		n += int(r.Stop-r.Start) + 1
	}
	return n
}

// hasCandidatePart reports whether the body structure contains any part that
// could be a DMARC or TLS-RPT report attachment.
func hasCandidatePart(bs imapc.BodyStructure) bool {
	if bs == nil {
		return false
	}
	found := false
	bs.Walk(func(path []int, part imapc.BodyStructure) bool {
		if found {
			return false
		}
		sp, ok := part.(*imapc.BodyStructureSinglePart)
		if !ok {
			return true
		}
		if parser.IsDMARCFile(sp.Filename()) || parser.IsTLSRPTFile(sp.Filename()) {
			found = true
			return false
		}
		if candidateMediaTypes[sp.MediaType()] {
			found = true
			return false
		}
		return true
	})
	return found
}

// extractAttachments parses an RFC 2822 message and returns report attachments,
// each stamped with the message's Date header.
func extractAttachments(raw []byte) ([]Attachment, error) {
	parts, _, err := parser.ExtractEMLAttachments(raw, func(format string, args ...any) {
		audit.Debug("imap: "+format, args...)
	})
	if err != nil {
		return nil, err
	}
	attachments := make([]Attachment, 0, len(parts))
	for _, p := range parts {
		attachments = append(attachments, Attachment{
			Filename:   p.Filename,
			Data:       p.Data,
			ReceivedAt: p.ReceivedAt,
			// The whole message, for the RFC 8460 §3 DKIM check on TLS reports.
			RawMessage: raw,
		})
	}
	return attachments, nil
}
