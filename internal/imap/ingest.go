package imap

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
	"github.com/jmoiron/sqlx"
)

// IngestAll connects to the IMAP server, fetches unseen messages, parses any
// DMARC report attachments, and stores them in the database.
// Returns the number of newly imported reports.
func IngestAll(cfg config.Config, db *sqlx.DB) (int, error) {
	audit.Debug("imap: connecting to %s:%s user=%q tls=%v", cfg.IMAPHost, cfg.IMAPPort, cfg.IMAPUser, cfg.IMAPTLS)
	c, err := Connect(cfg)
	if err != nil {
		return 0, fmt.Errorf("imap connect: %w", err)
	}
	defer c.Logout()
	audit.Debug("imap: connected and logged in successfully")

	attachments, err := FetchUnseen(c, cfg.IMAPMailbox, cfg.IMAPProcessedMailbox)
	if err != nil {
		return 0, fmt.Errorf("fetch unseen: %w", err)
	}
	audit.Debug("imap: %d attachment(s) total ready for parsing", len(attachments))

	imported := 0
	for i, att := range attachments {
		audit.Debug("imap: parsing attachment %d/%d filename=%q size=%d", i+1, len(attachments), att.Filename, len(att.Data))
		fb, rawXML, err := parser.Parse(att.Filename, bytes.NewReader(att.Data))
		if err != nil {
			log.Printf("IMAP ingest: skipping unparseable attachment %q: %v", att.Filename, err)
			audit.Debug("imap: parse failed for %q: %v", att.Filename, err)
			continue
		}
		audit.Debug("imap: parsed OK — org=%q domain=%q report_id=%q records=%d",
			fb.ReportMetadata.OrgName, fb.PolicyPublished.Domain,
			fb.ReportMetadata.ReportID, len(fb.Records))

		_, err = database.SaveReport(db, fb, att.Filename, rawXML)
		if err != nil {
			if errors.Is(err, database.ErrDuplicate) {
				audit.Debug("imap: attachment %q is a duplicate, skipping", att.Filename)
				audit.ReportDuplicate(att.Filename, fb.ReportMetadata.OrgName, fb.ReportMetadata.ReportID)
				continue
			}
			return imported, fmt.Errorf("save report %q: %w", att.Filename, err)
		}
		audit.Debug("imap: saved attachment %q successfully", att.Filename)
		audit.ReportImported(att.Filename, fb.ReportMetadata.OrgName,
			fb.PolicyPublished.Domain, fb.ReportMetadata.ReportID, len(fb.Records))
		imported++
	}

	audit.Debug("imap: ingest complete — imported=%d total_attachments=%d", imported, len(attachments))
	return imported, nil
}
