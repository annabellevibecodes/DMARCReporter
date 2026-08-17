package imap

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/emersion/go-sasl"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// IngestAccount connects to an account's IMAP server, fetches unexamined
// messages, parses DMARC and TLS-RPT report attachments, and stores them.
// Returns the number of newly imported reports (both kinds).
func IngestAccount(db *sqlx.DB, acc database.Account, password string, saslClient sasl.Client) (int, error) {
	opt := ConnectOptions{
		Host:     acc.Host,
		Port:     acc.Port,
		TLS:      acc.TLS == 1,
		Username: acc.Username,
		Password: password,
		SASL:     saslClient,
	}
	audit.Debug("imap[%s]: connecting to %s:%s user=%q tls=%v", acc.Name, acc.Host, acc.Port, acc.Username, opt.TLS)
	c, err := Connect(opt)
	if err != nil {
		return 0, fmt.Errorf("imap connect: %w", err)
	}
	defer c.Logout()

	processedMailbox, err := ResolveProcessedMailbox(c, acc.Mailbox, acc.ProcessedMailbox)
	if err != nil {
		return 0, err
	}

	attachments, err := FetchReports(c, db, acc.ID, acc.Mailbox, processedMailbox)
	if err != nil {
		return 0, fmt.Errorf("fetch: %w", err)
	}

	return SaveAttachments(db, acc.Name, attachments)
}

// TestAccount verifies connectivity, authentication, and mailbox access
// without fetching or moving anything.
func TestAccount(acc database.Account, password string, saslClient sasl.Client) error {
	c, err := Connect(ConnectOptions{
		Host:     acc.Host,
		Port:     acc.Port,
		TLS:      acc.TLS == 1,
		Username: acc.Username,
		Password: password,
		SASL:     saslClient,
	})
	if err != nil {
		return err
	}
	defer c.Logout()
	if _, err := c.Select(acc.Mailbox, nil).Wait(); err != nil {
		return fmt.Errorf("select %q: %w", acc.Mailbox, err)
	}
	return nil
}

// SaveAttachments parses and stores a batch of report attachments,
// returning the number imported (duplicates and parse failures are skipped).
func SaveAttachments(db *sqlx.DB, source string, attachments []Attachment) (int, error) {
	imported := 0
	for i, att := range attachments {
		audit.Debug("imap[%s]: parsing attachment %d/%d filename=%q size=%d", source, i+1, len(attachments), att.Filename, len(att.Data))

		if parser.IsTLSRPTFile(att.Filename) {
			report, rawJSON, err := parser.ParseTLSRPT(att.Filename, bytes.NewReader(att.Data))
			if err != nil {
				log.Printf("ingest[%s]: skipping unparseable TLS report %q: %v", source, att.Filename, err)
				continue
			}
			if _, err := database.SaveTLSRPT(db, report, att.Filename, rawJSON); err != nil {
				if errors.Is(err, database.ErrDuplicate) {
					audit.ReportDuplicate(att.Filename, report.OrganizationName, report.ReportID)
					continue
				}
				return imported, fmt.Errorf("save TLS report %q: %w", att.Filename, err)
			}
			audit.ReportImported(att.Filename, report.OrganizationName, "(tlsrpt)", report.ReportID, len(report.Policies))
			imported++
			continue
		}

		fb, rawXML, err := parser.Parse(att.Filename, bytes.NewReader(att.Data))
		if err != nil {
			log.Printf("ingest[%s]: skipping unparseable attachment %q: %v", source, att.Filename, err)
			continue
		}
		if _, err := database.SaveReport(db, fb, att.Filename, rawXML); err != nil {
			if errors.Is(err, database.ErrDuplicate) {
				audit.ReportDuplicate(att.Filename, fb.ReportMetadata.OrgName, fb.ReportMetadata.ReportID)
				continue
			}
			return imported, fmt.Errorf("save report %q: %w", att.Filename, err)
		}
		audit.ReportImported(att.Filename, fb.ReportMetadata.OrgName,
			fb.PolicyPublished.Domain, fb.ReportMetadata.ReportID, len(fb.Records))
		imported++
	}
	return imported, nil
}
