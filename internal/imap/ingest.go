package imap

import (
	"fmt"

	"github.com/emersion/go-sasl"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/importer"
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

// SaveAttachments parses and stores a batch of report attachments fetched over
// IMAP, returning the number imported (duplicates and parse failures are
// recorded in ingest_events and skipped). account is the account name used in
// log lines.
func SaveAttachments(db *sqlx.DB, account string, attachments []Attachment) (int, error) {
	res, err := importer.SaveAttachments(db, database.IngestSourceIMAP, account, attachments)
	return res.Imported, err
}
