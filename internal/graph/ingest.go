package graph

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/importer"
)

// defaultFolder is the Graph well-known folder name used when an account
// does not specify one; Graph accepts well-known names directly as folder
// IDs in API paths.
const defaultFolder = "inbox"

func folderID(acc database.Account) string {
	if acc.Mailbox == "" {
		return defaultFolder
	}
	return acc.Mailbox
}

// IngestAccount fetches unexamined messages from an Office 365 mailbox via
// the Microsoft Graph API, parses DMARC and TLS-RPT report attachments, and
// stores them. Returns the number of newly imported reports (both kinds).
func IngestAccount(db *sqlx.DB, acc database.Account, token string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	folder := folderID(acc)
	audit.Debug("graph[%s]: fetching mailbox=%q folder=%q", acc.Name, acc.Username, folder)

	attachments, err := FetchReports(ctx, token, db, acc.ID, acc.Username, folder, acc.ProcessedMailbox)
	if err != nil {
		return 0, fmt.Errorf("graph fetch: %w", err)
	}
	res, err := importer.SaveAttachments(db, database.IngestSourceGraph, acc.Name, attachments)
	return res.Imported, err
}

// TestAccount verifies connectivity, authentication, and folder access
// without fetching or moving anything.
func TestAccount(acc database.Account, token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	folder := folderID(acc)
	getURL := fmt.Sprintf("%s/mailFolders/%s", userPath(acc.Username), url.PathEscape(folder))
	var f struct {
		ID string `json:"id"`
	}
	if err := doJSON(ctx, token, "GET", getURL, nil, &f); err != nil {
		return fmt.Errorf("access folder %q: %w", folder, err)
	}
	return nil
}
