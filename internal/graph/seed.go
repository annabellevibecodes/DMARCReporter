package graph

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// seedMessage is one message's headers as Graph returns them.
type seedMessage struct {
	ID               string `json:"id"`
	ReceivedDateTime string `json:"receivedDateTime"`
	Headers          []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"internetMessageHeaders"`
}

type seedMessageList struct {
	Value    []seedMessage `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

// IngestSeedAccount reads a seed mailbox over Graph for the BIMI verdicts
// receivers stamped on the operator's own mail (B21).
//
// As with the IMAP path, nothing is moved, nothing is deleted, and no message
// body is requested: Graph returns the internet headers directly, which is all
// this needs.
func IngestSeedAccount(db *sqlx.DB, acc database.Account, token string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	folder := folderID(acc)
	audit.Debug("graph[%s]: reading seed mailbox=%q folder=%q", acc.Name, acc.Username, folder)

	seen, err := database.GetSeenGraphIDs(db, acc.ID)
	if err != nil {
		return 0, fmt.Errorf("load seen ids: %w", err)
	}

	query := encodeQuery(map[string]string{
		"$select": "id,receivedDateTime,internetMessageHeaders",
		"$top":    "50",
	})
	next := fmt.Sprintf("%s/mailFolders/%s/messages?%s", userPath(acc.Username), url.PathEscape(folder), query)

	var (
		recorded int
		examined []string
	)
	for next != "" {
		var list seedMessageList
		if err := doJSON(ctx, token, "GET", next, nil, &list); err != nil {
			return recorded, fmt.Errorf("list messages: %w", err)
		}
		for _, msg := range list.Value {
			if seen[msg.ID] {
				continue
			}
			examined = append(examined, msg.ID)
			n, err := recordSeedHeaders(db, acc.ID, msg)
			if err != nil {
				audit.Debug("graph[%s]: seed verdict: %v", acc.Name, err)
				continue
			}
			recorded += n
		}
		next = list.NextLink
		// Never send the bearer token anywhere but the Graph API, whatever
		// the continuation link in the response says.
		if next != "" && !strings.HasPrefix(next, baseURL+"/") {
			return recorded, fmt.Errorf("list messages: refusing to follow @odata.nextLink outside %s", baseURL)
		}
	}

	if err := database.MarkGraphIDsSeen(db, acc.ID, examined); err != nil {
		return recorded, fmt.Errorf("mark message ids seen: %w", err)
	}
	return recorded, nil
}

// recordSeedHeaders turns Graph's header list into the mail.Header the shared
// recorder expects, so both providers produce identical rows.
func recordSeedHeaders(db *sqlx.DB, accountID int64, msg seedMessage) (int, error) {
	header := mail.Header{}
	for _, h := range msg.Headers {
		// Canonical casing, because Graph reports headers as the sender wrote
		// them and mail.Header lookups are canonical.
		name := canonicalHeaderName(h.Name)
		header[name] = append(header[name], h.Value)
	}
	// receivedDateTime is Graph's own record of when the message arrived, and
	// is used in preference to the Date header the sender wrote.
	var receivedAt int64
	if msg.ReceivedDateTime != "" {
		if t, err := time.Parse(time.RFC3339, msg.ReceivedDateTime); err == nil {
			receivedAt = t.Unix()
		}
	}
	return database.RecordSeedVerdicts(db, accountID, header, receivedAt)
}

// canonicalHeaderName renders a header name in the Foo-Bar form net/mail uses.
func canonicalHeaderName(name string) string {
	parts := strings.Split(strings.TrimSpace(name), "-")
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + strings.ToLower(p[1:])
	}
	return strings.Join(parts, "-")
}
