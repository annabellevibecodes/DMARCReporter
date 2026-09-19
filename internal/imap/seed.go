package imap

import (
	"fmt"
	"net/mail"
	"strings"

	imapc "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// IngestSeedAccount reads a seed mailbox for the BIMI verdicts receivers
// stamped on the operator's own mail (B21).
//
// It is deliberately much less invasive than the report path: only headers are
// downloaded, no attachment is opened, no message is moved, and nothing is
// deleted. A seed mailbox belongs to the operator and holds their ordinary
// mail; this reads it and leaves it exactly as it was.
func IngestSeedAccount(db *sqlx.DB, acc database.Account, password string, saslClient sasl.Client) (int, error) {
	c, err := Connect(ConnectOptions{
		Host:     acc.Host,
		Port:     acc.Port,
		TLS:      acc.TLS == 1,
		Username: acc.Username,
		Password: password,
		SASL:     saslClient,
	})
	if err != nil {
		return 0, fmt.Errorf("imap connect: %w", err)
	}
	defer c.Logout()

	return FetchSeedVerdicts(c, db, acc)
}

// FetchSeedVerdicts downloads the headers of messages not examined before,
// records every bimi= verdict it finds, and marks the messages seen.
//
// Every message is marked seen, whether or not it carried a verdict: most mail
// in a seed mailbox will not, and re-downloading its headers on every pass for
// ever would make the job grow without bound.
func FetchSeedVerdicts(c *imapclient.Client, db *sqlx.DB, acc database.Account) (int, error) {
	selData, err := c.Select(acc.Mailbox, &imapc.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		return 0, fmt.Errorf("select %q: %w", acc.Mailbox, err)
	}

	seen, err := database.GetSeenUIDs(db, acc.ID, selData.UIDValidity)
	if err != nil {
		return 0, fmt.Errorf("load seen uids: %w", err)
	}

	searchData, err := c.UIDSearch(&imapc.SearchCriteria{}, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("search all: %w", err)
	}
	if searchData.All == nil {
		return 0, nil
	}
	uidSet, ok := searchData.All.(imapc.UIDSet)
	if !ok || len(uidSet) == 0 {
		return 0, nil
	}

	var unseen imapc.UIDSet
	var unseenCount int
	for _, r := range uidSet {
		for u := r.Start; u <= r.Stop; u++ {
			if !seen[uint32(u)] {
				unseen = append(unseen, imapc.UIDRange{Start: u, Stop: u})
				unseenCount++
			}
			if u == r.Stop {
				break
			}
		}
	}
	audit.Debug("imap[%s]: seed mailbox has %d unexamined message(s)", acc.Name, unseenCount)
	if unseenCount == 0 {
		return 0, nil
	}

	// Headers only. A seed mailbox is ordinary mail and its bodies are none of
	// this application's business.
	fetchOpts := &imapc.FetchOptions{
		UID: true,
		// INTERNALDATE is the server's own record of when the message
		// arrived. It is used in preference to the Date header, which the
		// sender writes and can therefore date into the future.
		InternalDate: true,
		BodySection: []*imapc.FetchItemBodySection{{
			Specifier: imapc.PartSpecifierHeader,
			Peek:      true,
		}},
	}
	msgs, err := c.Fetch(unseen, fetchOpts).Collect()
	if err != nil {
		return 0, fmt.Errorf("fetch headers: %w", err)
	}

	var (
		recorded  int
		examined  []uint32
		accountID = acc.ID
	)
	for _, msg := range msgs {
		examined = append(examined, uint32(msg.UID))
		var raw []byte
		for _, buf := range msg.BodySection {
			if len(buf.Bytes) > 0 {
				raw = buf.Bytes
				break
			}
		}
		if len(raw) == 0 {
			continue
		}
		var receivedAt int64
		if !msg.InternalDate.IsZero() {
			receivedAt = msg.InternalDate.Unix()
		}
		n, err := recordSeedVerdicts(db, accountID, raw, receivedAt)
		if err != nil {
			audit.Debug("imap[%s]: seed verdict: %v", acc.Name, err)
			continue
		}
		recorded += n
	}

	if err := database.MarkUIDsSeen(db, accountID, selData.UIDValidity, examined); err != nil {
		return recorded, fmt.Errorf("mark uids seen: %w", err)
	}
	return recorded, nil
}

// recordSeedVerdicts parses one message's headers and stores its verdicts.
func recordSeedVerdicts(db *sqlx.DB, accountID int64, rawHeaders []byte, receivedAt int64) (int, error) {
	msg, err := mail.ReadMessage(strings.NewReader(string(rawHeaders) + "\r\n"))
	if err != nil {
		return 0, fmt.Errorf("read headers: %w", err)
	}
	return database.RecordSeedVerdicts(db, accountID, msg.Header, receivedAt)
}
