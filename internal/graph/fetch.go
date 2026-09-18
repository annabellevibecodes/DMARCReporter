package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/importer"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

const maxAttachmentSize = 10 * 1024 * 1024

type folder struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

type folderList struct {
	Value []folder `json:"value"`
}

type messageStub struct {
	ID               string `json:"id"`
	ReceivedDateTime string `json:"receivedDateTime"`
}

// receivedUnix parses the Graph receivedDateTime (RFC 3339) into Unix seconds;
// 0 when absent or unparseable.
func (m messageStub) receivedUnix() int64 {
	if m.ReceivedDateTime == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339Nano, m.ReceivedDateTime)
	if err != nil {
		if t, err = time.Parse(time.RFC3339, m.ReceivedDateTime); err != nil {
			return 0
		}
	}
	return t.Unix()
}

type messageList struct {
	Value    []messageStub `json:"value"`
	NextLink string        `json:"@odata.nextLink"`
}

type attachment struct {
	Type         string `json:"@odata.type"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	ContentBytes string `json:"contentBytes"`
}

type attachmentList struct {
	Value []attachment `json:"value"`
}

// escapeODataString escapes single quotes for use inside an OData $filter
// string literal.
func escapeODataString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func userPath(mailbox string) string {
	return baseURL + "/users/" + url.PathEscape(mailbox)
}

// encodeQuery builds a URL query string, percent-encoding spaces as %20
// rather than url.Values.Encode()'s default '+' — Graph's OData query
// parser expects %20 (see the $filter/$select examples in its docs).
func encodeQuery(params map[string]string) string {
	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	return strings.ReplaceAll(v.Encode(), "+", "%20")
}

// resolveProcessedFolder returns the ID of the child folder named name under
// parentFolderID, creating it if it does not already exist.
func resolveProcessedFolder(ctx context.Context, token, mailbox, parentFolderID, name string) (string, error) {
	if name == "" {
		name = "Processed"
	}
	query := encodeQuery(map[string]string{
		"$filter": fmt.Sprintf("displayName eq '%s'", escapeODataString(name)),
	})
	listURL := fmt.Sprintf("%s/mailFolders/%s/childFolders?%s",
		userPath(mailbox), url.PathEscape(parentFolderID), query)
	var fl folderList
	if err := doJSON(ctx, token, "GET", listURL, nil, &fl); err != nil {
		return "", fmt.Errorf("list child folders: %w", err)
	}
	if len(fl.Value) > 0 {
		return fl.Value[0].ID, nil
	}

	audit.Debug("graph: creating processed folder %q under %q", name, parentFolderID)
	body, _ := json.Marshal(map[string]string{"displayName": name})
	createURL := fmt.Sprintf("%s/mailFolders/%s/childFolders", userPath(mailbox), url.PathEscape(parentFolderID))
	var created folder
	if err := doJSON(ctx, token, "POST", createURL, bytes.NewReader(body), &created); err != nil {
		return "", fmt.Errorf("create processed folder %q: %w", name, err)
	}
	return created.ID, nil
}

// listCandidateMessages returns the messages in folderID that carry at least
// one attachment (id + received time), following pagination.
func listCandidateMessages(ctx context.Context, token, mailbox, folderID string) ([]messageStub, error) {
	var msgs []messageStub
	query := encodeQuery(map[string]string{
		"$filter": "hasAttachments eq true",
		"$select": "id,receivedDateTime",
		"$top":    "50",
	})
	next := fmt.Sprintf("%s/mailFolders/%s/messages?%s", userPath(mailbox), url.PathEscape(folderID), query)
	for next != "" {
		var ml messageList
		if err := doJSON(ctx, token, "GET", next, nil, &ml); err != nil {
			return nil, fmt.Errorf("list messages: %w", err)
		}
		msgs = append(msgs, ml.Value...)
		next = ml.NextLink
		// Never send the bearer token anywhere but the Graph API, whatever
		// the continuation link in the response says.
		if next != "" && !strings.HasPrefix(next, baseURL+"/") {
			return nil, fmt.Errorf("list messages: refusing to follow @odata.nextLink outside %s", baseURL)
		}
	}
	return msgs, nil
}

// fetchMessageAttachments downloads the report attachments (if any) of one
// message, stamping each with receivedAt.
func fetchMessageAttachments(ctx context.Context, token, mailbox, messageID string, receivedAt int64) ([]importer.Attachment, error) {
	listURL := fmt.Sprintf("%s/messages/%s/attachments", userPath(mailbox), url.PathEscape(messageID))
	var al attachmentList
	if err := doJSON(ctx, token, "GET", listURL, nil, &al); err != nil {
		return nil, fmt.Errorf("list attachments: %w", err)
	}

	var out []importer.Attachment
	for _, att := range al.Value {
		if att.Type != "#microsoft.graph.fileAttachment" {
			continue
		}
		if !parser.IsDMARCFile(att.Name) && !parser.IsTLSRPTFile(att.Name) {
			continue
		}

		var data []byte
		if att.ContentBytes != "" {
			decoded, err := base64.StdEncoding.DecodeString(att.ContentBytes)
			if err != nil {
				audit.Debug("graph: message %s attachment %q: base64 decode error: %v", messageID, att.Name, err)
				continue
			}
			data = decoded
		} else {
			// Large attachments omit contentBytes from the list response;
			// fetch the raw content directly.
			valueURL := fmt.Sprintf("%s/messages/%s/attachments/%s/$value",
				userPath(mailbox), url.PathEscape(messageID), url.PathEscape(att.ID))
			raw, err := getRaw(ctx, token, valueURL)
			if err != nil {
				audit.Debug("graph: message %s attachment %q: $value fetch error: %v", messageID, att.Name, err)
				continue
			}
			data = raw
		}

		if len(data) > maxAttachmentSize {
			audit.Debug("graph: message %s attachment %q exceeds %d byte limit, skipping", messageID, att.Name, maxAttachmentSize)
			continue
		}
		out = append(out, importer.Attachment{Filename: att.Name, Data: data, ReceivedAt: receivedAt})
	}
	return out, nil
}

// moveMessage moves a message to destFolderID.
func moveMessage(ctx context.Context, token, mailbox, messageID, destFolderID string) error {
	body, _ := json.Marshal(map[string]string{"destinationId": destFolderID})
	moveURL := fmt.Sprintf("%s/messages/%s/move", userPath(mailbox), url.PathEscape(messageID))
	return doJSON(ctx, token, "POST", moveURL, bytes.NewReader(body), nil)
}

// FetchReports fetches messages with attachments from folderID that have not
// been examined before, extracts report attachments, moves messages carrying
// reports to a processed child folder, and records report-free messages so
// they are never re-downloaded.
func FetchReports(ctx context.Context, token string, db *sqlx.DB, accountID int64, mailbox, folderID, processedFolderName string) ([]importer.Attachment, error) {
	seen, err := database.GetSeenGraphIDs(db, accountID)
	if err != nil {
		return nil, fmt.Errorf("load seen message ids: %w", err)
	}

	candidates, err := listCandidateMessages(ctx, token, mailbox, folderID)
	if err != nil {
		return nil, err
	}
	var unseen []messageStub
	for _, m := range candidates {
		if !seen[m.ID] {
			unseen = append(unseen, m)
		}
	}
	audit.Debug("graph: %d message(s) with attachments, %d not yet examined", len(candidates), len(unseen))
	if len(unseen) == 0 {
		return nil, nil
	}

	var processedFolderID string
	var attachments []importer.Attachment
	var noReport []string
	moved := 0

	for _, msg := range unseen {
		msgID := msg.ID
		atts, err := fetchMessageAttachments(ctx, token, mailbox, msgID, msg.receivedUnix())
		if err != nil {
			audit.Debug("graph: message %s: %v", msgID, err)
			continue
		}
		if len(atts) == 0 {
			noReport = append(noReport, msgID)
			continue
		}
		attachments = append(attachments, atts...)

		if processedFolderID == "" {
			processedFolderID, err = resolveProcessedFolder(ctx, token, mailbox, folderID, processedFolderName)
			if err != nil {
				return attachments, err
			}
		}
		if err := moveMessage(ctx, token, mailbox, msgID, processedFolderID); err != nil {
			return attachments, fmt.Errorf("move message %s: %w", msgID, err)
		}
		moved++
	}

	if err := database.MarkGraphIDsSeen(db, accountID, noReport); err != nil {
		return attachments, fmt.Errorf("mark message ids seen: %w", err)
	}

	audit.Debug("graph: fetch complete — %d attachment(s), %d moved, %d cached as report-free",
		len(attachments), moved, len(noReport))
	return attachments, nil
}
