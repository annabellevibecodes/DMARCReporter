// Package importer is the single "parse and store an attachment" path shared
// by the upload handler, the IMAP fetcher and the Microsoft Graph fetcher. It
// records one ingest_events row per attachment so duplicates and parse
// failures are visible instead of being silently swallowed.
package importer

import (
	"bytes"
	"errors"
	"fmt"
	"log"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// Attachment holds the raw bytes and filename of a report attachment
// (DMARC aggregate XML or TLS-RPT JSON, possibly compressed).
type Attachment struct {
	Filename string
	Data     []byte
	// ReceivedAt is the Date header of the carrying mail (Unix seconds);
	// 0 when unknown (bare file upload).
	ReceivedAt int64
}

// Result summarises one SaveAttachments call.
type Result struct {
	Imported   int
	Duplicates int
	Failed     int
	// LastReportID is the DB id of the last DMARC report imported (0 if none).
	LastReportID int64
}

// Total returns the number of attachments examined.
func (r Result) Total() int { return r.Imported + r.Duplicates + r.Failed }

// SaveAttachments parses and stores a batch of report attachments. source is
// one of database.IngestSource*; account is a human label for logs (account
// name or ""). Duplicates and parse failures are recorded and skipped; only
// database errors abort the batch.
func SaveAttachments(db *sqlx.DB, source, account string, attachments []Attachment) (Result, error) {
	var res Result
	tag := source
	if account != "" {
		tag = source + "[" + account + "]"
	}
	for i, att := range attachments {
		audit.Debug("%s: parsing attachment %d/%d filename=%q size=%d", tag, i+1, len(attachments), att.Filename, len(att.Data))

		ev := database.IngestEvent{Source: source, Filename: att.Filename}

		if parser.IsTLSRPTFile(att.Filename) {
			ev.Kind = database.IngestKindTLSRPT
			report, rawJSON, err := parser.ParseTLSRPT(att.Filename, bytes.NewReader(att.Data))
			if err != nil {
				log.Printf("ingest[%s]: skipping unparseable TLS report %q: %v", tag, att.Filename, err)
				audit.ReportParseFailed(att.Filename)
				ev.Status, ev.Error = database.IngestStatusParseError, err.Error()
				record(db, ev)
				res.Failed++
				continue
			}
			ev.OrgName, ev.ReportID = report.OrganizationName, report.ReportID
			if _, err := database.SaveTLSRPT(db, report, att.Filename, rawJSON); err != nil {
				if errors.Is(err, database.ErrDuplicate) {
					audit.ReportDuplicate(att.Filename, report.OrganizationName, report.ReportID)
					ev.Status = database.IngestStatusDuplicate
					record(db, ev)
					res.Duplicates++
					continue
				}
				return res, fmt.Errorf("save TLS report %q: %w", att.Filename, err)
			}
			audit.ReportImported(att.Filename, report.OrganizationName, "(tlsrpt)", report.ReportID, len(report.Policies))
			ev.Status = database.IngestStatusOK
			record(db, ev)
			res.Imported++
			continue
		}

		ev.Kind = database.IngestKindDMARC
		if !parser.IsDMARCFile(att.Filename) {
			// Unknown extension: the parser sniffs gzip/zip/XML, so still try.
			ev.Kind = database.IngestKindUnknown
		}
		fb, rawXML, err := parser.Parse(att.Filename, bytes.NewReader(att.Data))
		if err != nil {
			log.Printf("ingest[%s]: skipping unparseable attachment %q: %v", tag, att.Filename, err)
			audit.ReportParseFailed(att.Filename)
			ev.Status, ev.Error = database.IngestStatusParseError, err.Error()
			record(db, ev)
			res.Failed++
			continue
		}
		ev.Kind = database.IngestKindDMARC
		ev.OrgName, ev.ReportID = fb.ReportMetadata.OrgName, fb.ReportMetadata.ReportID
		id, err := database.SaveReportAt(db, fb, att.Filename, rawXML, att.ReceivedAt)
		if err != nil {
			if errors.Is(err, database.ErrDuplicate) {
				audit.ReportDuplicate(att.Filename, fb.ReportMetadata.OrgName, fb.ReportMetadata.ReportID)
				ev.Status = database.IngestStatusDuplicate
				record(db, ev)
				res.Duplicates++
				continue
			}
			return res, fmt.Errorf("save report %q: %w", att.Filename, err)
		}
		audit.ReportImported(att.Filename, fb.ReportMetadata.OrgName,
			fb.PolicyPublished.Domain, fb.ReportMetadata.ReportID, len(fb.Records))
		ev.Status = database.IngestStatusOK
		record(db, ev)
		res.Imported++
		res.LastReportID = id
	}
	return res, nil
}

// RecordRejected stores a 'rejected' event for an attachment that was refused
// before parsing (e.g. over the size cap).
func RecordRejected(db *sqlx.DB, source, filename, reason string) {
	kind := database.IngestKindUnknown
	switch {
	case parser.IsTLSRPTFile(filename):
		kind = database.IngestKindTLSRPT
	case parser.IsDMARCFile(filename):
		kind = database.IngestKindDMARC
	}
	record(db, database.IngestEvent{
		Source: source, Filename: filename, Kind: kind,
		Status: database.IngestStatusRejected, Error: reason,
	})
}

func record(db *sqlx.DB, ev database.IngestEvent) {
	if err := database.RecordIngestEvent(db, ev); err != nil {
		log.Printf("ingest: could not record event for %q: %v", ev.Filename, err)
	}
}
