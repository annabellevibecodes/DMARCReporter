package database

import (
	"time"

	"github.com/jmoiron/sqlx"
)

// Ingest event sources and statuses.
const (
	IngestSourceUpload = "upload"
	IngestSourceIMAP   = "imap"
	IngestSourceGraph  = "graph"

	IngestKindDMARC   = "dmarc"
	IngestKindTLSRPT  = "tlsrpt"
	IngestKindUnknown = "unknown"

	IngestStatusOK         = "ok"
	IngestStatusDuplicate  = "duplicate"
	IngestStatusParseError = "parse_error"
	IngestStatusRejected   = "rejected"
	// IngestStatusDuplicateRange is a report-id already seen for that
	// organisation arriving with a different date range. Counted apart from
	// ordinary duplicates: a retry is harmless, but id reuse across windows
	// means a window is being dropped and nobody would otherwise notice.
	IngestStatusDuplicateRange = "duplicate_range"
)

// IngestEvent is one processed attachment.
type IngestEvent struct {
	ID       int64  `db:"id"`
	At       int64  `db:"at"`
	Source   string `db:"source"`
	Filename string `db:"filename"`
	Kind     string `db:"kind"`
	Status   string `db:"status"`
	OrgName  string `db:"org_name"`
	ReportID string `db:"report_id"`
	Error    string `db:"error"`
}

// AtTime returns At as a UTC time.
func (e IngestEvent) AtTime() time.Time { return time.Unix(e.At, 0).UTC() }

// RecordIngestEvent stores one ingest event. Errors are truncated so a
// pathological parser message cannot bloat the table.
func RecordIngestEvent(db *sqlx.DB, e IngestEvent) error {
	if e.At == 0 {
		e.At = time.Now().Unix()
	}
	if len(e.Error) > 500 {
		e.Error = e.Error[:500]
	}
	if len(e.Filename) > 255 {
		e.Filename = e.Filename[:255]
	}
	_, err := db.Exec(`
		INSERT INTO ingest_events (at, source, filename, kind, status, org_name, report_id, error)
		VALUES (?,?,?,?,?,?,?,?)`,
		e.At, e.Source, e.Filename, e.Kind, e.Status, e.OrgName, e.ReportID, e.Error)
	return err
}

// IngestEventCount holds a count per status.
type IngestEventCount struct {
	Status string `db:"status"`
	Kind   string `db:"kind"`
	Count  int64  `db:"count"`
}

// CountIngestEvents returns counts grouped by status and kind since the given
// Unix time (0 = all).
func CountIngestEvents(db *sqlx.DB, since int64) ([]IngestEventCount, error) {
	var out []IngestEventCount
	err := db.Select(&out, `
		SELECT status, kind, COUNT(*) AS count
		FROM ingest_events
		WHERE at >= ?
		GROUP BY status, kind
		ORDER BY status, kind`, since)
	return out, err
}

// ListIngestEvents returns the most recent events with the given status
// ("" = any), newest first.
func ListIngestEvents(db *sqlx.DB, status string, since int64, limit int) ([]IngestEvent, error) {
	var out []IngestEvent
	if limit <= 0 {
		limit = 100
	}
	if status == "" {
		err := db.Select(&out, `SELECT * FROM ingest_events WHERE at >= ? ORDER BY at DESC, id DESC LIMIT ?`, since, limit)
		return out, err
	}
	err := db.Select(&out, `SELECT * FROM ingest_events WHERE status = ? AND at >= ? ORDER BY at DESC, id DESC LIMIT ?`, status, since, limit)
	return out, err
}

// PruneIngestEvents removes events older than the retention window.
func PruneIngestEvents(db *sqlx.DB, olderThan time.Duration) error {
	_, err := db.Exec(`DELETE FROM ingest_events WHERE at < ?`, time.Now().Add(-olderThan).Unix())
	return err
}
