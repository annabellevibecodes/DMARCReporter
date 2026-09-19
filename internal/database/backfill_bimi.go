package database

import (
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// BIMIBackfillResult summarises one BackfillBIMI run.
type BIMIBackfillResult struct {
	// Scanned is how many stored reports were re-parsed.
	Scanned int
	// WithBIMI is how many of them carried a <bimi> element.
	WithBIMI int
	// Assertions and Errors are the rows created.
	Assertions int
	Errors     int
	// Failed is how many stored documents no longer parse and were left alone.
	Failed int
}

// BackfillBIMI re-parses report_xml for reports imported before the BIMI
// reporting support existed, and populates bimi_assertions, bimi_errors and
// the per-report hygiene counters.
//
// Only reports that have no assertion rows yet are touched, so the run is
// idempotent: a report that genuinely carried no <bimi> element is re-scanned
// on a later run and produces nothing again, which costs a parse and changes
// nothing. The alternative — a marker per report — would need a column to say
// "scanned and found nothing", and the hygiene counters already say that.
//
// A stored document that no longer parses is left exactly as it is. Its
// records were imported when it arrived and remain valid; only the BIMI data
// inside it is unavailable.
func BackfillBIMI(db *sqlx.DB) (BIMIBackfillResult, error) {
	var res BIMIBackfillResult

	type row struct {
		ID  int64  `db:"id"`
		XML string `db:"xml_data"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT r.id, x.xml_data
		  FROM reports r
		  JOIN report_xml x ON x.report_id = r.id
		 WHERE x.xml_data != ''
		   AND NOT EXISTS (SELECT 1 FROM bimi_assertions a WHERE a.report_id = r.id)
		 ORDER BY r.id`); err != nil {
		return res, err
	}

	for _, r := range rows {
		res.Scanned++
		fb, err := parser.ParseXML(strings.NewReader(r.XML))
		if err != nil {
			res.Failed++
			continue
		}

		tx, err := db.Beginx()
		if err != nil {
			return res, err
		}
		// The hygiene counters are rewritten whether or not the report has a
		// <bimi> element: a report with none must record bimi_present = 0
		// rather than keeping whatever the column defaulted to, or B18
		// coverage would count it as unknown instead of as "no BIMI data".
		if _, err := tx.Exec(`
			UPDATE reports
			   SET bimi_present = ?, bimi_dup_tuples = ?, bimi_bad_counts = ?,
			       bimi_unknown_types = ?, bimi_missing_attrs = ?, malformed_fields = ?
			 WHERE id = ?`,
			fb.BIMIHygiene.Present, fb.BIMIHygiene.DupTuples, fb.BIMIHygiene.BadCounts,
			fb.BIMIHygiene.UnknownTypes, fb.BIMIHygiene.MissingAttrs,
			fb.BIMIHygiene.MalformedFields, r.ID); err != nil {
			tx.Rollback()
			return res, err
		}
		if err := insertBIMI(tx, r.ID, fb.BIMI); err != nil {
			tx.Rollback()
			return res, err
		}
		if err := tx.Commit(); err != nil {
			return res, err
		}

		if fb.BIMI != nil {
			res.WithBIMI++
			for _, d := range fb.BIMI.Domains {
				res.Assertions += len(d.Assertions)
				for _, a := range d.Assertions {
					if a.Errors != nil {
						res.Errors += len(a.Errors.Entries)
					}
				}
			}
		}
	}
	return res, nil
}
