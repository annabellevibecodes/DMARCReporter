package database

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// BackfillFromXML re-parses report_xml.xml_data for every report and populates
// the columns added by the analytics extension (version, namespace, np,
// discovery_method, testing, generator, report_errors, the *_present flags and
// RFC-default pct/fo) plus the selectors inventory. Reports without stored XML
// are left untouched. progress, when non-nil, is called after each report.
// Returns the number of reports updated.
func BackfillFromXML(db *sqlx.DB, progress func(done, total int)) (int, error) {
	type row struct {
		ID      int64  `db:"id"`
		XMLData string `db:"xml_data"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT r.id, x.xml_data
		FROM reports r
		JOIN report_xml x ON x.report_id = r.id
		WHERE x.xml_data != ''
		ORDER BY r.id`); err != nil {
		return 0, err
	}

	updated := 0
	for i, r := range rows {
		fb, err := parser.ParseXML(bytes.NewReader([]byte(r.XMLData)))
		if err != nil {
			// Stored XML that no longer parses is left as-is; the report row itself is fine.
			if progress != nil {
				progress(i+1, len(rows))
			}
			continue
		}
		tx, err := db.Beginx()
		if err != nil {
			return updated, err
		}
		if err := updateReportExtras(tx, r.ID, fb); err != nil {
			tx.Rollback()
			return updated, fmt.Errorf("report %d: %w", r.ID, err)
		}
		if err := upsertSelectors(tx, fb); err != nil {
			tx.Rollback()
			return updated, fmt.Errorf("report %d selectors: %w", r.ID, err)
		}
		if err := tx.Commit(); err != nil {
			return updated, err
		}
		updated++
		if progress != nil {
			progress(i+1, len(rows))
		}
	}
	return updated, nil
}

// updateReportExtras writes the extension columns for an existing report.
func updateReportExtras(tx *sqlx.Tx, reportID int64, fb *models.Feedback) error {
	pp := fb.PolicyPublished
	_, err := tx.Exec(`
		UPDATE reports SET
			version = ?, xml_namespace = ?, np = ?, discovery_method = ?, testing = ?,
			generator = ?, report_errors = ?,
			subdomain_policy = ?, sp_present = ?,
			pct = ?, pct_present = ?,
			failure_options = ?, fo_present = ?
		WHERE id = ?`,
		fb.VersionText(), fb.Namespace(), pp.NP, pp.DiscoveryMethod, pp.Testing,
		fb.ReportMetadata.Generator, errorsJSON(fb.ReportMetadata.Errors),
		pp.SubdomainPolicy, boolInt(pp.SPPresent),
		pp.Pct, boolInt(pp.PctPresent),
		pp.FailureOptions, boolInt(pp.FOPresent),
		reportID)
	return err
}

// upsertSelectors records every (signing domain, selector) pair in fb in the
// selectors inventory, widening first_seen/last_seen as needed.
func upsertSelectors(tx *sqlx.Tx, fb *models.Feedback) error {
	begin := fb.ReportMetadata.DateRange.Begin
	seen := map[[2]string]bool{}
	for _, rec := range fb.Records {
		for _, d := range rec.AuthResults.DKIM {
			if d.Selector == "" {
				continue
			}
			k := [2]string{d.Domain, d.Selector}
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, err := tx.Exec(`
				INSERT INTO selectors (domain, selector, first_seen, last_seen)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(domain, selector) DO UPDATE SET
					first_seen = CASE WHEN first_seen = 0 OR excluded.first_seen < first_seen THEN excluded.first_seen ELSE first_seen END,
					last_seen  = CASE WHEN excluded.last_seen > last_seen THEN excluded.last_seen ELSE last_seen END`,
				d.Domain, d.Selector, begin, begin); err != nil {
				return err
			}
		}
	}
	return nil
}

func errorsJSON(errs []string) string {
	if len(errs) == 0 {
		return ""
	}
	b, err := json.Marshal(errs)
	if err != nil {
		return ""
	}
	return string(b)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
