package database

import (
	"fmt"

	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/jmoiron/sqlx"
)

// BIMIAssertionRow is one stored <assertion> element.
type BIMIAssertionRow struct {
	ID              int64  `db:"id" json:"id"`
	ReportID        int64  `db:"report_id" json:"report_id"`
	AlignedDomain   string `db:"aligned_domain" json:"aligned_domain"`
	AssertionDomain string `db:"assertion_domain" json:"assertion_domain"`
	Selector        string `db:"selector" json:"selector"`
	LValue          string `db:"l_value" json:"l"`
	AValue          string `db:"a_value" json:"a"`
	EvidencePresent int    `db:"evidence_present" json:"evidence_present"`
	EvidenceDate    int64  `db:"evidence_date" json:"evidence_date"`
	EvidenceDateRaw string `db:"evidence_date_raw" json:"evidence_date_raw"`
	EvidenceIssuer  string `db:"evidence_issuer" json:"evidence_issuer"`
	EvidenceType    string `db:"evidence_type" json:"evidence_type"`
	EvidenceURL     string `db:"evidence_url" json:"evidence_url"`
}

// Unpublished reports the magic l= value §3.2 defines for an empty l= tag: the
// evaluator saw a record that declines to publish an indicator. It is not a
// URI and must never be fetched.
func (r BIMIAssertionRow) Unpublished() bool { return r.LValue == models.Unpublished }

// BIMIErrorRow is one stored ERROR-NAME:class:type tuple.
type BIMIErrorRow struct {
	ID          int64  `db:"id" json:"id"`
	AssertionID int64  `db:"assertion_id" json:"assertion_id"`
	Element     string `db:"element" json:"element"`
	Class       string `db:"class" json:"class"`
	Type        string `db:"type" json:"type"`
	Description string `db:"description" json:"description"`
	Count       int64  `db:"count" json:"count"`
}

// insertBIMI stores the <bimi> element of one report.
//
// Assertions are stored whether or not they carry errors: §3.4 forbids an
// <errors> element when there were none, so an assertion row with no error
// rows is the *only* way the schema can say "this configuration was evaluated
// and worked". Dropping it would throw away every success in the corpus.
func insertBIMI(tx *sqlx.Tx, reportID int64, report *models.BIMIReport) error {
	if report == nil {
		return nil
	}
	for _, d := range report.Domains {
		for _, a := range d.Assertions {
			var (
				present                          int
				date                             int64
				dateRaw, issuer, docType, docURL string
			)
			if a.Evidence != nil {
				present = 1
				date = a.Evidence.ParsedDate
				dateRaw = a.Evidence.Date
				issuer = a.Evidence.Issuer
				docType = a.Evidence.Type
				docURL = a.Evidence.URL
			}
			res, err := tx.Exec(`
				INSERT INTO bimi_assertions
					(report_id, aligned_domain, assertion_domain, selector, l_value, a_value,
					 evidence_present, evidence_date, evidence_date_raw, evidence_issuer,
					 evidence_type, evidence_url)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
				reportID, d.Aligned, d.Assertion, a.Selector, a.L, a.A,
				present, date, dateRaw, issuer, docType, docURL)
			if err != nil {
				return fmt.Errorf("insert bimi_assertion: %w", err)
			}
			assertionID, _ := res.LastInsertId()

			if a.Errors == nil {
				continue
			}
			for _, e := range a.Errors.Entries {
				if _, err := tx.Exec(`
					INSERT INTO bimi_errors (assertion_id, element, class, type, description, count)
					VALUES (?,?,?,?,?,?)`,
					assertionID, e.Element, e.Class, e.Type, e.Description, e.Count,
				); err != nil {
					return fmt.Errorf("insert bimi_error: %w", err)
				}
			}
		}
	}
	return nil
}

// ListBIMIAssertions returns the assertions of one report, with their errors.
func ListBIMIAssertions(db *sqlx.DB, reportID int64) ([]BIMIAssertionRow, map[int64][]BIMIErrorRow, error) {
	rows := []BIMIAssertionRow{}
	if err := db.Select(&rows, `
		SELECT * FROM bimi_assertions WHERE report_id = ? ORDER BY id`, reportID); err != nil {
		return nil, nil, err
	}
	errs := []BIMIErrorRow{}
	if err := db.Select(&errs, `
		SELECT e.* FROM bimi_errors e
		  JOIN bimi_assertions a ON a.id = e.assertion_id
		 WHERE a.report_id = ?
		 ORDER BY e.id`, reportID); err != nil {
		return nil, nil, err
	}
	byAssertion := map[int64][]BIMIErrorRow{}
	for _, e := range errs {
		byAssertion[e.AssertionID] = append(byAssertion[e.AssertionID], e)
	}
	return rows, byAssertion, nil
}
