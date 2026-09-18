package database

import (
	"encoding/json"
	"strings"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// TLSRPTBackfillResult summarises one BackfillTLSRPT run.
type TLSRPTBackfillResult struct {
	// Reports is how many reports gained policy/failure rows.
	Reports int
	// MultiPolicy is how many of those carry two policy entries for one
	// domain and MX pattern — the reports whose displayed totals change once
	// the query-time rollup applies.
	MultiPolicy int
	// Failed is how many rows could not be re-parsed and were left alone.
	Failed int
}

// BackfillTLSRPT re-parses tlsrpt_reports.raw_json for every report that has
// no policy rows yet, and populates tlsrpt_policies, tlsrpt_policy_mx,
// tlsrpt_failures and the per-report hygiene counters.
//
// The report rows themselves are not rewritten: their stored total_success /
// total_failure stay exactly as imported. What changes for the operator is
// that multi-policy reports can now be rolled up correctly at query time, so
// figures that double-counted before will move — which is why the run reports
// how many reports were affected, and why the TLS page says so on screen.
//
// Reports whose raw_json is empty or no longer parses are left untouched;
// their summary counts remain usable.
func BackfillTLSRPT(db *sqlx.DB) (TLSRPTBackfillResult, error) {
	var res TLSRPTBackfillResult

	type row struct {
		ID       int64  `db:"id"`
		RawJSON  string `db:"raw_json"`
		Filename string `db:"source_filename"`
		Begin    int64  `db:"date_range_begin"`
		End      int64  `db:"date_range_end"`
	}
	var rows []row
	if err := db.Select(&rows, `
		SELECT r.id, r.raw_json, r.source_filename, r.date_range_begin, r.date_range_end
		  FROM tlsrpt_reports r
		 WHERE r.raw_json != ''
		   AND NOT EXISTS (SELECT 1 FROM tlsrpt_policies p WHERE p.tlsrpt_report_id = r.id)
		 ORDER BY r.id`); err != nil {
		return res, err
	}

	for _, r := range rows {
		var report parser.TLSReport
		if err := json.Unmarshal([]byte(r.RawJSON), &report); err != nil {
			res.Failed++
			continue
		}

		tx, err := db.Beginx()
		if err != nil {
			return res, err
		}
		h, err := insertTLSRPTPolicies(tx, r.ID, &report)
		if err != nil {
			tx.Rollback() //nolint:errcheck // the run continues with the next report
			return res, err
		}
		if fnBegin, fnEnd, ok := parser.TLSRPTFilenameRange(r.Filename); ok && (fnBegin != r.Begin || fnEnd != r.End) {
			h.RangeVariance = 1
		}
		if _, err := tx.Exec(`
			UPDATE tlsrpt_reports
			   SET multi_policy = ?, unattributed_failures = ?, malformed_ips = ?,
			       unknown_result_types = ?, range_variance = ?
			 WHERE id = ?`,
			h.MultiPolicy, h.UnattributedFailures, h.MalformedIPs, h.UnknownResultTypes, h.RangeVariance,
			r.ID); err != nil {
			tx.Rollback() //nolint:errcheck
			return res, err
		}
		if err := tx.Commit(); err != nil {
			return res, err
		}

		res.Reports++
		if h.MultiPolicy == 1 {
			res.MultiPolicy++
		}
	}
	return res, nil
}

// backfillTransport is the transport recorded for reports imported before the
// column existed: we no longer know how they arrived, and guessing "smtp"
// would retroactively subject them to the DKIM requirement.
const backfillTransport = ""

// TLSRPTTransportOrUnknown renders a stored transport for display.
func TLSRPTTransportOrUnknown(transport string) string {
	if strings.TrimSpace(transport) == backfillTransport {
		return "unknown"
	}
	return transport
}
