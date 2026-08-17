package database

import (
	"time"

	"github.com/jmoiron/sqlx"
)

// PassRateWindow holds message totals for one time window.
type PassRateWindow struct {
	TotalMessages int64 `db:"total_messages"`
	Passed        int64 `db:"passed"`
}

// Rate returns the pass rate in percent, or -1 when the window is empty.
func (w PassRateWindow) Rate() float64 {
	if w.TotalMessages == 0 {
		return -1
	}
	return float64(w.Passed) / float64(w.TotalMessages) * 100
}

// GetPassRateWindow returns pass/total counts for reports whose
// date_range_begin falls in [from, to).
func GetPassRateWindow(db *sqlx.DB, from, to int64) (PassRateWindow, error) {
	var w PassRateWindow
	err := db.Get(&w, `
		SELECT
			COALESCE(SUM(rr.count), 0) AS total_messages,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE r.date_range_begin >= ? AND r.date_range_begin < ?`, from, to)
	return w, err
}

// NewFailingSource is a source IP whose first-ever appearance is recent and
// which is failing DMARC.
type NewFailingSource struct {
	SourceIP  string `db:"source_ip"`
	Failed    int64  `db:"failed"`
	Total     int64  `db:"total"`
	FirstSeen int64  `db:"first_seen"`
}

// GetNewFailingSources returns source IPs first observed at or after since
// that have DMARC failures.
func GetNewFailingSources(db *sqlx.DB, since int64) ([]NewFailingSource, error) {
	var sources []NewFailingSource
	err := db.Select(&sources, `
		SELECT
			rr.source_ip,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			SUM(rr.count) AS total,
			MIN(r.date_range_begin) AS first_seen
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		GROUP BY rr.source_ip
		HAVING first_seen >= ? AND failed > 0
		ORDER BY failed DESC`, since)
	return sources, err
}

// MarkAlertSent records an alert key; returns false if it was already sent.
func MarkAlertSent(db *sqlx.DB, key string) (bool, error) {
	res, err := db.Exec(`INSERT OR IGNORE INTO alerts_sent (key, sent_at) VALUES (?, ?)`,
		key, time.Now().Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// PruneAlertsSent removes dedup entries older than the retention window.
func PruneAlertsSent(db *sqlx.DB, olderThan time.Duration) error {
	_, err := db.Exec(`DELETE FROM alerts_sent WHERE sent_at < ?`,
		time.Now().Add(-olderThan).Unix())
	return err
}
