package database

import (
	"database/sql"
	"errors"
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
	return GetPassRateWindowDomain(db, "", from, to)
}

// GetPassRateWindowDomain is GetPassRateWindow scoped to one policy domain
// ("" = all domains).
func GetPassRateWindowDomain(db *sqlx.DB, domain string, from, to int64) (PassRateWindow, error) {
	var w PassRateWindow
	q := `
		SELECT
			COALESCE(SUM(rr.count), 0) AS total_messages,
			COALESCE(SUM(CASE WHEN rr.eval_dkim = 'pass' OR rr.eval_spf = 'pass'
				THEN rr.count ELSE 0 END), 0) AS passed
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		WHERE r.date_range_begin >= ? AND r.date_range_begin < ?`
	if domain != "" {
		err := db.Get(&w, q+` AND r.domain = ?`, from, to, domain)
		return w, err
	}
	err := db.Get(&w, q, from, to)
	return w, err
}

// NewFailingSource is a source IP whose first-ever appearance is recent and
// which is failing DMARC.
type NewFailingSource struct {
	SourceIP  string `db:"source_ip"`
	Domain    string `db:"domain"`
	Failed    int64  `db:"failed"`
	Total     int64  `db:"total"`
	FirstSeen int64  `db:"first_seen"`
}

// GetNewFailingSources returns source IPs first observed at or after since
// that have DMARC failures (all domains together; see GetNewFailingSourcesByDomain).
func GetNewFailingSources(db *sqlx.DB, since int64) ([]NewFailingSource, error) {
	var sources []NewFailingSource
	err := db.Select(&sources, `
		SELECT
			rr.source_ip,
			'' AS domain,
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

// GetNewFailingSourcesByDomain returns (domain, source IP) pairs where the IP
// was first observed for that domain at or after since, has failures and at
// least minMessages messages.
func GetNewFailingSourcesByDomain(db *sqlx.DB, since int64, minMessages int) ([]NewFailingSource, error) {
	var sources []NewFailingSource
	err := db.Select(&sources, `
		SELECT
			rr.source_ip,
			r.domain,
			SUM(CASE WHEN rr.eval_dkim != 'pass' AND rr.eval_spf != 'pass' THEN rr.count ELSE 0 END) AS failed,
			SUM(rr.count) AS total,
			MIN(r.date_range_begin) AS first_seen
		FROM record_rows rr
		JOIN reports r ON r.id = rr.report_id
		GROUP BY r.domain, rr.source_ip
		HAVING first_seen >= ? AND failed > 0 AND total >= ?
		ORDER BY failed DESC`, since, minMessages)
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

// Alert severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Alert is a persisted, acknowledgeable alert (one row per rule/domain/key).
type Alert struct {
	ID             int64  `db:"id" json:"id"`
	Rule           string `db:"rule" json:"rule"`
	Domain         string `db:"domain" json:"domain"`
	Key            string `db:"key" json:"key"`
	Severity       string `db:"severity" json:"severity"`
	Message        string `db:"message" json:"message"`
	FirstFired     int64  `db:"first_fired" json:"first_fired"`
	LastFired      int64  `db:"last_fired" json:"last_fired"`
	Count          int64  `db:"count" json:"count"`
	AcknowledgedAt int64  `db:"acknowledged_at" json:"acknowledged_at"`
	Payload        string `db:"payload" json:"payload"` // JSON
}

// Open reports whether the alert has not been acknowledged.
func (a Alert) Open() bool { return a.AcknowledgedAt == 0 }

// UpsertAlert inserts the alert or, when a row with the same (rule, domain,
// key) exists, bumps last_fired and count and refreshes message/payload.
// It returns whether the alert should be delivered: true for a new row or for
// a row that had been acknowledged before this firing (which is re-opened).
func UpsertAlert(db *sqlx.DB, a Alert) (deliver bool, id int64, err error) {
	now := time.Now().Unix()
	var existing Alert
	err = db.Get(&existing, `SELECT * FROM alerts WHERE rule = ? AND domain = ? AND key = ?`, a.Rule, a.Domain, a.Key)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		res, err := db.Exec(`
			INSERT INTO alerts (rule, domain, key, severity, message, first_fired, last_fired, count, acknowledged_at, payload)
			VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?)`,
			a.Rule, a.Domain, a.Key, a.Severity, a.Message, now, now, a.Payload)
		if err != nil {
			return false, 0, err
		}
		id, _ = res.LastInsertId()
		return true, id, nil
	case err != nil:
		return false, 0, err
	}
	reopen := existing.AcknowledgedAt != 0
	if _, err := db.Exec(`
		UPDATE alerts SET last_fired = ?, count = count + 1, severity = ?, message = ?, payload = ?, acknowledged_at = 0
		WHERE id = ?`, now, a.Severity, a.Message, a.Payload, existing.ID); err != nil {
		return false, 0, err
	}
	return reopen, existing.ID, nil
}

// ListAlerts returns alerts by state: "open", "ack" or "all"; newest first.
func ListAlerts(db *sqlx.DB, state string, domain string, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 200
	}
	where := " WHERE 1=1"
	var args []any
	switch state {
	case "open":
		where += " AND acknowledged_at = 0"
	case "ack", "acknowledged":
		where += " AND acknowledged_at != 0"
	}
	if domain != "" {
		where += " AND domain = ?"
		args = append(args, domain)
	}
	args = append(args, limit)
	var out []Alert
	err := db.Select(&out, `SELECT * FROM alerts`+where+`
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 ELSE 2 END, last_fired DESC
		LIMIT ?`, args...)
	return out, err
}

// ListAlertDomains returns the distinct non-empty domains that have alerts,
// so the alerts page can offer them as a filter.
func ListAlertDomains(db *sqlx.DB) ([]string, error) {
	var out []string
	err := db.Select(&out, `SELECT DISTINCT domain FROM alerts WHERE domain != '' ORDER BY domain`)
	return out, err
}

// CountOpenAlerts returns the number of unacknowledged alerts, optionally for
// one domain, and the number of open critical ones.
func CountOpenAlerts(db *sqlx.DB, domain string) (open, critical int, err error) {
	var row struct {
		Open     int `db:"open"`
		Critical int `db:"critical"`
	}
	q := `SELECT COUNT(*) AS open, COALESCE(SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END), 0) AS critical
		FROM alerts WHERE acknowledged_at = 0`
	if domain != "" {
		err = db.Get(&row, q+` AND domain = ?`, domain)
	} else {
		err = db.Get(&row, q)
	}
	return row.Open, row.Critical, err
}

// AcknowledgeAlert marks an alert as acknowledged; returns false when no such alert.
func AcknowledgeAlert(db *sqlx.DB, id int64) (bool, error) {
	res, err := db.Exec(`UPDATE alerts SET acknowledged_at = ? WHERE id = ? AND acknowledged_at = 0`, time.Now().Unix(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// GetAlert returns one alert or nil.
func GetAlert(db *sqlx.DB, id int64) (*Alert, error) {
	var a Alert
	err := db.Get(&a, `SELECT * FROM alerts WHERE id = ?`, id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
