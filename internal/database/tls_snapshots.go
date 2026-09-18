package database

import (
	"database/sql"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

func sortStrings(s []string) { sort.Strings(s) }

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

func atoi64(s string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// Snapshot kinds.
const (
	TLSSnapshotTLSRPT = "tlsrpt"  // _smtp._tls.<domain>
	TLSSnapshotMTASTS = "mta_sts" // _mta-sts.<domain> + the policy file
	TLSSnapshotTLSA   = "tlsa"    // _25._tcp.<mx host>
)

// TLSSnapshot is one observed state of a published record.
//
// Rows are one per *distinct* state, not one per check: re-observing the same
// content bumps LastSeen and the check count, and a change writes a new row.
// That makes the table a change log by construction — which is what T8 drift
// and the change-log view need — without growing by one row per Enrich run.
type TLSSnapshot struct {
	ID        int64  `db:"id" json:"id"`
	Domain    string `db:"domain" json:"domain"`
	Kind      string `db:"kind" json:"kind"`
	Host      string `db:"host" json:"host"` // MX host for tlsa, "" otherwise
	Content   string `db:"content" json:"content"`
	Detail    string `db:"detail" json:"detail"` // JSON of the parsed fields
	Error     string `db:"error" json:"error"`
	FirstSeen int64  `db:"first_seen" json:"first_seen"`
	LastSeen  int64  `db:"last_seen" json:"last_seen"`
	Checks    int64  `db:"checks" json:"checks"`
}

// FirstSeenTime returns FirstSeen as a UTC time.
func (s TLSSnapshot) FirstSeenTime() time.Time { return time.Unix(s.FirstSeen, 0).UTC() }

// UpsertTLSSnapshot records an observation.
//
// changed reports whether this differed from the most recent state, which is
// what makes the row a change rather than a confirmation.
func UpsertTLSSnapshot(db *sqlx.DB, s TLSSnapshot) (changed bool, err error) {
	now := time.Now().Unix()
	if s.LastSeen == 0 {
		s.LastSeen = now
	}
	if s.FirstSeen == 0 {
		s.FirstSeen = s.LastSeen
	}
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	s.Host = strings.ToLower(strings.TrimSpace(s.Host))

	current, err := GetCurrentTLSSnapshot(db, s.Domain, s.Kind, s.Host)
	if err != nil {
		return false, err
	}
	if current != nil && current.Content == s.Content && current.Error == s.Error {
		_, err := db.Exec(`
			UPDATE tls_snapshots SET last_seen = ?, checks = checks + 1, detail = ?
			 WHERE id = ?`, s.LastSeen, s.Detail, current.ID)
		return false, err
	}

	_, err = db.Exec(`
		INSERT INTO tls_snapshots (domain, kind, host, content, detail, error, first_seen, last_seen, checks)
		VALUES (?,?,?,?,?,?,?,?,1)`,
		s.Domain, s.Kind, s.Host, s.Content, s.Detail, s.Error, s.FirstSeen, s.LastSeen)
	if err != nil {
		return false, err
	}
	// The first observation of a record is not a change to report.
	return current != nil, nil
}

// GetCurrentTLSSnapshot returns the most recently observed state, or nil.
func GetCurrentTLSSnapshot(db *sqlx.DB, domain, kind, host string) (*TLSSnapshot, error) {
	var s TLSSnapshot
	err := db.Get(&s, `
		SELECT id, domain, kind, host, content, detail, error, first_seen, last_seen, checks
		  FROM tls_snapshots
		 WHERE domain = ? AND kind = ? AND host = ?
		 ORDER BY last_seen DESC, id DESC LIMIT 1`,
		strings.ToLower(domain), kind, strings.ToLower(host))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// ListTLSSnapshots returns the observed states of one domain, newest first.
// kind may be "" for every kind.
func ListTLSSnapshots(db *sqlx.DB, domain, kind string, limit int) ([]TLSSnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []TLSSnapshot
	query := `
		SELECT id, domain, kind, host, content, detail, error, first_seen, last_seen, checks
		  FROM tls_snapshots WHERE domain = ?`
	args := []any{strings.ToLower(domain)}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY last_seen DESC, id DESC LIMIT ?`
	args = append(args, limit)

	err := db.Select(&out, query, args...)
	if out == nil {
		out = []TLSSnapshot{}
	}
	return out, err
}

// ListCurrentTLSSnapshots returns the current state of every record of one
// kind, across all domains.
func ListCurrentTLSSnapshots(db *sqlx.DB, kind string) ([]TLSSnapshot, error) {
	var out []TLSSnapshot
	err := db.Select(&out, `
		SELECT s.id, s.domain, s.kind, s.host, s.content, s.detail, s.error, s.first_seen, s.last_seen, s.checks
		  FROM tls_snapshots s
		  JOIN (
		        SELECT domain, kind, host, MAX(last_seen) AS last_seen
		          FROM tls_snapshots WHERE kind = ?
		         GROUP BY domain, kind, host
		  ) latest
		    ON latest.domain = s.domain AND latest.kind = s.kind
		   AND latest.host = s.host AND latest.last_seen = s.last_seen
		 ORDER BY s.domain, s.host`, kind)
	if out == nil {
		out = []TLSSnapshot{}
	}
	return out, err
}

// ListStaleTLSPolicyDomains returns the domains whose published TLS records
// have not been checked since before cutoff: every managed domain, plus every
// domain seen in a TLS report.
func ListStaleTLSPolicyDomains(db *sqlx.DB, cutoff int64) ([]string, error) {
	var out []string
	err := db.Select(&out, `
		WITH candidates AS (
			SELECT domain FROM managed_domains
			UNION
			SELECT DISTINCT policy_domain AS domain FROM tlsrpt_policies WHERE policy_domain != ''
		)
		SELECT c.domain FROM candidates c
		 WHERE c.domain != ''
		   AND NOT EXISTS (
		        SELECT 1 FROM tls_snapshots s
		         WHERE s.domain = c.domain AND s.kind = ? AND s.last_seen >= ?
		   )
		 ORDER BY c.domain`, TLSSnapshotTLSRPT, cutoff)
	return out, err
}

// TLSDrift is one disagreement between what a domain publishes and what a
// reporter said it applied (T8).
type TLSDrift struct {
	Domain string `json:"domain"`
	Kind   string `json:"kind"` // mta_sts | tlsa
	// Published is the current snapshot; Reported is what the report carried.
	Published string `json:"published"`
	Reported  string `json:"reported"`
	// Field names what differs for an MTA-STS policy (mode, max_age, mx), or
	// is "rrset" for TLSA.
	Field      string `json:"field"`
	OrgName    string `json:"org_name"`
	LastReport int64  `json:"last_report"`
}

// GetTLSPolicyDrift is the half of T8 that needs the published snapshots:
// what reporters applied versus what the domain currently publishes.
//
// A difference is not automatically a fault — a report describes a window
// that may predate a deliberate change, so the report's window is returned
// with each row and the UI says as much. What it reliably catches is the
// case the brief cares about: a botched key rollover, where senders are still
// applying an RRset the domain no longer publishes.
func GetTLSPolicyDrift(db *sqlx.DB, f TLSFilter) ([]TLSDrift, error) {
	where, args := f.where()

	var rows []struct {
		Domain       string `db:"policy_domain"`
		PolicyType   string `db:"policy_type"`
		PolicyString string `db:"policy_string"`
		STSMode      string `db:"sts_mode"`
		STSMaxAge    int64  `db:"sts_max_age"`
		MXPattern    string `db:"mx_host_pattern"`
		OrgName      string `db:"org_name"`
		LastReport   int64  `db:"last_report"`
	}
	if err := db.Select(&rows, `
		SELECT p.policy_domain, p.policy_type, p.policy_string, p.sts_mode, p.sts_max_age,
		       p.mx_host_pattern, r.org_name, MAX(r.date_range_end) AS last_report
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+where+`
		   AND p.policy_type IN ('sts','tlsa')
		 GROUP BY p.policy_domain, p.policy_type, p.policy_string, p.sts_mode, p.sts_max_age,
		          p.mx_host_pattern, r.org_name`, args...); err != nil {
		return nil, err
	}

	published := map[string]*TLSSnapshot{}
	snapshotFor := func(domain, kind, host string) (*TLSSnapshot, error) {
		key := kind + "\x00" + domain + "\x00" + host
		if s, ok := published[key]; ok {
			return s, nil
		}
		s, err := GetCurrentTLSSnapshot(db, domain, kind, host)
		if err != nil {
			return nil, err
		}
		published[key] = s
		return s, nil
	}

	var out []TLSDrift
	for _, row := range rows {
		switch row.PolicyType {
		case "sts":
			snap, err := snapshotFor(row.Domain, TLSSnapshotMTASTS, "")
			if err != nil {
				return nil, err
			}
			if snap == nil || snap.Content == "" {
				continue
			}
			pub := parseSTSSnapshot(snap.Content)
			if row.STSMode != "" && pub.mode != "" && row.STSMode != pub.mode {
				out = append(out, TLSDrift{
					Domain: row.Domain, Kind: TLSSnapshotMTASTS, Field: "mode",
					Published: pub.mode, Reported: row.STSMode,
					OrgName: row.OrgName, LastReport: row.LastReport,
				})
			}
			if row.STSMaxAge > 0 && pub.maxAge > 0 && row.STSMaxAge != pub.maxAge {
				out = append(out, TLSDrift{
					Domain: row.Domain, Kind: TLSSnapshotMTASTS, Field: "max_age",
					Published: itoa64(pub.maxAge), Reported: itoa64(row.STSMaxAge),
					OrgName: row.OrgName, LastReport: row.LastReport,
				})
			}
			if row.MXPattern != "" && len(pub.mx) > 0 {
				reported := strings.Split(row.MXPattern, ",")
				if !sameStringSet(reported, pub.mx) {
					out = append(out, TLSDrift{
						Domain: row.Domain, Kind: TLSSnapshotMTASTS, Field: "mx",
						Published: strings.Join(pub.mx, ","), Reported: row.MXPattern,
						OrgName: row.OrgName, LastReport: row.LastReport,
					})
				}
			}

		case "tlsa":
			// A TLSA policy is reported per MX host pattern; the snapshot is
			// per host, so compare against each host the report names.
			for _, host := range strings.Split(row.MXPattern, ",") {
				host = strings.TrimSpace(host)
				if host == "" || strings.Contains(host, "*") {
					continue // a wildcard names no single host to look up
				}
				snap, err := snapshotFor(row.Domain, TLSSnapshotTLSA, host)
				if err != nil {
					return nil, err
				}
				if snap == nil || snap.Content == "" {
					continue
				}
				reported := normaliseRRset(TLSPolicyStringLines(row.PolicyString))
				if reported == "" {
					continue
				}
				if reported != normaliseRRset(strings.Split(snap.Content, "\n")) {
					out = append(out, TLSDrift{
						Domain: row.Domain, Kind: TLSSnapshotTLSA, Field: "rrset",
						Published: snap.Content, Reported: reported,
						OrgName: row.OrgName, LastReport: row.LastReport,
					})
				}
			}
		}
	}
	return out, nil
}

// stsSnapshotFields is the published policy parsed back out of a snapshot.
type stsSnapshotFields struct {
	mode   string
	maxAge int64
	mx     []string
}

// parseSTSSnapshot reads the stored policy body. The snapshot keeps the file
// verbatim, so this is the same parse a sender would do.
func parseSTSSnapshot(content string) stsSnapshotFields {
	var out stsSnapshotFields
	for _, line := range strings.Split(content, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "mode":
			out.mode = strings.ToLower(value)
		case "max_age":
			out.maxAge = atoi64(value)
		case "mx":
			if value != "" {
				out.mx = append(out.mx, strings.ToLower(value))
			}
		}
	}
	sortStrings(out.mx)
	return out
}

// normaliseRRset renders RRset lines in a stable order with collapsed
// whitespace, so formatting differences between a reporter and a zone file do
// not read as drift.
func normaliseRRset(lines []string) string {
	var out []string
	for _, line := range lines {
		fields := strings.Fields(strings.ToUpper(line))
		if len(fields) == 0 {
			continue
		}
		out = append(out, strings.Join(fields, " "))
	}
	sortStrings(out)
	return strings.Join(out, "\n")
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	for i := range x {
		x[i] = strings.ToLower(strings.TrimSpace(x[i]))
	}
	for i := range y {
		y[i] = strings.ToLower(strings.TrimSpace(y[i]))
	}
	sortStrings(x)
	sortStrings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
