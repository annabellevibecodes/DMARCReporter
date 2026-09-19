package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// Snapshot kinds.
const (
	BIMISnapshotRecord    = "record"    // <selector>._bimi.<domain>
	BIMISnapshotIndicator = "indicator" // the document served at l=
	BIMISnapshotEvidence  = "evidence"  // the document served at a=
)

// Sources of a BIMI selector, recorded so B3 can say how one came to be known.
const (
	BIMISelectorPublished = "published" // found in DNS
	BIMISelectorReported  = "reported"  // echoed back by an evaluator
	BIMISelectorLPS       = "lps"       // implied by a local-part prefix list
)

// BIMISnapshot is one observed state of part of a domain's BIMI configuration.
//
// Rows are one per *distinct* state, not one per check: re-observing the same
// content bumps LastSeen and the check count, and a change writes a new row.
// That makes the table a change log by construction, which is what B5 needs,
// without it growing by one row per domain per Enrich run.
type BIMISnapshot struct {
	ID        int64  `db:"id" json:"id"`
	Domain    string `db:"domain" json:"domain"`
	Selector  string `db:"selector" json:"selector"`
	Kind      string `db:"kind" json:"kind"`
	Content   string `db:"content" json:"content"`
	Detail    string `db:"detail" json:"detail"` // JSON of the parsed fields
	Error     string `db:"error" json:"error"`
	FirstSeen int64  `db:"first_seen" json:"first_seen"`
	LastSeen  int64  `db:"last_seen" json:"last_seen"`
	Checks    int64  `db:"checks" json:"checks"`
}

// FirstSeenTime returns FirstSeen as a UTC time.
func (s BIMISnapshot) FirstSeenTime() time.Time { return time.Unix(s.FirstSeen, 0).UTC() }

// LastSeenTime returns LastSeen as a UTC time.
func (s BIMISnapshot) LastSeenTime() time.Time { return time.Unix(s.LastSeen, 0).UTC() }

const bimiSnapshotCols = `id, domain, selector, kind, content, detail, error, first_seen, last_seen, checks`

// UpsertBIMISnapshot records one observation.
//
// changed reports whether this differed from the most recent state, which is
// what makes the new row a change rather than a confirmation. The first
// observation of anything is never a change: there was nothing to change from.
func UpsertBIMISnapshot(db *sqlx.DB, s BIMISnapshot) (changed bool, err error) {
	now := time.Now().Unix()
	if s.LastSeen == 0 {
		s.LastSeen = now
	}
	if s.FirstSeen == 0 {
		s.FirstSeen = s.LastSeen
	}
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	s.Selector = normaliseBIMISelector(s.Selector)
	if s.Detail == "" {
		s.Detail = "{}"
	}

	current, err := GetCurrentBIMISnapshot(db, s.Domain, s.Selector, s.Kind)
	if err != nil {
		return false, err
	}
	if current != nil && current.Content == s.Content && current.Error == s.Error {
		_, err := db.Exec(`
			UPDATE bimi_snapshots SET last_seen = ?, checks = checks + 1, detail = ?
			 WHERE id = ?`, s.LastSeen, s.Detail, current.ID)
		return false, err
	}

	_, err = db.Exec(`
		INSERT INTO bimi_snapshots (domain, selector, kind, content, detail, error, first_seen, last_seen, checks)
		VALUES (?,?,?,?,?,?,?,?,1)`,
		s.Domain, s.Selector, s.Kind, s.Content, s.Detail, s.Error, s.FirstSeen, s.LastSeen)
	if err != nil {
		return false, err
	}
	return current != nil, nil
}

// GetCurrentBIMISnapshot returns the most recently observed state, or nil.
func GetCurrentBIMISnapshot(db *sqlx.DB, domain, selector, kind string) (*BIMISnapshot, error) {
	var s BIMISnapshot
	err := db.Get(&s, `
		SELECT `+bimiSnapshotCols+`
		  FROM bimi_snapshots
		 WHERE domain = ? AND selector = ? AND kind = ?
		 ORDER BY last_seen DESC, id DESC LIMIT 1`,
		strings.ToLower(strings.TrimSpace(domain)), normaliseBIMISelector(selector), kind)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &s, nil
}

// ListBIMISnapshots returns observed states newest first — the change log
// behind B5. An empty domain or kind means every domain or every kind.
func ListBIMISnapshots(db *sqlx.DB, domain, kind string, limit int) ([]BIMISnapshot, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `SELECT ` + bimiSnapshotCols + ` FROM bimi_snapshots WHERE 1=1`
	var args []any
	if domain != "" {
		query += ` AND domain = ?`
		args = append(args, strings.ToLower(strings.TrimSpace(domain)))
	}
	if kind != "" {
		query += ` AND kind = ?`
		args = append(args, kind)
	}
	query += ` ORDER BY last_seen DESC, id DESC LIMIT ?`
	args = append(args, limit)

	out := []BIMISnapshot{}
	err := db.Select(&out, query, args...)
	if out == nil {
		out = []BIMISnapshot{}
	}
	return out, err
}

// ListCurrentBIMISnapshots returns the current state of one kind for every
// domain and selector — the inventory behind B1.
func ListCurrentBIMISnapshots(db *sqlx.DB, kind string) ([]BIMISnapshot, error) {
	out := []BIMISnapshot{}
	err := db.Select(&out, `
		SELECT s.id, s.domain, s.selector, s.kind, s.content, s.detail, s.error,
		       s.first_seen, s.last_seen, s.checks
		  FROM bimi_snapshots s
		  JOIN (
		        SELECT domain, selector, kind, MAX(last_seen) AS last_seen
		          FROM bimi_snapshots WHERE kind = ?
		         GROUP BY domain, selector, kind
		  ) latest
		    ON latest.domain = s.domain AND latest.selector = s.selector
		   AND latest.kind = s.kind AND latest.last_seen = s.last_seen
		 ORDER BY s.domain, s.selector`, kind)
	if out == nil {
		out = []BIMISnapshot{}
	}
	return out, err
}

// ListStaleBIMIDomains returns the domains whose BIMI record has not been
// looked up since before cutoff: every managed domain, plus every policy
// domain seen in a report, so a domain gains BIMI data as soon as mail for it
// is reported rather than only once someone adds it by hand.
func ListStaleBIMIDomains(db *sqlx.DB, cutoff int64) ([]string, error) {
	out := []string{}
	err := db.Select(&out, `
		WITH candidates AS (
			SELECT domain FROM managed_domains
			UNION
			SELECT DISTINCT domain FROM reports WHERE domain != ''
		)
		SELECT c.domain FROM candidates c
		 WHERE c.domain != ''
		   AND NOT EXISTS (
		        SELECT 1 FROM bimi_snapshots s
		         WHERE s.domain = c.domain AND s.kind = ? AND s.last_seen >= ?
		   )
		 ORDER BY c.domain`, BIMISnapshotRecord, cutoff)
	return out, err
}

// BIMISelector is one row of the BIMI selector inventory (B3).
type BIMISelector struct {
	Domain    string `db:"domain" json:"domain"`
	Selector  string `db:"selector" json:"selector"`
	Source    string `db:"source" json:"source"`
	FirstSeen int64  `db:"first_seen" json:"first_seen"`
	LastSeen  int64  `db:"last_seen" json:"last_seen"`
	Expected  int    `db:"expected" json:"expected"` // -1 unset, 0 no, 1 yes
}

// UpsertBIMISelector records that a selector was seen at a point in time.
//
// The operator's expected flag is never touched here, and neither is an
// existing first_seen: an inventory that forgets when a selector appeared
// cannot answer "is this new?", which is the only question X22 asks.
func UpsertBIMISelector(db *sqlx.DB, s BIMISelector) error {
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	s.Selector = normaliseBIMISelector(s.Selector)
	if s.Source == "" {
		s.Source = BIMISelectorPublished
	}
	if s.LastSeen == 0 {
		s.LastSeen = time.Now().Unix()
	}
	if s.FirstSeen == 0 {
		s.FirstSeen = s.LastSeen
	}
	_, err := db.Exec(`
		INSERT INTO bimi_selectors (domain, selector, source, first_seen, last_seen, expected)
		VALUES (?,?,?,?,?,-1)
		ON CONFLICT(domain, selector) DO UPDATE SET
			source     = excluded.source,
			first_seen = MIN(bimi_selectors.first_seen, excluded.first_seen),
			last_seen  = MAX(bimi_selectors.last_seen, excluded.last_seen)`,
		s.Domain, s.Selector, s.Source, s.FirstSeen, s.LastSeen)
	return err
}

// ListBIMISelectors returns the selector inventory, optionally for one domain.
func ListBIMISelectors(db *sqlx.DB, domain string) ([]BIMISelector, error) {
	out := []BIMISelector{}
	if domain == "" {
		err := db.Select(&out, `SELECT * FROM bimi_selectors ORDER BY domain, selector`)
		return out, err
	}
	err := db.Select(&out, `SELECT * FROM bimi_selectors WHERE domain = ? ORDER BY selector`,
		strings.ToLower(strings.TrimSpace(domain)))
	return out, err
}

// SetBIMISelectorExpected marks a selector expected (1), unexpected (0) or
// unset (-1), creating the row when the selector has not been observed yet.
func SetBIMISelectorExpected(db *sqlx.DB, domain, selector string, expected int) error {
	if expected < -1 || expected > 1 {
		expected = -1
	}
	_, err := db.Exec(`
		INSERT INTO bimi_selectors (domain, selector, source, first_seen, last_seen, expected)
		VALUES (?, ?, ?, 0, 0, ?)
		ON CONFLICT(domain, selector) DO UPDATE SET expected = excluded.expected`,
		strings.ToLower(strings.TrimSpace(domain)), normaliseBIMISelector(selector), BIMISelectorPublished, expected)
	return err
}

// normaliseBIMISelector lower-cases a selector; core spec §4.5 states they are
// case insensitive, so two spellings must not become two inventory rows.
func normaliseBIMISelector(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "default"
	}
	return s
}
