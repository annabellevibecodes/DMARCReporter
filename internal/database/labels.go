package database

import (
	"database/sql"
	"errors"
	"time"

	"github.com/jmoiron/sqlx"
)

// Valid ip_labels.classification values ("" clears the override).
var Classifications = []string{"known_good", "forwarder", "unknown", "suspicious"}

// ValidClassification reports whether c is "" or one of Classifications.
func ValidClassification(c string) bool {
	if c == "" {
		return true
	}
	for _, v := range Classifications {
		if v == c {
			return true
		}
	}
	return false
}

// IPLabel is a user-set label for a source IP.
type IPLabel struct {
	IP             string `db:"ip" json:"ip"`
	Label          string `db:"label" json:"label"`
	Classification string `db:"classification" json:"classification"`
	Notes          string `db:"notes" json:"notes"`
	UpdatedAt      int64  `db:"updated_at" json:"updated_at"`
}

// UpsertIPLabel stores or updates the label for an IP. An all-empty label
// deletes the row.
func UpsertIPLabel(db *sqlx.DB, l IPLabel) error {
	if l.Label == "" && l.Classification == "" && l.Notes == "" {
		_, err := db.Exec(`DELETE FROM ip_labels WHERE ip = ?`, l.IP)
		return err
	}
	_, err := db.Exec(`
		INSERT INTO ip_labels (ip, label, classification, notes, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			label = excluded.label,
			classification = excluded.classification,
			notes = excluded.notes,
			updated_at = excluded.updated_at`,
		l.IP, l.Label, l.Classification, l.Notes, time.Now().Unix())
	return err
}

// GetIPLabel returns the label for ip, or nil when none is set.
func GetIPLabel(db *sqlx.DB, ip string) (*IPLabel, error) {
	var l IPLabel
	err := db.Get(&l, `SELECT * FROM ip_labels WHERE ip = ?`, ip)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// ListIPLabels returns every label keyed by IP.
func ListIPLabels(db *sqlx.DB) (map[string]IPLabel, error) {
	var rows []IPLabel
	if err := db.Select(&rows, `SELECT * FROM ip_labels`); err != nil {
		return nil, err
	}
	m := make(map[string]IPLabel, len(rows))
	for _, r := range rows {
		m[r.IP] = r
	}
	return m, nil
}

// Selector is one row of the DKIM selector inventory.
type Selector struct {
	Domain    string `db:"domain"`
	Selector  string `db:"selector"`
	FirstSeen int64  `db:"first_seen"`
	LastSeen  int64  `db:"last_seen"`
	Expected  int    `db:"expected"` // -1 unset, 0 no, 1 yes
}

// ListSelectors returns the selector inventory, optionally scoped to a signing domain.
func ListSelectors(db *sqlx.DB, domain string) ([]Selector, error) {
	var out []Selector
	if domain == "" {
		err := db.Select(&out, `SELECT * FROM selectors ORDER BY domain, selector`)
		return out, err
	}
	err := db.Select(&out, `SELECT * FROM selectors WHERE domain = ? ORDER BY selector`, domain)
	return out, err
}

// SetSelectorExpected marks a selector as expected (1), unexpected (0) or unset (-1).
// The row is created if the selector has not been observed yet.
func SetSelectorExpected(db *sqlx.DB, domain, selector string, expected int) error {
	if expected < -1 || expected > 1 {
		expected = -1
	}
	_, err := db.Exec(`
		INSERT INTO selectors (domain, selector, first_seen, last_seen, expected)
		VALUES (?, ?, 0, 0, ?)
		ON CONFLICT(domain, selector) DO UPDATE SET expected = excluded.expected`,
		domain, selector, expected)
	return err
}

// ManagedDomain is a domain the operator owns.
type ManagedDomain struct {
	Domain  string `db:"domain" json:"domain"`
	AddedAt int64  `db:"added_at" json:"added_at"`
}

// ListManagedDomains returns all managed domains alphabetically.
func ListManagedDomains(db *sqlx.DB) ([]ManagedDomain, error) {
	var out []ManagedDomain
	err := db.Select(&out, `SELECT * FROM managed_domains ORDER BY domain`)
	return out, err
}

// ManagedDomainSet returns the managed domains as a set.
func ManagedDomainSet(db *sqlx.DB) (map[string]bool, error) {
	list, err := ListManagedDomains(db)
	if err != nil {
		return nil, err
	}
	m := make(map[string]bool, len(list))
	for _, d := range list {
		m[d.Domain] = true
	}
	return m, nil
}

// AddManagedDomain adds a domain (no-op when already present).
func AddManagedDomain(db *sqlx.DB, domain string) error {
	_, err := db.Exec(`INSERT OR IGNORE INTO managed_domains (domain, added_at) VALUES (?, ?)`,
		domain, time.Now().Unix())
	return err
}

// RemoveManagedDomain deletes a domain from the managed list.
func RemoveManagedDomain(db *sqlx.DB, domain string) error {
	_, err := db.Exec(`DELETE FROM managed_domains WHERE domain = ?`, domain)
	return err
}

// SeedManagedDomains inserts every distinct reports.domain into managed_domains.
// Returns the number of rows added.
func SeedManagedDomains(db *sqlx.DB) (int, error) {
	res, err := db.Exec(`
		INSERT OR IGNORE INTO managed_domains (domain, added_at)
		SELECT DISTINCT domain, ? FROM reports WHERE domain != ''`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
