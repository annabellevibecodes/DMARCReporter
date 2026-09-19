package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// Account providers.
const (
	ProviderIMAP  = "imap"
	ProviderGmail = "gmail"
	ProviderO365  = "o365"
	ProviderGraph = "msgraph" // Office 365 via the Microsoft Graph REST API (no IMAP)
)

// Account auth types.
const (
	AuthPassword     = "password"      // IMAP LOGIN
	AuthOAuthRefresh = "oauth-refresh" // XOAUTH2 with a stored refresh token (Gmail)
	AuthOAuthClient  = "oauth-client"  // XOAUTH2 with client-credentials flow (O365 daemon)
)

// Account is one mailbox that DMARC reports are fetched from.
type Account struct {
	ID                int64  `db:"id"`
	Name              string `db:"name"`
	Provider          string `db:"provider"`
	Host              string `db:"host"`
	Port              string `db:"port"`
	Username          string `db:"username"`
	AuthType          string `db:"auth_type"`
	SecretEnc         string `db:"secret_enc"`
	Mailbox           string `db:"mailbox"`
	ProcessedMailbox  string `db:"processed_mailbox"`
	TLS               int    `db:"tls"`
	Enabled           int    `db:"enabled"`
	CreatedAt         int64  `db:"created_at"`
	LastFetchAt       int64  `db:"last_fetch_at"`
	LastFetchStatus   string `db:"last_fetch_status"`
	LastFetchDetail   string `db:"last_fetch_detail"`
	LastFetchImported int64  `db:"last_fetch_imported"`
	// Purpose is report (the default) or seed. A seed mailbox is never read
	// for report attachments and never has anything moved out of it.
	Purpose string `db:"purpose"`
}

// IsSeed reports a mailbox read for BIMI verdicts rather than for reports.
func (a Account) IsSeed() bool { return a.Purpose == PurposeSeed }

// LastFetchTime returns LastFetchAt as a UTC time.Time.
func (a Account) LastFetchTime() time.Time { return time.Unix(a.LastFetchAt, 0).UTC() }

// AccountSecrets is the decrypted content of Account.SecretEnc.
// Which fields are set depends on AuthType.
type AccountSecrets struct {
	Password     string `json:"password,omitempty"`      // password auth
	ClientID     string `json:"client_id,omitempty"`     // oauth-*
	ClientSecret string `json:"client_secret,omitempty"` // oauth-*
	RefreshToken string `json:"refresh_token,omitempty"` // oauth-refresh
	Tenant       string `json:"tenant,omitempty"`        // oauth-client (O365 tenant ID)
}

// ListAccounts returns all accounts ordered by name.
func ListAccounts(db *sqlx.DB) ([]Account, error) {
	var accounts []Account
	err := db.Select(&accounts, `SELECT * FROM accounts ORDER BY name ASC`)
	return accounts, err
}

// ListEnabledAccounts returns all enabled accounts ordered by name.
func ListEnabledAccounts(db *sqlx.DB) ([]Account, error) {
	var accounts []Account
	err := db.Select(&accounts, `SELECT * FROM accounts WHERE enabled = 1 ORDER BY name ASC`)
	return accounts, err
}

// CountEnabledAccounts returns the number of enabled accounts.
func CountEnabledAccounts(db *sqlx.DB) (int, error) {
	var n int
	err := db.Get(&n, `SELECT COUNT(*) FROM accounts WHERE enabled = 1`)
	return n, err
}

// GetAccount returns one account by ID, or nil if it does not exist.
func GetAccount(db *sqlx.DB, id int64) (*Account, error) {
	var a Account
	if err := db.Get(&a, `SELECT * FROM accounts WHERE id = ?`, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// GetAccountByName returns one account by unique name, or nil if absent.
func GetAccountByName(db *sqlx.DB, name string) (*Account, error) {
	var a Account
	if err := db.Get(&a, `SELECT * FROM accounts WHERE name = ?`, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &a, nil
}

// InsertAccount stores a new account and returns its ID.
func InsertAccount(db *sqlx.DB, a Account) (int64, error) {
	res, err := db.Exec(`
		INSERT INTO accounts
			(name, provider, host, port, username, auth_type, secret_enc,
			 mailbox, processed_mailbox, tls, enabled, created_at, purpose)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.Name, a.Provider, a.Host, a.Port, a.Username, a.AuthType, a.SecretEnc,
		a.Mailbox, a.ProcessedMailbox, a.TLS, a.Enabled, time.Now().Unix(), normalisePurpose(a.Purpose))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateAccountConfig updates the connection settings of an existing account.
//
// Changing the purpose clears the examined-message caches: a mailbox already
// walked as a report source has had none of its BIMI verdicts read, and one
// walked as a seed source has had none of its attachments opened. Without the
// purge the change would take effect only for mail arriving afterwards.
func UpdateAccountConfig(db *sqlx.DB, a Account) error {
	prev, err := GetAccount(db, a.ID)
	if err == nil && prev != nil && normalisePurpose(prev.Purpose) != normalisePurpose(a.Purpose) {
		if err := ClearAccountSeenCache(db, a.ID); err != nil {
			return err
		}
	}
	return updateAccountConfig(db, a)
}

// ClearAccountSeenCache forgets which messages of an account have been
// examined, so the next fetch walks the mailbox again.
func ClearAccountSeenCache(db *sqlx.DB, id int64) error {
	if _, err := db.Exec(`DELETE FROM imap_seen WHERE account_id = ?`, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM graph_seen WHERE account_id = ?`, id)
	return err
}

func updateAccountConfig(db *sqlx.DB, a Account) error {
	_, err := db.Exec(`
		UPDATE accounts SET
			name = ?, provider = ?, host = ?, port = ?, username = ?,
			auth_type = ?, secret_enc = ?, mailbox = ?, processed_mailbox = ?, tls = ?,
			purpose = ?
		WHERE id = ?`,
		a.Name, a.Provider, a.Host, a.Port, a.Username,
		a.AuthType, a.SecretEnc, a.Mailbox, a.ProcessedMailbox, a.TLS,
		normalisePurpose(a.Purpose), a.ID)
	return err
}

// normalisePurpose keeps the column to the two values that mean anything.
// An unrecognised purpose becomes "report": a mailbox whose role is unclear
// must not silently be read as the operator's own mail.
func normalisePurpose(p string) string {
	if strings.TrimSpace(strings.ToLower(p)) == PurposeSeed {
		return PurposeSeed
	}
	return PurposeReport
}

// UpdateAccountSecret replaces only the encrypted secret blob.
func UpdateAccountSecret(db *sqlx.DB, id int64, secretEnc string) error {
	_, err := db.Exec(`UPDATE accounts SET secret_enc = ? WHERE id = ?`, secretEnc, id)
	return err
}

// SetAccountEnabled toggles an account on or off.
func SetAccountEnabled(db *sqlx.DB, id int64, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := db.Exec(`UPDATE accounts SET enabled = ? WHERE id = ?`, v, id)
	return err
}

// DeleteAccount removes an account and its seen-message caches.
func DeleteAccount(db *sqlx.DB, id int64) error {
	if _, err := db.Exec(`DELETE FROM imap_seen WHERE account_id = ?`, id); err != nil {
		return err
	}
	if _, err := db.Exec(`DELETE FROM graph_seen WHERE account_id = ?`, id); err != nil {
		return err
	}
	_, err := db.Exec(`DELETE FROM accounts WHERE id = ?`, id)
	return err
}

// SetAccountFetchStatus records the outcome of a fetch run.
func SetAccountFetchStatus(db *sqlx.DB, id int64, status, detail string, imported int) error {
	_, err := db.Exec(`
		UPDATE accounts SET
			last_fetch_at = ?, last_fetch_status = ?, last_fetch_detail = ?, last_fetch_imported = ?
		WHERE id = ?`,
		time.Now().Unix(), status, detail, imported, id)
	return err
}

// GetSeenUIDs returns the cached set of examined UIDs for an account+UIDVALIDITY.
// Rows recorded under a different UIDVALIDITY are purged (the server reset UIDs).
func GetSeenUIDs(db *sqlx.DB, accountID int64, uidValidity uint32) (map[uint32]bool, error) {
	if _, err := db.Exec(`DELETE FROM imap_seen WHERE account_id = ? AND uidvalidity != ?`,
		accountID, uidValidity); err != nil {
		return nil, err
	}
	var uids []uint32
	if err := db.Select(&uids, `SELECT uid FROM imap_seen WHERE account_id = ? AND uidvalidity = ?`,
		accountID, uidValidity); err != nil {
		return nil, err
	}
	seen := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		seen[u] = true
	}
	return seen, nil
}

// MarkUIDsSeen records UIDs as examined-with-no-report so they are skipped next time.
func MarkUIDsSeen(db *sqlx.DB, accountID int64, uidValidity uint32, uids []uint32) error {
	if len(uids) == 0 {
		return nil
	}
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, u := range uids {
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO imap_seen (account_id, uidvalidity, uid, seen_at)
			VALUES (?,?,?,?)`, accountID, uidValidity, u, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetSeenGraphIDs returns the cached set of examined Graph message IDs for an account.
func GetSeenGraphIDs(db *sqlx.DB, accountID int64) (map[string]bool, error) {
	var ids []string
	if err := db.Select(&ids, `SELECT message_id FROM graph_seen WHERE account_id = ?`, accountID); err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	return seen, nil
}

// MarkGraphIDsSeen records Graph message IDs as examined-with-no-report so
// they are skipped next time.
func MarkGraphIDsSeen(db *sqlx.DB, accountID int64, messageIDs []string) error {
	if len(messageIDs) == 0 {
		return nil
	}
	tx, err := db.Beginx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range messageIDs {
		if _, err := tx.Exec(`
			INSERT OR IGNORE INTO graph_seen (account_id, message_id, seen_at)
			VALUES (?,?,?)`, accountID, id, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
