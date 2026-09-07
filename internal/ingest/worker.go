// Package ingest runs mail fetches in the background: on demand (Fetch button),
// and optionally on a schedule (FETCH_INTERVAL).
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/alerts"
	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/graph"
	"github.com/annabellevibecodes/dmarcreporter/internal/imap"
	"github.com/annabellevibecodes/dmarcreporter/internal/mailauth"
	"github.com/annabellevibecodes/dmarcreporter/internal/secrets"
)

// EnvAccountName is the reserved account name for configuration supplied via
// IMAP_* environment variables. It is synced into the accounts table on start.
const EnvAccountName = "Environment (IMAP_*)"

// Status is a snapshot of the worker state.
type Status struct {
	Running      bool
	LastRunAt    time.Time
	LastImported int
	LastError    string
}

// Worker coordinates background fetch runs across all enabled accounts.
type Worker struct {
	DB   *sqlx.DB
	Cfg  config.Config
	Box  *secrets.Box
	Auth *mailauth.Manager

	mu           sync.Mutex
	running      bool
	lastRunAt    time.Time
	lastImported int
	lastError    string
}

func NewWorker(db *sqlx.DB, cfg config.Config, box *secrets.Box, auth *mailauth.Manager) *Worker {
	return &Worker{DB: db, Cfg: cfg, Box: box, Auth: auth}
}

// Status returns a snapshot of the worker state.
func (w *Worker) Status() Status {
	w.mu.Lock()
	defer w.mu.Unlock()
	return Status{Running: w.running, LastRunAt: w.lastRunAt, LastImported: w.lastImported, LastError: w.lastError}
}

// TriggerAll starts a fetch run for all enabled accounts in the background.
// Returns false if a run is already in progress.
func (w *Worker) TriggerAll() bool {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return false
	}
	w.running = true
	w.mu.Unlock()

	go func() {
		imported, err := w.runAll()
		w.mu.Lock()
		w.running = false
		w.lastRunAt = time.Now().UTC()
		w.lastImported = imported
		w.lastError = ""
		if err != nil {
			w.lastError = err.Error()
		}
		w.mu.Unlock()
	}()
	return true
}

// StartScheduler triggers a fetch run every interval. Call once from main.
func (w *Worker) StartScheduler(interval time.Duration) {
	if interval <= 0 {
		return
	}
	log.Printf("ingest: scheduled fetch every %s", interval)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			w.TriggerAll()
		}
	}()
}

// runAll fetches every enabled account sequentially. Individual account
// failures are recorded on the account and do not abort the run.
func (w *Worker) runAll() (int, error) {
	accounts, err := database.ListEnabledAccounts(w.DB)
	if err != nil {
		return 0, fmt.Errorf("list accounts: %w", err)
	}
	if len(accounts) == 0 {
		return 0, fmt.Errorf("no enabled accounts configured")
	}

	totalImported := 0
	var firstErr error
	for _, acc := range accounts {
		audit.IMAPFetchStarted(acc.Name + ":" + acc.Mailbox)
		_ = database.SetAccountFetchStatus(w.DB, acc.ID, "running", "", 0)

		imported, err := w.ingestOne(acc)
		if err != nil {
			log.Printf("ingest: account %q failed: %v", acc.Name, err)
			audit.IMAPFetchFailed(acc.Name + ":" + acc.Mailbox)
			_ = database.SetAccountFetchStatus(w.DB, acc.ID, "error", err.Error(), 0)
			if firstErr == nil {
				firstErr = fmt.Errorf("account %q: %w", acc.Name, err)
			}
			continue
		}
		audit.IMAPFetchCompleted(acc.Name+":"+acc.Mailbox, imported)
		_ = database.SetAccountFetchStatus(w.DB, acc.ID, "ok", "", imported)
		totalImported += imported
	}

	if totalImported > 0 {
		alerts.Evaluate(w.DB, w.Cfg)
	}
	return totalImported, firstErr
}

func (w *Worker) ingestOne(acc database.Account) (int, error) {
	if acc.Provider == database.ProviderGraph {
		token, err := w.GraphAccessToken(&acc)
		if err != nil {
			return 0, err
		}
		return graph.IngestAccount(w.DB, acc, token)
	}
	password, saslClient, err := w.Credentials(&acc)
	if err != nil {
		return 0, err
	}
	return imap.IngestAccount(w.DB, acc, password, saslClient)
}

// GraphAccessToken decrypts the account's secrets and returns a bearer token
// for the Microsoft Graph API.
func (w *Worker) GraphAccessToken(acc *database.Account) (string, error) {
	sec, err := w.DecryptSecrets(acc)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return w.Auth.AccessToken(ctx, acc, sec)
}

// Credentials decrypts the account's secrets and returns either a password or
// a ready-to-use SASL client (for OAuth accounts).
func (w *Worker) Credentials(acc *database.Account) (password string, saslClient sasl.Client, err error) {
	sec, err := w.DecryptSecrets(acc)
	if err != nil {
		return "", nil, err
	}
	switch acc.AuthType {
	case database.AuthPassword:
		return sec.Password, nil, nil
	case database.AuthOAuthRefresh, database.AuthOAuthClient:
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		token, err := w.Auth.AccessToken(ctx, acc, sec)
		if err != nil {
			return "", nil, err
		}
		return "", mailauth.NewXOAUTH2Client(acc.Username, token), nil
	default:
		return "", nil, fmt.Errorf("unknown auth type %q", acc.AuthType)
	}
}

// DecryptSecrets decrypts and decodes an account's secret blob.
func (w *Worker) DecryptSecrets(acc *database.Account) (*database.AccountSecrets, error) {
	var sec database.AccountSecrets
	if acc.SecretEnc == "" {
		return &sec, nil
	}
	plain, err := w.Box.Decrypt(acc.SecretEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt secrets for %q (was the key file replaced?): %w", acc.Name, err)
	}
	if err := json.Unmarshal(plain, &sec); err != nil {
		return nil, fmt.Errorf("decode secrets for %q: %w", acc.Name, err)
	}
	return &sec, nil
}

// EncryptSecrets encodes and encrypts an account secret blob.
func (w *Worker) EncryptSecrets(sec *database.AccountSecrets) (string, error) {
	plain, err := json.Marshal(sec)
	if err != nil {
		return "", err
	}
	return w.Box.Encrypt(plain)
}

// SyncEnvAccount mirrors the IMAP_* environment configuration into the
// accounts table (under a reserved name) so all fetching goes through one
// path. Call once at startup; no-op when IMAP_HOST is unset.
func (w *Worker) SyncEnvAccount() error {
	if w.Cfg.IMAPHost == "" {
		return nil
	}
	secretEnc, err := w.EncryptSecrets(&database.AccountSecrets{Password: w.Cfg.IMAPPass})
	if err != nil {
		return err
	}
	tls := 0
	if w.Cfg.IMAPTLS {
		tls = 1
	}
	acc := database.Account{
		Name:             EnvAccountName,
		Provider:         database.ProviderIMAP,
		Host:             w.Cfg.IMAPHost,
		Port:             w.Cfg.IMAPPort,
		Username:         w.Cfg.IMAPUser,
		AuthType:         database.AuthPassword,
		SecretEnc:        secretEnc,
		Mailbox:          w.Cfg.IMAPMailbox,
		ProcessedMailbox: w.Cfg.IMAPProcessedMailbox,
		TLS:              tls,
		Enabled:          1,
	}
	existing, err := database.GetAccountByName(w.DB, EnvAccountName)
	if err != nil {
		return err
	}
	if existing == nil {
		_, err = database.InsertAccount(w.DB, acc)
		return err
	}
	acc.ID = existing.ID
	return database.UpdateAccountConfig(w.DB, acc)
}
