package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/graph"
	"github.com/annabellevibecodes/dmarcreporter/internal/imap"
	"github.com/annabellevibecodes/dmarcreporter/internal/ingest"
	"github.com/annabellevibecodes/dmarcreporter/internal/mailauth"
)

// providerPreset fills in host/port for the well-known providers. Host/port
// are unused for the Graph API provider (no socket is dialed) — the values
// returned are cosmetic, just enough to pass validation.
func providerPreset(provider, host, port string) (string, string) {
	switch provider {
	case database.ProviderGmail:
		return "imap.gmail.com", "993"
	case database.ProviderO365:
		return "outlook.office365.com", "993"
	case database.ProviderGraph:
		return "graph.microsoft.com", "443"
	default:
		if port == "" {
			port = "993"
		}
		return host, port
	}
}

// HandleAccountsPage renders the mail-accounts settings page.
func (a *App) HandleAccountsPage(c *fiber.Ctx) error {
	accounts, err := database.ListAccounts(a.DB)
	if err != nil {
		return err
	}
	// Never expose secrets to the template.
	for i := range accounts {
		accounts[i].SecretEnc = ""
	}
	status := a.Worker.Status()
	flashKind, flashMsg := getFlash(c)
	return c.Render("accounts", fiber.Map{
		"Title":         "Mail Accounts — DMARC Reporter",
		"Theme":         getTheme(c),
		"ActivePage":    "accounts",
		"Accounts":      accounts,
		"FetchRunning":  status.Running,
		"LastRunAt":     status.LastRunAt,
		"LastImported":  status.LastImported,
		"LastError":     status.LastError,
		"EnvAccount":    ingest.EnvAccountName,
		"IMAPEnabled":   a.FetchEnabled(),
		"FlashKind":     flashKind,
		"FlashMsg":      flashMsg,
		"CSRFToken":     c.Locals("csrf"),
	}, "layouts/base")
}

// HandleAccountCreate stores a new fetch account.
func (a *App) HandleAccountCreate(c *fiber.Ctx) error {
	name := strings.TrimSpace(c.FormValue("name"))
	provider := c.FormValue("provider")
	username := strings.TrimSpace(c.FormValue("username"))
	mailbox := strings.TrimSpace(c.FormValue("mailbox"))
	processed := strings.TrimSpace(c.FormValue("processed_mailbox"))

	if name == "" || username == "" {
		a.setFlash(c, "error", "Name and username are required.")
		return c.Redirect("/accounts")
	}
	if name == ingest.EnvAccountName {
		a.setFlash(c, "error", "That account name is reserved.")
		return c.Redirect("/accounts")
	}
	switch provider {
	case database.ProviderIMAP, database.ProviderGmail, database.ProviderO365, database.ProviderGraph:
	default:
		a.setFlash(c, "error", "Unknown provider.")
		return c.Redirect("/accounts")
	}
	if mailbox == "" {
		if provider == database.ProviderGraph {
			mailbox = "inbox"
		} else {
			mailbox = "INBOX"
		}
	}
	host, port := providerPreset(provider, strings.TrimSpace(c.FormValue("host")), strings.TrimSpace(c.FormValue("port")))
	if host == "" {
		a.setFlash(c, "error", "Host is required for generic IMAP accounts.")
		return c.Redirect("/accounts")
	}

	// Determine auth type and collect secrets.
	sec := database.AccountSecrets{
		Password:     c.FormValue("password"),
		ClientID:     strings.TrimSpace(c.FormValue("client_id")),
		ClientSecret: c.FormValue("client_secret"),
		Tenant:       strings.TrimSpace(c.FormValue("tenant")),
	}
	authType := database.AuthPassword
	switch provider {
	case database.ProviderGmail:
		if sec.Password == "" {
			if sec.ClientID == "" || sec.ClientSecret == "" {
				a.setFlash(c, "error", "Gmail needs either an app password, or an OAuth client ID and secret.")
				return c.Redirect("/accounts")
			}
			authType = database.AuthOAuthRefresh
		}
	case database.ProviderO365:
		if sec.Tenant == "" || sec.ClientID == "" || sec.ClientSecret == "" {
			a.setFlash(c, "error", "Office 365 needs tenant ID, client ID, and client secret (basic auth is disabled by Microsoft).")
			return c.Redirect("/accounts")
		}
		authType = database.AuthOAuthClient
		sec.Password = ""
	case database.ProviderGraph:
		if sec.Tenant == "" || sec.ClientID == "" || sec.ClientSecret == "" {
			a.setFlash(c, "error", "Office 365 (Graph API) needs tenant ID, client ID, and client secret.")
			return c.Redirect("/accounts")
		}
		authType = database.AuthOAuthClient
		sec.Password = ""
	default:
		if sec.Password == "" {
			a.setFlash(c, "error", "Password is required for IMAP accounts.")
			return c.Redirect("/accounts")
		}
	}

	secretEnc, err := a.Worker.EncryptSecrets(&sec)
	if err != nil {
		return err
	}
	tls := 1
	if c.FormValue("tls") == "off" {
		tls = 0
	}
	acc := database.Account{
		Name:             name,
		Provider:         provider,
		Host:             host,
		Port:             port,
		Username:         username,
		AuthType:         authType,
		SecretEnc:        secretEnc,
		Mailbox:          mailbox,
		ProcessedMailbox: processed,
		TLS:              tls,
		Enabled:          1,
	}
	id, err := database.InsertAccount(a.DB, acc)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			a.setFlash(c, "error", "An account with that name already exists.")
			return c.Redirect("/accounts")
		}
		return err
	}

	if authType == database.AuthOAuthRefresh {
		// Gmail OAuth accounts need the one-time consent flow before they work.
		return a.startGoogleConsent(c, id)
	}
	a.setFlash(c, "success", fmt.Sprintf("Account %q added. Use Test to verify the connection.", name))
	return c.Redirect("/accounts")
}

func (a *App) accountFromParam(c *fiber.Ctx) (*database.Account, error) {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return nil, fiber.ErrBadRequest
	}
	acc, err := database.GetAccount(a.DB, id)
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, fiber.ErrNotFound
	}
	return acc, nil
}

// HandleAccountDelete removes an account.
func (a *App) HandleAccountDelete(c *fiber.Ctx) error {
	acc, err := a.accountFromParam(c)
	if err != nil {
		return err
	}
	if err := database.DeleteAccount(a.DB, acc.ID); err != nil {
		return err
	}
	a.Worker.Auth.Invalidate(acc.ID)
	a.setFlash(c, "success", fmt.Sprintf("Account %q deleted.", acc.Name))
	return c.Redirect("/accounts")
}

// HandleAccountToggle enables or disables an account.
func (a *App) HandleAccountToggle(c *fiber.Ctx) error {
	acc, err := a.accountFromParam(c)
	if err != nil {
		return err
	}
	enable := acc.Enabled == 0
	if err := database.SetAccountEnabled(a.DB, acc.ID, enable); err != nil {
		return err
	}
	verb := "disabled"
	if enable {
		verb = "enabled"
	}
	a.setFlash(c, "success", fmt.Sprintf("Account %q %s.", acc.Name, verb))
	return c.Redirect("/accounts")
}

// HandleAccountTest checks connectivity and mailbox access synchronously.
func (a *App) HandleAccountTest(c *fiber.Ctx) error {
	acc, err := a.accountFromParam(c)
	if err != nil {
		return err
	}

	if acc.Provider == database.ProviderGraph {
		token, err := a.Worker.GraphAccessToken(acc)
		if err != nil {
			a.setFlash(c, "error", fmt.Sprintf("Account %q: %v", acc.Name, err))
			return c.Redirect("/accounts")
		}
		if err := graph.TestAccount(*acc, token); err != nil {
			a.setFlash(c, "error", fmt.Sprintf("Account %q: connection test failed: %v", acc.Name, err))
			return c.Redirect("/accounts")
		}
		a.setFlash(c, "success", fmt.Sprintf("Account %q: connection and mailbox OK.", acc.Name))
		return c.Redirect("/accounts")
	}

	password, saslClient, err := a.Worker.Credentials(acc)
	if err != nil {
		a.setFlash(c, "error", fmt.Sprintf("Account %q: %v", acc.Name, err))
		return c.Redirect("/accounts")
	}
	if err := imap.TestAccount(*acc, password, saslClient); err != nil {
		a.setFlash(c, "error", fmt.Sprintf("Account %q: connection test failed: %v", acc.Name, err))
		return c.Redirect("/accounts")
	}
	a.setFlash(c, "success", fmt.Sprintf("Account %q: connection and mailbox OK.", acc.Name))
	return c.Redirect("/accounts")
}

// --- Google OAuth consent flow -------------------------------------------

const googleOAuthCookie = "goauth_state"

func (a *App) googleRedirectURI() string {
	return strings.TrimRight(a.Cfg.BaseURL, "/") + "/oauth/google/callback"
}

// startGoogleConsent redirects the browser to Google's consent screen for the
// given account. State is bound to a HttpOnly cookie to prevent CSRF.
func (a *App) startGoogleConsent(c *fiber.Ctx, accountID int64) error {
	acc, err := database.GetAccount(a.DB, accountID)
	if err != nil {
		return err
	}
	if acc == nil {
		return fiber.ErrNotFound
	}
	sec, err := a.Worker.DecryptSecrets(acc)
	if err != nil {
		return err
	}
	if sec.ClientID == "" {
		a.setFlash(c, "error", "This account has no OAuth client ID; it cannot use the Google consent flow.")
		return c.Redirect("/accounts")
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	state := hex.EncodeToString(nonce)
	c.Cookie(&fiber.Cookie{
		Name:     googleOAuthCookie,
		Value:    state + "|" + strconv.FormatInt(accountID, 10),
		HTTPOnly: true,
		Secure:   a.Cfg.SecureCookies,
		SameSite: "Lax",
		Path:     "/",
		MaxAge:   600,
	})
	return c.Redirect(mailauth.GoogleAuthURL(sec.ClientID, a.googleRedirectURI(), state))
}

// HandleGoogleConnect (POST) restarts the consent flow for an existing account.
func (a *App) HandleGoogleConnect(c *fiber.Ctx) error {
	acc, err := a.accountFromParam(c)
	if err != nil {
		return err
	}
	return a.startGoogleConsent(c, acc.ID)
}

// HandleGoogleCallback finishes the consent flow: verifies state, exchanges
// the code for a refresh token, and stores it in the account's secrets.
func (a *App) HandleGoogleCallback(c *fiber.Ctx) error {
	defer c.Cookie(&fiber.Cookie{Name: googleOAuthCookie, Value: "", Path: "/", MaxAge: -1, HTTPOnly: true, SameSite: "Lax"})

	if errParam := c.Query("error"); errParam != "" {
		a.setFlash(c, "error", "Google authorization was denied: "+errParam)
		return c.Redirect("/accounts")
	}
	cookie := c.Cookies(googleOAuthCookie)
	state := c.Query("state")
	code := c.Query("code")
	parts := strings.SplitN(cookie, "|", 2)
	if cookie == "" || state == "" || code == "" || len(parts) != 2 || parts[0] != state {
		a.setFlash(c, "error", "OAuth state mismatch — please retry the Connect flow.")
		return c.Redirect("/accounts")
	}
	accountID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	acc, err := database.GetAccount(a.DB, accountID)
	if err != nil {
		return err
	}
	if acc == nil {
		return fiber.ErrNotFound
	}
	sec, err := a.Worker.DecryptSecrets(acc)
	if err != nil {
		return err
	}

	refreshToken, err := mailauth.GoogleExchangeCode(c.Context(), sec.ClientID, sec.ClientSecret, a.googleRedirectURI(), code)
	if err != nil {
		a.setFlash(c, "error", "Google token exchange failed: "+err.Error())
		return c.Redirect("/accounts")
	}
	sec.RefreshToken = refreshToken
	secretEnc, err := a.Worker.EncryptSecrets(sec)
	if err != nil {
		return err
	}
	if err := database.UpdateAccountSecret(a.DB, acc.ID, secretEnc); err != nil {
		return err
	}
	a.Worker.Auth.Invalidate(acc.ID)
	a.setFlash(c, "success", fmt.Sprintf("Google account %q connected. Use Test to verify.", acc.Name))
	return c.Redirect("/accounts")
}
