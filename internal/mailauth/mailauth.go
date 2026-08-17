// Package mailauth provides OAuth2 access tokens and the SASL XOAUTH2
// mechanism used to authenticate IMAP connections to Gmail and Office 365.
package mailauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

const (
	googleTokenURL = "https://oauth2.googleapis.com/token"
	googleAuthURL  = "https://accounts.google.com/o/oauth2/v2/auth"
	// GoogleScope grants full IMAP access; Gmail's IMAP XOAUTH2 requires it.
	GoogleScope = "https://mail.google.com/"

	msftTokenURLFmt = "https://login.microsoftonline.com/%s/oauth2/v2.0/token"
	// msftScope is the resource scope for IMAP client-credential tokens.
	msftScope = "https://outlook.office365.com/.default"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// xoauth2Client implements the SASL XOAUTH2 mechanism (used by both Gmail and
// Office 365). The initial response carries the user and bearer token; any
// server challenge indicates an error payload which we acknowledge with an
// empty response so the server returns a tagged failure.
type xoauth2Client struct {
	username, token string
}

// NewXOAUTH2Client returns a SASL client for the XOAUTH2 mechanism.
func NewXOAUTH2Client(username, token string) sasl.Client {
	return &xoauth2Client{username: username, token: token}
}

func (c *xoauth2Client) Start() (string, []byte, error) {
	ir := []byte("user=" + c.username + "\x01auth=Bearer " + c.token + "\x01\x01")
	return "XOAUTH2", ir, nil
}

func (c *xoauth2Client) Next(challenge []byte) ([]byte, error) {
	// The server sent a base64 JSON error blob; reply with an empty line to
	// receive the final NO. Surface the blob for diagnostics.
	return []byte{}, fmt.Errorf("xoauth2 rejected: %s", string(challenge))
}

type cachedToken struct {
	token  string
	expiry time.Time
}

// Manager fetches and caches OAuth2 access tokens per account.
type Manager struct {
	mu    sync.Mutex
	cache map[int64]cachedToken
}

func NewManager() *Manager {
	return &Manager{cache: make(map[int64]cachedToken)}
}

// Invalidate drops any cached token for the account (e.g. after secrets change).
func (m *Manager) Invalidate(accountID int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cache, accountID)
}

// AccessToken returns a valid access token for an OAuth-authenticated account,
// using the cache when the token has more than a minute of life left.
func (m *Manager) AccessToken(ctx context.Context, acc *database.Account, sec *database.AccountSecrets) (string, error) {
	m.mu.Lock()
	if c, ok := m.cache[acc.ID]; ok && time.Until(c.expiry) > time.Minute {
		m.mu.Unlock()
		return c.token, nil
	}
	m.mu.Unlock()

	var (
		token     string
		expiresIn int
		err       error
	)
	switch acc.AuthType {
	case database.AuthOAuthRefresh:
		token, expiresIn, err = refreshTokenGrant(ctx, sec.ClientID, sec.ClientSecret, sec.RefreshToken)
	case database.AuthOAuthClient:
		token, expiresIn, err = clientCredentialsGrant(ctx, sec.Tenant, sec.ClientID, sec.ClientSecret)
	default:
		return "", fmt.Errorf("account %q does not use OAuth (auth_type=%s)", acc.Name, acc.AuthType)
	}
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	m.cache[acc.ID] = cachedToken{token: token, expiry: time.Now().Add(time.Duration(expiresIn) * time.Second)}
	m.mu.Unlock()
	return token, nil
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func postTokenForm(ctx context.Context, endpoint string, form url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("token endpoint returned HTTP %d with unparseable body", resp.StatusCode)
	}
	if tr.Error != "" {
		return nil, fmt.Errorf("token endpoint error: %s: %s", tr.Error, tr.ErrorDescription)
	}
	if tr.AccessToken == "" && tr.RefreshToken == "" {
		return nil, fmt.Errorf("token endpoint returned HTTP %d without a token", resp.StatusCode)
	}
	return &tr, nil
}

// refreshTokenGrant exchanges a Google refresh token for an access token.
func refreshTokenGrant(ctx context.Context, clientID, clientSecret, refreshToken string) (string, int, error) {
	tr, err := postTokenForm(ctx, googleTokenURL, url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {refreshToken},
	})
	if err != nil {
		return "", 0, fmt.Errorf("google token refresh: %w", err)
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}

// clientCredentialsGrant obtains an app-only access token from Entra ID for
// Office 365 IMAP (requires the IMAP.AccessAsApp application permission and
// mailbox access granted to the service principal).
func clientCredentialsGrant(ctx context.Context, tenant, clientID, clientSecret string) (string, int, error) {
	if tenant == "" {
		return "", 0, fmt.Errorf("o365 account is missing the tenant ID")
	}
	tr, err := postTokenForm(ctx, fmt.Sprintf(msftTokenURLFmt, url.PathEscape(tenant)), url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {msftScope},
	})
	if err != nil {
		return "", 0, fmt.Errorf("o365 token: %w", err)
	}
	return tr.AccessToken, tr.ExpiresIn, nil
}

// GoogleAuthURL builds the consent URL for the one-time Gmail authorization
// flow. access_type=offline + prompt=consent ensure a refresh token is issued.
func GoogleAuthURL(clientID, redirectURI, state string) string {
	q := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {GoogleScope},
		"access_type":   {"offline"},
		"prompt":        {"consent"},
		"state":         {state},
	}
	return googleAuthURL + "?" + q.Encode()
}

// GoogleExchangeCode swaps an authorization code for a refresh token.
func GoogleExchangeCode(ctx context.Context, clientID, clientSecret, redirectURI, code string) (refreshToken string, err error) {
	tr, err := postTokenForm(ctx, googleTokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
		"code":          {code},
	})
	if err != nil {
		return "", fmt.Errorf("google code exchange: %w", err)
	}
	if tr.RefreshToken == "" {
		return "", fmt.Errorf("google did not return a refresh token — remove the app's prior grant at myaccount.google.com/permissions and retry")
	}
	return tr.RefreshToken, nil
}
