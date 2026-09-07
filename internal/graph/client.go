// Package graph fetches DMARC/TLS-RPT report attachments from an Office 365
// mailbox over the Microsoft Graph REST API, as an alternative to IMAP.
package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
)

const baseURL = "https://graph.microsoft.com/v1.0"

var httpClient = &http.Client{Timeout: 60 * time.Second}

// graphError is the error envelope Graph returns on non-2xx responses.
type graphError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// doJSON issues an authenticated Graph API request and decodes a JSON
// response into out (which may be nil for responses without a body, e.g.
// PATCH). Retries once on HTTP 429, honoring Retry-After (capped at 30s).
func doJSON(ctx context.Context, token, method, url string, body io.Reader, out any) error {
	resp, err := doRequest(ctx, token, method, url, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		wait := 5 * time.Second
		if s := resp.Header.Get("Retry-After"); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				wait = time.Duration(n) * time.Second
				if wait > 30*time.Second {
					wait = 30 * time.Second
				}
			}
		}
		resp.Body.Close()
		audit.Debug("graph: throttled (429), retrying in %s", wait)
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
		resp, err = doRequest(ctx, token, method, url, body)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return fmt.Errorf("graph: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var ge graphError
		if json.Unmarshal(data, &ge) == nil && ge.Error.Message != "" {
			return fmt.Errorf("graph: %s %s: HTTP %d: %s: %s", method, url, resp.StatusCode, ge.Error.Code, ge.Error.Message)
		}
		return fmt.Errorf("graph: %s %s: HTTP %d", method, url, resp.StatusCode)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("graph: decode response from %s %s: %w", method, url, err)
	}
	return nil
}

func doRequest(ctx context.Context, token, method, url string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("graph: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("graph: %s %s: %w", method, url, err)
	}
	return resp, nil
}

// getRaw fetches a URL and returns the raw response body, used for
// downloading large attachment content via the $value endpoint.
func getRaw(ctx context.Context, token, url string) ([]byte, error) {
	resp, err := doRequest(ctx, token, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, fmt.Errorf("graph: read %s: %w", url, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("graph: GET %s: HTTP %d", url, resp.StatusCode)
	}
	return data, nil
}
