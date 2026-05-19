package imap

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/emersion/go-imap/v2/imapclient"
)

// Connect opens a TLS (or plain) IMAP connection and logs in.
// The caller must call client.Logout() when done.
func Connect(cfg config.Config) (*imapclient.Client, error) {
	addr := net.JoinHostPort(cfg.IMAPHost, cfg.IMAPPort)

	var (
		c   *imapclient.Client
		err error
	)
	opts := &imapclient.Options{}

	if cfg.IMAPTLS {
		audit.Debug("imap: dialing TLS to %s", addr)
		tlsCfg := &tls.Config{ServerName: cfg.IMAPHost}
		c, err = imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: tlsCfg})
	} else {
		audit.Debug("imap: dialing plaintext to %s", addr)
		c, err = imapclient.DialInsecure(addr, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("imap dial %s: %w", addr, err)
	}
	audit.Debug("imap: dial OK, logging in as %q", cfg.IMAPUser)

	if err := c.Login(cfg.IMAPUser, cfg.IMAPPass).Wait(); err != nil {
		c.Close()
		return nil, fmt.Errorf("imap login: %w", err)
	}
	audit.Debug("imap: login OK")

	// Ensure the processed mailbox exists.
	audit.Debug("imap: ensuring processed mailbox %q exists", cfg.IMAPProcessedMailbox)
	if err := ensureMailbox(c, cfg.IMAPProcessedMailbox); err != nil {
		c.Close()
		return nil, err
	}
	audit.Debug("imap: processed mailbox ready")

	return c, nil
}

// ensureMailbox creates the mailbox if it does not already exist.
func ensureMailbox(c *imapclient.Client, name string) error {
	// List to check existence.
	listCmd := c.List("", name, nil)
	mailboxes, err := listCmd.Collect()
	if err != nil {
		return fmt.Errorf("list mailbox %q: %w", name, err)
	}
	if len(mailboxes) > 0 {
		return nil // already exists
	}
	if err := c.Create(name, nil).Wait(); err != nil {
		return fmt.Errorf("create mailbox %q: %w", name, err)
	}
	return nil
}
