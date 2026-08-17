package imap

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-sasl"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
)

// ConnectOptions describes how to reach and authenticate one IMAP mailbox.
type ConnectOptions struct {
	Host     string
	Port     string
	TLS      bool
	Username string
	Password string      // used when SASL is nil (LOGIN)
	SASL     sasl.Client // used when set (e.g. XOAUTH2 for Gmail / O365)
}

// Connect opens a TLS (or plain) IMAP connection and authenticates.
// The caller must call client.Logout() when done.
func Connect(opt ConnectOptions) (*imapclient.Client, error) {
	addr := net.JoinHostPort(opt.Host, opt.Port)

	var (
		c   *imapclient.Client
		err error
	)
	if opt.TLS {
		audit.Debug("imap: dialing TLS to %s", addr)
		tlsCfg := &tls.Config{ServerName: opt.Host}
		c, err = imapclient.DialTLS(addr, &imapclient.Options{TLSConfig: tlsCfg})
	} else {
		audit.Debug("imap: dialing plaintext to %s", addr)
		c, err = imapclient.DialInsecure(addr, &imapclient.Options{})
	}
	if err != nil {
		return nil, fmt.Errorf("imap dial %s: %w", addr, err)
	}

	if opt.SASL != nil {
		audit.Debug("imap: dial OK, authenticating (SASL) as %q", opt.Username)
		if err := c.Authenticate(opt.SASL); err != nil {
			c.Close()
			return nil, fmt.Errorf("imap sasl auth: %w", err)
		}
	} else {
		audit.Debug("imap: dial OK, logging in as %q", opt.Username)
		if err := c.Login(opt.Username, opt.Password).Wait(); err != nil {
			c.Close()
			return nil, fmt.Errorf("imap login: %w", err)
		}
	}
	audit.Debug("imap: authenticated")
	return c, nil
}

// hierarchyDelimiter returns the server's mailbox hierarchy delimiter
// ('.' on Dovecot/Courier, '/' on Gmail and Office 365).
func hierarchyDelimiter(c *imapclient.Client) (rune, error) {
	mailboxes, err := c.List("", "INBOX", nil).Collect()
	if err != nil || len(mailboxes) == 0 {
		// Fall back to the root hierarchy request.
		mailboxes, err = c.List("", "", nil).Collect()
		if err != nil || len(mailboxes) == 0 {
			return 0, fmt.Errorf("list hierarchy delimiter: %w", err)
		}
	}
	return mailboxes[0].Delim, nil
}

// ResolveProcessedMailbox returns the mailbox processed messages move to and
// creates it if missing. When configured is empty the name is derived from the
// source mailbox and the server's hierarchy delimiter (e.g. INBOX.Processed on
// Dovecot, INBOX/Processed on Gmail and Office 365).
func ResolveProcessedMailbox(c *imapclient.Client, srcMailbox, configured string) (string, error) {
	name := configured
	if name == "" {
		delim, err := hierarchyDelimiter(c)
		if err != nil {
			return "", err
		}
		if delim == 0 {
			// Flat namespace: fall back to a top-level mailbox.
			name = "Processed"
		} else {
			name = srcMailbox + string(delim) + "Processed"
		}
	}
	audit.Debug("imap: ensuring processed mailbox %q exists", name)
	if err := ensureMailbox(c, name); err != nil {
		return "", err
	}
	return name, nil
}

// ensureMailbox creates the mailbox if it does not already exist.
func ensureMailbox(c *imapclient.Client, name string) error {
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
