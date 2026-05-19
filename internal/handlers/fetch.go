package handlers

import (
	"fmt"
	"log"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	imapingest "github.com/annabellevibecodes/dmarcreporter/internal/imap"
)

func (a *App) HandleFetch(c *fiber.Ctx) error {
	if a.Cfg.IMAPHost == "" {
		a.setFlash(c, "error", "IMAP is not configured.")
		return c.Redirect("/")
	}

	audit.IMAPFetchStarted(a.Cfg.IMAPMailbox)

	count, err := imapingest.IngestAll(a.Cfg, a.DB)
	if err != nil {
		log.Printf("IMAP fetch error: %v", err)
		audit.IMAPFetchFailed(a.Cfg.IMAPMailbox)
		a.setFlash(c, "error", "IMAP fetch failed. Check server logs for details.")
		return c.Redirect("/reports")
	}

	audit.IMAPFetchCompleted(a.Cfg.IMAPMailbox, count)

	if count == 0 {
		a.setFlash(c, "info", "No new reports found — mailbox is empty or all messages are already imported.")
	} else {
		a.setFlash(c, "success", fmt.Sprintf("Imported %d new report(s) from mailbox.", count))
	}
	return c.Redirect("/reports")
}
