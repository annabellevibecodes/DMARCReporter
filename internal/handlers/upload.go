package handlers

import (
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/alerts"
	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/importer"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

const maxUploadSize = 10 * 1024 * 1024 // 10 MB

func (a *App) HandleUploadForm(c *fiber.Ctx) error {
	flashKind, flashMsg := getFlash(c)
	return c.Render("upload", fiber.Map{
		"Title":       "Upload — DMARC Reporter",
		"Theme":       getTheme(c),
		"ActivePage":  "upload",
		"IMAPEnabled": a.FetchEnabled(),
		"FlashKind":   flashKind,
		"FlashMsg":    flashMsg,
		"CSRFToken":   c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleUploadSubmit(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		return fiber.ErrBadRequest
	}

	files := form.File["report"]
	if len(files) == 0 {
		a.setFlash(c, "error", "No file selected.")
		return c.Redirect("/upload")
	}

	imported := 0
	duplicates := 0
	var lastID int64

	for _, fh := range files {
		if fh.Size > maxUploadSize {
			importer.RecordRejected(a.DB, database.IngestSourceUpload, fh.Filename, "exceeds the 10 MB limit")
			a.setFlash(c, "error", "File exceeds the 10 MB limit.")
			return c.Redirect("/upload")
		}

		f, err := fh.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(f, maxUploadSize+1))
		f.Close()
		if err != nil {
			return err
		}

		var atts []importer.Attachment
		isEML := strings.HasSuffix(strings.ToLower(fh.Filename), ".eml")
		if isEML {
			// Raw email: extract every DMARC / TLS-RPT attachment and the Date header.
			parts, _, perr := parser.ExtractEMLAttachments(data, nil)
			if perr != nil || len(parts) == 0 {
				if perr == nil {
					perr = fmt.Errorf("no DMARC or TLS-RPT report attachments found")
				}
				log.Printf("upload parse error for %q: %v", fh.Filename, perr)
				audit.ReportParseFailed(fh.Filename)
				_ = database.RecordIngestEvent(a.DB, database.IngestEvent{
					Source: database.IngestSourceUpload, Filename: fh.Filename,
					Kind: database.IngestKindUnknown, Status: database.IngestStatusParseError,
					Error: perr.Error(),
				})
				a.setFlash(c, "error", "Email file could not be parsed. No DMARC or TLS-RPT report attachments found.")
				return c.Redirect("/upload")
			}
			for _, p := range parts {
				atts = append(atts, importer.Attachment{
					Filename: p.Filename, Data: p.Data, ReceivedAt: p.ReceivedAt,
					// An uploaded .eml is still a mailed report, so its DKIM
					// signature is checked exactly as if we had fetched it.
					RawMessage: data,
				})
			}
		} else {
			atts = []importer.Attachment{{Filename: fh.Filename, Data: data}}
		}

		res, err := importer.SaveAttachments(a.DB, database.IngestSourceUpload, "", atts)
		if err != nil {
			return err
		}
		if res.Failed > 0 && res.Imported == 0 && res.Duplicates == 0 {
			if parser.IsTLSRPTFile(fh.Filename) {
				a.setFlash(c, "error", "File could not be parsed as an SMTP TLS report.")
			} else if isEML {
				a.setFlash(c, "error", "Email file could not be parsed. No DMARC report attachments found.")
			} else {
				a.setFlash(c, "error", "File could not be parsed as a DMARC report. Check the format and try again.")
			}
			return c.Redirect("/upload")
		}
		imported += res.Imported
		duplicates += res.Duplicates
		if res.LastReportID != 0 {
			lastID = res.LastReportID
		}
	}

	if imported > 0 {
		go alerts.Evaluate(a.DB, a.Cfg)
	}

	switch {
	case imported == 0 && duplicates > 0:
		a.setFlash(c, "warning", fmt.Sprintf("%d report(s) already imported — no new data.", duplicates))
		return c.Redirect("/reports")
	case imported == 1 && lastID != 0:
		return c.Redirect(fmt.Sprintf("/reports/%d", lastID))
	default:
		a.setFlash(c, "success", fmt.Sprintf("Imported %d report(s).", imported))
		return c.Redirect("/reports")
	}
}
