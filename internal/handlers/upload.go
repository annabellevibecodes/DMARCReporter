package handlers

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/models"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

const maxUploadSize = 10 * 1024 * 1024 // 10 MB

func (a *App) HandleUploadForm(c *fiber.Ctx) error {
	flashKind, flashMsg := getFlash(c)
	return c.Render("upload", fiber.Map{
		"Title":       "Upload — DMARC Reporter",
		"Theme":       getTheme(c),
		"ActivePage":  "upload",
		"IMAPEnabled": a.Cfg.IMAPHost != "",
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
			a.setFlash(c, "error", "File exceeds the 10 MB limit.")
			return c.Redirect("/upload")
		}

		f, err := fh.Open()
		if err != nil {
			return err
		}
		defer f.Close()

		var feedbacks []*models.Feedback
		var filenames []string
		var rawXMLs [][]byte

		if strings.HasSuffix(strings.ToLower(fh.Filename), ".eml") {
			feedbacks, filenames, rawXMLs, err = parser.ParseEML(f)
			if err != nil {
				log.Printf("upload parse error for %q: %v", fh.Filename, err)
				audit.ReportParseFailed(fh.Filename)
				a.setFlash(c, "error", "Email file could not be parsed. No DMARC report attachments found.")
				return c.Redirect("/upload")
			}
		} else {
			fb, rawXML, parseErr := parser.Parse(fh.Filename, f)
			if parseErr != nil {
				log.Printf("upload parse error for %q: %v", fh.Filename, parseErr)
				audit.ReportParseFailed(fh.Filename)
				a.setFlash(c, "error", "File could not be parsed as a DMARC report. Check the format and try again.")
				return c.Redirect("/upload")
			}
			feedbacks = []*models.Feedback{fb}
			filenames = []string{fh.Filename}
			rawXMLs = [][]byte{rawXML}
		}

		for i, fb := range feedbacks {
			filename := filenames[i]
			id, err := database.SaveReport(a.DB, fb, filename, rawXMLs[i])
			if err != nil {
				if errors.Is(err, database.ErrDuplicate) {
					audit.ReportDuplicate(filename, fb.ReportMetadata.OrgName, fb.ReportMetadata.ReportID)
					duplicates++
					continue
				}
				return err
			}
			audit.ReportImported(filename,
				fb.ReportMetadata.OrgName,
				fb.PolicyPublished.Domain,
				fb.ReportMetadata.ReportID,
				len(fb.Records),
			)
			imported++
			lastID = id
		}
	}

	switch {
	case imported == 0 && duplicates > 0:
		a.setFlash(c, "warning", fmt.Sprintf("%d report(s) already imported — no new data.", duplicates))
		return c.Redirect("/reports")
	case imported == 1:
		return c.Redirect(fmt.Sprintf("/reports/%d", lastID))
	default:
		a.setFlash(c, "success", fmt.Sprintf("Imported %d report(s).", imported))
		return c.Redirect("/reports")
	}
}
