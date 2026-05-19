package handlers

import (
	"fmt"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/export"
)

var domainReExport = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

func (a *App) HandleExport(c *fiber.Ctx) error {
	format := c.Query("format")
	domain := c.Query("domain")

	if domain != "" && (len(domain) > 253 || !domainReExport.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	switch format {
	case "csv", "xlsx", "pdf", "docx":
	default:
		return fiber.ErrBadRequest
	}

	rd, err := export.Fetch(a.DB, domain)
	if err != nil {
		return err
	}

	scope := "all"
	if domain != "" {
		scope = domain
	}
	date := time.Now().UTC().Format("2006-01-02")
	filename := fmt.Sprintf("dmarc-report-%s-%s.%s", scope, date, format)
	c.Set("Content-Disposition", `attachment; filename="`+filename+`"`)

	switch format {
	case "csv":
		c.Set("Content-Type", "text/csv; charset=utf-8")
		return export.WriteCSV(c.Response().BodyWriter(), rd)
	case "xlsx":
		c.Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		return export.WriteXLSX(c.Response().BodyWriter(), rd)
	case "pdf":
		c.Set("Content-Type", "application/pdf")
		return export.WritePDF(c.Response().BodyWriter(), rd)
	case "docx":
		c.Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		return export.WriteDOCX(c.Response().BodyWriter(), rd)
	}
	return nil
}
