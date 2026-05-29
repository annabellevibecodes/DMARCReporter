package handlers

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

func (a *App) HandleReportsList(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	pageSize := 25
	domain := c.Query("domain")
	orgName := c.Query("org_name")
	reportID := c.Query("report_id")
	dateFromStr := c.Query("date_from")
	dateToStr := c.Query("date_to")

	sortBy := c.Query("sort", "date_begin")
	sortDir := c.Query("dir", "desc")
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}

	filter := database.ReportFilter{
		Domain:   domain,
		OrgName:  orgName,
		ReportID: reportID,
		Page:     page,
		PageSize: pageSize,
		SortBy:   sortBy,
		SortDir:  sortDir,
	}
	if dateFromStr != "" {
		if t, err := time.Parse("2006-01-02", dateFromStr); err == nil {
			filter.DateFrom = t
		}
	}
	if dateToStr != "" {
		if t, err := time.Parse("2006-01-02", dateToStr); err == nil {
			filter.DateTo = t.Add(24*time.Hour - time.Second)
		}
	}

	reports, total, err := database.ListReports(a.DB, filter)
	if err != nil {
		return err
	}

	reportDomains, err := database.ListReportDomains(a.DB)
	if err != nil {
		return err
	}

	reportOrgs, err := database.ListReportOrgs(a.DB)
	if err != nil {
		return err
	}

	totalPages := (total + pageSize - 1) / pageSize
	flashKind, flashMsg := getFlash(c)
	return c.Render("reports", fiber.Map{
		"Title":         "Reports — DMARC Reporter",
		"Theme":         getTheme(c),
		"ActivePage":    "reports",
		"Reports":       reports,
		"Page":          page,
		"TotalPages":    totalPages,
		"PageNums":      pageWindow(page, totalPages),
		"Total":         total,
		"Domain":        domain,
		"OrgName":       orgName,
		"ReportID":      reportID,
		"DateFrom":      dateFromStr,
		"DateTo":        dateToStr,
		"ReportDomains": reportDomains,
		"ReportOrgs":    reportOrgs,
		"SortBy":        sortBy,
		"SortDir":       sortDir,
		"IMAPEnabled":   a.Cfg.IMAPHost != "",
		"FlashKind":     flashKind,
		"FlashMsg":      flashMsg,
		"CSRFToken":     c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleReportXML(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}
	xmlData, err := database.GetReportXML(a.DB, id)
	if err != nil {
		return err
	}
	if xmlData == "" {
		return fiber.ErrNotFound
	}
	c.Set("Content-Type", "application/xml; charset=utf-8")
	c.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%d.xml"`, id))
	return c.SendString(xmlData)
}

func (a *App) HandleReportDetail(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil {
		return fiber.ErrBadRequest
	}

	report, err := database.GetReport(a.DB, id)
	if err != nil {
		return err
	}
	if report == nil {
		return fiber.ErrNotFound
	}

	records, err := database.GetReportRecords(a.DB, id)
	if err != nil {
		return err
	}

	xmlData, err := database.GetReportXML(a.DB, id)
	if err != nil {
		return err
	}

	// Bundle records where header_from and envelope_from differ (ignoring empty/null-sender).
	type AlignmentMismatch struct {
		HeaderFrom   string
		EnvelopeFrom string
		Count        int
	}
	type mismatchKey struct{ h, e string }
	mismatchMap := map[mismatchKey]*AlignmentMismatch{}
	for _, r := range records {
		if r.EnvelopeFrom == "" || r.EnvelopeFrom == "<>" || r.EnvelopeFrom == r.HeaderFrom {
			continue
		}
		k := mismatchKey{r.HeaderFrom, r.EnvelopeFrom}
		if _, ok := mismatchMap[k]; !ok {
			mismatchMap[k] = &AlignmentMismatch{HeaderFrom: r.HeaderFrom, EnvelopeFrom: r.EnvelopeFrom}
		}
		mismatchMap[k].Count += r.Count
	}
	var mismatches []AlignmentMismatch
	for _, m := range mismatchMap {
		mismatches = append(mismatches, *m)
	}

	dkimByRecord, err := database.GetReportDKIMResults(a.DB, id)
	if err != nil {
		return err
	}

	return c.Render("report_detail", fiber.Map{
		"Title":        "Report " + report.ReportID + " — DMARC Reporter",
		"Theme":        getTheme(c),
		"ActivePage":   "reports",
		"Report":       report,
		"Records":      records,
		"HasXML":       xmlData != "",
		"Mismatches":   mismatches,
		"DKIMByRecord": dkimByRecord,
		"IMAPEnabled":  a.Cfg.IMAPHost != "",
		"CSRFToken":    c.Locals("csrf"),
	}, "layouts/base")
}
