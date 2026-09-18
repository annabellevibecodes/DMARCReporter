package handlers

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

const sourcesPageSize = 100

// matrixLabel is the human name of an authentication-matrix cell.
func matrixLabel(m string) string {
	switch m {
	case "both":
		return "both aligned"
	case "dkim":
		return "DKIM only"
	case "spf":
		return "SPF only"
	case "neither":
		return "neither"
	}
	return m
}

func (a *App) HandleSourcesList(c *fiber.Ctx) error {
	envelopeFrom := strings.TrimSpace(c.Query("envelope_from"))
	disposition := c.Query("disposition")
	if disposition != "quarantine" && disposition != "reject" {
		disposition = ""
	}
	country := strings.TrimSpace(c.Query("country"))
	sourceIP := strings.TrimSpace(c.Query("ip"))
	// Policy domain (r.domain): the matrix boxes on a domain detail page link
	// here with it, so the page must honour it or the scope is silently lost.
	domain := strings.TrimSpace(c.Query("domain"))
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	period := c.Query("period", "1y")
	from, to, periodLabel := parsePeriod(period)

	f := database.StatsFilter{EnvelopeFrom: envelopeFrom, Domain: domain, From: from, To: to}
	q := sourceQueryFromCtx(c)
	q.Limit = sourcesPageSize
	q.Offset = (page - 1) * sourcesPageSize
	q.Sort = c.Query("sort", "")
	q.Dir = c.Query("dir", "desc")
	if q.Dir != "asc" {
		q.Dir = "desc"
	}
	if q.Sort == "fail_rate" {
		// Legacy default: fail rate descending == pass rate ascending.
		q.Sort = "pass_rate"
		if q.Dir == "desc" {
			q.Dir = "asc"
		} else {
			q.Dir = "desc"
		}
	}
	q.Disposition = disposition
	q.Country = country
	if sourceIP != "" {
		q.Search = sourceIP
	}

	sources, total, err := database.GetSourceInventory(a.DB, f, q, a.patternThresholds())
	if err != nil {
		return err
	}
	envelopeFromDomains, err := database.ListEnvelopeFromDomains(a.DB)
	if err != nil {
		return err
	}

	// Query string shared by the sort / page / filter links.
	base := url.Values{}
	base.Set("period", period)
	if q.Min > 1 {
		base.Set("min", strconv.Itoa(q.Min))
	}
	if domain != "" {
		base.Set("domain", domain)
	}
	if envelopeFrom != "" {
		base.Set("envelope_from", envelopeFrom)
	}
	if sourceIP != "" {
		base.Set("ip", sourceIP)
	}
	if disposition != "" {
		base.Set("disposition", disposition)
	}
	if country != "" {
		base.Set("country", country)
	}
	if q.Pattern != "" {
		base.Set("pattern", q.Pattern)
	}
	if q.Matrix != "" {
		base.Set("matrix", q.Matrix)
	}
	if q.NewOnly {
		base.Set("new", "1")
	}
	sortQ := url.Values{}
	if c.Query("sort") != "" {
		sortQ.Set("sort", c.Query("sort"))
		sortQ.Set("dir", c.Query("dir", "desc"))
	}

	// Every filter this page accepts gets a control, so a filter arriving by
	// link (from a dashboard drill-down) can be seen and changed in place.
	patternOpts := [][2]string{{"", "All patterns"}}
	for _, p := range ipinfo.Patterns {
		patternOpts = append(patternOpts, [2]string{p, ipinfo.PatternLabel(p)})
	}
	patternChips := chipRow("/sources", base, "pattern", q.Pattern, patternOpts)
	matrixChips := chipRow("/sources", base, "matrix", q.Matrix, [][2]string{
		{"", "All results"},
		{"both", "Both aligned"},
		{"dkim", "DKIM only"},
		{"spf", "SPF only"},
		{"neither", "Neither"},
	})
	dispositionChips := chipRow("/sources", base, "disposition", disposition, [][2]string{
		{"", "Any disposition"},
		{"quarantine", "Quarantine"},
		{"reject", "Reject"},
	})

	// "New in period" needs a bounded window to mean anything (S2).
	newChip := filterChip{Label: "New in period", Active: q.NewOnly}
	switch {
	case from <= 0:
		newChip.Disabled = true
		newChip.Title = "Pick a bounded period to list sources first seen inside it"
	case q.NewOnly:
		newChip.Href = chipHref("/sources", base, "new", "")
	default:
		newChip.Href = chipHref("/sources", base, "new", "1")
	}

	var active []activeFilter
	addActive := func(key, value, label string) {
		if value == "" {
			return
		}
		active = append(active, activeFilter{Label: label, Href: chipHref("/sources", base, key, "")})
	}
	addActive("domain", domain, "domain: "+domain)
	addActive("envelope_from", envelopeFrom, "MAIL FROM: "+envelopeFrom)
	addActive("ip", sourceIP, "search: "+sourceIP)
	addActive("country", country, "country: "+country)
	addActive("disposition", disposition, "disposition: "+disposition)
	addActive("matrix", q.Matrix, "matrix: "+matrixLabel(q.Matrix))
	addActive("pattern", q.Pattern, "pattern: "+ipinfo.PatternLabel(q.Pattern))
	if q.NewOnly {
		addActive("new", "1", "new in period")
	}
	if q.Min > 1 {
		addActive("min", strconv.Itoa(q.Min), fmt.Sprintf("min %d messages", q.Min))
	}

	totalPages := (total + sourcesPageSize - 1) / sourcesPageSize
	flashKind, flashMsg := getFlash(c)
	return c.Render("sources", fiber.Map{
		"PageNums":            pageWindow(page, totalPages),
		"Title":               "Sources — DMARC Reporter",
		"Theme":               getTheme(c),
		"ActivePage":          "sources",
		"Sources":             sources,
		"EnvelopeFrom":        envelopeFrom,
		"EnvelopeFromDomains": envelopeFromDomains,
		"Disposition":         disposition,
		"Country":             country,
		"SourceIP":            sourceIP,
		"Page":                page,
		"TotalPages":          totalPages,
		"Total":               total,
		"PeriodOptions":       periodOptions,
		"SelectedPeriod":      period,
		"PeriodLabel":         periodLabel,
		"MinMessages":         q.Min,
		"SortBy":              c.Query("sort", ""),
		"SortDir":             c.Query("dir", "desc"),
		"Pattern":             q.Pattern,
		"PatternChips":        patternChips,
		"MatrixChips":         matrixChips,
		"DispositionChips":    dispositionChips,
		"NewChip":             newChip,
		"ActiveFilters":       active,
		"ClearAllHref":        template.URL("/sources?period=" + url.QueryEscape(period)),
		"Domain":              domain,
		"Matrix":              q.Matrix,
		"MatrixLabel":         matrixLabel(q.Matrix),
		"NewOnly":             q.NewOnly,
		"BaseQuery":           template.URL(base.Encode()),
		"SortQuery":           template.URL(sortQ.Encode()),
		"Classifications":     database.Classifications,
		"CurrentPath":         currentPath(c),
		"IMAPEnabled":         a.FetchEnabled(),
		"FlashKind":           flashKind,
		"FlashMsg":            flashMsg,
		"CSRFToken":           c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleSourceDetail(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if net.ParseIP(ip) == nil {
		return fiber.ErrBadRequest
	}

	period := c.Query("period", "1y")
	from, to, periodLabel := parsePeriod(period)
	f := database.StatsFilter{From: from, To: to}

	records, err := database.GetSourceRecords(a.DB, ip, from, 100)
	if err != nil {
		return err
	}

	agg, err := database.GetSourceAggStats(a.DB, ip, from)
	if err != nil {
		return err
	}

	detail, err := database.GetSourceDetail(a.DB, ip, f, a.patternThresholds())
	if err != nil {
		return err
	}
	var timelineJSON []byte
	if detail != nil {
		type trendPayload struct {
			Labels []string `json:"labels"`
			Passed []int64  `json:"passed"`
			Failed []int64  `json:"failed"`
		}
		td := trendPayload{}
		for _, pt := range detail.Timeline {
			td.Labels = append(td.Labels, pt.Week)
			td.Passed = append(td.Passed, pt.Passed)
			td.Failed = append(td.Failed, pt.Failed)
		}
		timelineJSON, _ = json.Marshal(td)
	}

	label, err := database.GetIPLabel(a.DB, ip)
	if err != nil {
		return err
	}
	if label == nil {
		label = &database.IPLabel{IP: ip}
	}

	// Resolve rDNS + WHOIS (served from cache; live lookup on first visit).
	ipInfo, _ := ipinfo.Get(a.DB, ip)

	flashKind, flashMsg := getFlash(c)
	return c.Render("source_detail", fiber.Map{
		"Title":           ip + " — DMARC Reporter",
		"Theme":           getTheme(c),
		"ActivePage":      "sources",
		"IP":              ip,
		"IPInfo":          ipInfo,
		"Records":         records,
		"TotalMessages":   agg.TotalMessages,
		"TotalPassed":     agg.Passed,
		"TotalFailed":     agg.Failed,
		"PassRate":        agg.PassRate,
		"Detail":          detail,
		"TimelineData":    template.JS(timelineJSON),
		"Label":           label,
		"Classifications": database.Classifications,
		"PeriodOptions":   periodOptions,
		"SelectedPeriod":  period,
		"PeriodLabel":     periodLabel,
		"CurrentPath":     currentPath(c),
		"IMAPEnabled":     a.FetchEnabled(),
		"FlashKind":       flashKind,
		"FlashMsg":        flashMsg,
		"CSRFToken":       c.Locals("csrf"),
	}, "layouts/base")
}
