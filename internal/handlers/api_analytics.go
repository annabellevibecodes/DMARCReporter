package handlers

import (
	"net"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

// windowPayload describes the window an API response covers.
type windowPayload struct {
	From  int64  `json:"from"`
	To    int64  `json:"to"`
	Label string `json:"label"`
	// Previous is set when compare=1 produced a comparison window.
	Previous *struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"previous,omitempty"`
}

func windowFor(f database.StatsFilter, label string) windowPayload {
	w := windowPayload{From: f.From, To: f.To, Label: label}
	if f.Compare {
		if prev, ok := f.PreviousWindow(); ok {
			w.Previous = &struct {
				From int64 `json:"from"`
				To   int64 `json:"to"`
			}{prev.From, prev.To}
		}
	}
	return w
}

// HandleAPIOverview serves C1–C8 (+ new-source count) for the window, with the
// previous window and deltas when compare=1.
func (a *App) HandleAPIOverview(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	cmp, err := database.WithComparison(f, func(sf database.StatsFilter) (*overviewMetrics, error) {
		return a.computeOverview(sf)
	})
	if err != nil {
		return err
	}
	var prev *overviewMetrics
	if cmp.Previous != nil {
		prev = *cmp.Previous
	}
	resp := fiber.Map{
		"window":      windowFor(f, c.Query("period")),
		"current":     cmp.Current,
		"previous":    prev,
		"delta":       computeDelta(cmp.Current, prev),
		"new_sources": cmp.Current.NewSourceList,
		"health":      nil,
		"open_alerts": 0,
	}
	a.decorateOverview(c, f, resp)
	return c.JSON(resp)
}

// decorateOverview is a hook for later phases (health score, open alerts).
func (a *App) decorateOverview(c *fiber.Ctx, f database.StatsFilter, resp fiber.Map) {
	if overviewExtras != nil {
		overviewExtras(a, f, resp)
	}
}

// overviewExtras is set by later phases to add health / alert data.
var overviewExtras func(a *App, f database.StatsFilter, resp fiber.Map)

// HandleAPIAuthMatrix serves the C5 2×2 matrix (both_pass added to the old
// failure-modes shape).
func (a *App) HandleAPIAuthMatrix(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	cmp, err := database.WithComparison(f, func(sf database.StatsFilter) (matrixPayload, error) {
		m, err := database.GetAuthMatrix(a.DB, sf)
		if err != nil {
			return matrixPayload{}, err
		}
		return toMatrixPayload(m), nil
	})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window":   windowFor(f, c.Query("period")),
		"current":  cmp.Current,
		"previous": cmp.Previous,
	})
}

// sourceQueryFromCtx parses the S1 table query parameters.
func sourceQueryFromCtx(c *fiber.Ctx) database.SourceQuery {
	q := database.SourceQuery{
		Sort:    c.Query("sort", "messages"),
		Dir:     c.Query("dir", "desc"),
		Pattern: c.Query("pattern"),
		Matrix:  c.Query("matrix"),
		NewOnly: c.Query("new") == "1",
		Search:  strings.TrimSpace(c.Query("q")),
	}
	if q.Dir != "asc" {
		q.Dir = "desc"
	}
	valid := false
	for _, p := range ipinfo.Patterns {
		if p == q.Pattern {
			valid = true
		}
	}
	if !valid {
		q.Pattern = ""
	}
	switch q.Matrix {
	case "both", "dkim", "spf", "neither":
	default:
		q.Matrix = ""
	}
	if len(q.Search) > 100 {
		q.Search = q.Search[:100]
	}
	q.Min, _ = strconv.Atoi(c.Query("min", "1"))
	if q.Min < 1 {
		q.Min = 1
	}
	if q.Min > 1_000_000 {
		q.Min = 1_000_000
	}
	q.Limit, _ = strconv.Atoi(c.Query("limit", "100"))
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	page, _ := strconv.Atoi(c.Query("page", "1"))
	if page < 1 {
		page = 1
	}
	q.Offset = (page - 1) * q.Limit
	return q
}

// HandleAPISources serves the S1 table.
func (a *App) HandleAPISources(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	q := sourceQueryFromCtx(c)
	rows, total, err := database.GetSourceInventory(a.DB, f, q, a.patternThresholds())
	if err != nil {
		return err
	}
	if rows == nil {
		rows = []database.SourceInventoryRow{}
	}
	return c.JSON(fiber.Map{
		"window":  windowFor(f, c.Query("period")),
		"total":   total,
		"limit":   q.Limit,
		"offset":  q.Offset,
		"sources": rows,
	})
}

// HandleAPISourceDetail serves /api/sources/:ip.
func (a *App) HandleAPISourceDetail(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if net.ParseIP(ip) == nil {
		return fiber.ErrBadRequest
	}
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	d, err := database.GetSourceDetail(a.DB, ip, f, a.patternThresholds())
	if err != nil {
		return err
	}
	if d == nil {
		return fiber.ErrNotFound
	}
	return c.JSON(d)
}

// HandleAPINewSources serves S2.
func (a *App) HandleAPINewSources(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	limit, _ := strconv.Atoi(c.Query("limit", "100"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := database.GetNewSources(a.DB, f, a.patternThresholds(), limit)
	if err != nil {
		return err
	}
	if rows == nil {
		rows = []database.SourceInventoryRow{}
	}
	return c.JSON(fiber.Map{
		"window":  windowFor(f, c.Query("period")),
		"sources": rows,
	})
}

// HandleAPISpoof serves S4.
func (a *App) HandleAPISpoof(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	limit, _ := strconv.Atoi(c.Query("limit", "20"))
	sv, err := database.GetSpoofVolume(a.DB, f, limit)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window":          windowFor(f, c.Query("period")),
		"resolved":        sv.Resolved,
		"in_spf":          sv.InSPF,
		"not_in_spf":      sv.NotInSPF,
		"unresolved":      sv.Unresolved,
		"total":           sv.Total,
		"not_in_spf_pct":  sv.NotInSPFShare(),
		"domains_pending": sv.Domains,
		"sources":         sv.Sources,
		"status":          spoofStatus(sv),
	})
}

func spoofStatus(sv *database.SpoofVolume) string {
	switch {
	case sv.Total == 0:
		return "no_failures"
	case !sv.Resolved:
		return "not_resolved_yet"
	case sv.Unresolved > 0:
		return "partial"
	}
	return "ok"
}

// HandleAPILabelUpsert handles POST /api/labels/:ip (form-encoded, CSRF
// protected). With a `redirect` field it redirects back (used by the inline
// forms); otherwise it returns the stored label as JSON.
func (a *App) HandleAPILabelUpsert(c *fiber.Ctx) error {
	ip := c.Params("ip")
	if net.ParseIP(ip) == nil {
		return fiber.ErrBadRequest
	}
	l := database.IPLabel{
		IP:             ip,
		Label:          strings.TrimSpace(c.FormValue("label")),
		Classification: strings.TrimSpace(c.FormValue("classification")),
		Notes:          strings.TrimSpace(c.FormValue("notes")),
	}
	if !database.ValidClassification(l.Classification) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid classification")
	}
	if len(l.Label) > 120 || len(l.Notes) > 2000 {
		return fiber.NewError(fiber.StatusBadRequest, "label or notes too long")
	}
	if err := database.UpsertIPLabel(a.DB, l); err != nil {
		return err
	}
	if redirect := c.FormValue("redirect"); safeRedirect(redirect) {
		a.setFlash(c, "success", "Label saved for "+ip+".")
		return c.Redirect(redirect, fiber.StatusSeeOther)
	}
	stored, err := database.GetIPLabel(a.DB, ip)
	if err != nil {
		return err
	}
	if stored == nil {
		return c.JSON(fiber.Map{"ip": ip, "label": "", "classification": "", "notes": ""})
	}
	return c.JSON(stored)
}
