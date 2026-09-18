package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// apiStatsFilter builds a StatsFilter from the query parameters shared by all
// API endpoints: period (same values as the UI selector), ef (envelope_from),
// domain, compare=1 (also compute the preceding window), and the legacy days
// parameter (used when period is absent).
func apiStatsFilter(c *fiber.Ctx) (database.StatsFilter, error) {
	f := database.StatsFilter{
		EnvelopeFrom: c.Query("ef"),
		Compare:      c.Query("compare") == "1",
	}
	if domain := c.Query("domain"); domain != "" {
		if len(domain) > 253 || !domainRe.MatchString(domain) {
			return f, fiber.ErrBadRequest
		}
		f.Domain = domain
	}
	if period := c.Query("period"); period != "" {
		f.From, f.To, _ = parsePeriod(period)
		return f, nil
	}
	days, _ := strconv.Atoi(c.Query("days", "90"))
	if days <= 0 || days > 365*5 {
		days = 90
	}
	f.From = time.Now().UTC().AddDate(0, 0, -days).Unix()
	return f, nil
}

type trendResponse struct {
	Labels []string `json:"labels"`
	Passed []int64  `json:"passed"`
	Failed []int64  `json:"failed"`
}

func trendToResponse(trend []database.TrendPoint) trendResponse {
	resp := trendResponse{}
	for _, pt := range trend {
		resp.Labels = append(resp.Labels, pt.Week)
		resp.Passed = append(resp.Passed, pt.Passed)
		resp.Failed = append(resp.Failed, pt.Failed)
	}
	return resp
}

func (a *App) HandleAPIStats(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	daily := database.TrendDaily(f.From)
	trend, err := database.GetTrendData(a.DB, f, daily)
	if err != nil {
		return err
	}
	trend = database.FillTrendGaps(trend, f.From, f.To, daily)
	return c.JSON(trendToResponse(trend))
}

func (a *App) HandleAPIFailureModes(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	fm, err := database.GetFailureModeBreakdown(a.DB, f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"both_pass":      fm.BothPass,
		"dkim_only_pass": fm.DKIMOnlyPass,
		"spf_only_pass":  fm.SPFOnlyPass,
		"both_fail":      fm.BothFail,
		"total":          fm.Total(),
	})
}

func (a *App) HandleAPIDomainTrend(c *fiber.Ctx) error {
	domain := c.Query("domain")
	if domain == "" || len(domain) > 253 || !domainRe.MatchString(domain) {
		return fiber.ErrBadRequest
	}
	days, _ := strconv.Atoi(c.Query("days", "90"))
	if days <= 0 || days > 365 {
		days = 90
	}

	from := time.Now().UTC().AddDate(0, 0, -days).Unix()
	daily := database.TrendDaily(from)
	trend, err := database.GetDomainTrend(a.DB, domain, from, daily)
	if err != nil {
		return err
	}
	trend = database.FillTrendGaps(trend, from, 0, daily)
	return c.JSON(trendToResponse(trend))
}

func (a *App) HandleAPITopFailingSources(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	min, _ := strconv.Atoi(c.Query("min", "5"))
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if min <= 0 {
		min = 5
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	sources, err := database.GetTopFailingSources(a.DB, min, limit, f)
	if err != nil {
		return err
	}
	return c.JSON(sources)
}
