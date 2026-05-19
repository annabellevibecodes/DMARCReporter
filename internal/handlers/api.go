package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

func (a *App) HandleAPIStats(c *fiber.Ctx) error {
	days, _ := strconv.Atoi(c.Query("days", "90"))
	if days <= 0 || days > 365 {
		days = 90
	}

	trend, err := database.GetTrendData(a.DB, database.StatsFilter{From: time.Now().UTC().AddDate(0, 0, -days).Unix()})
	if err != nil {
		return err
	}

	type response struct {
		Labels []string `json:"labels"`
		Passed []int64  `json:"passed"`
		Failed []int64  `json:"failed"`
	}
	resp := response{}
	for _, pt := range trend {
		resp.Labels = append(resp.Labels, pt.Week)
		resp.Passed = append(resp.Passed, pt.Passed)
		resp.Failed = append(resp.Failed, pt.Failed)
	}
	return c.JSON(resp)
}

func (a *App) HandleAPIFailureModes(c *fiber.Ctx) error {
	fm, err := database.GetFailureModeBreakdown(a.DB, database.StatsFilter{})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"dkim_only_pass": fm.DKIMOnlyPass,
		"spf_only_pass":  fm.SPFOnlyPass,
		"both_fail":      fm.BothFail,
	})
}

func (a *App) HandleAPIDomainTrend(c *fiber.Ctx) error {
	domain := c.Query("domain")
	if domain == "" {
		return fiber.ErrBadRequest
	}
	days, _ := strconv.Atoi(c.Query("days", "90"))
	if days <= 0 || days > 365 {
		days = 90
	}

	trend, err := database.GetDomainTrend(a.DB, domain, days)
	if err != nil {
		return err
	}

	type response struct {
		Labels []string `json:"labels"`
		Passed []int64  `json:"passed"`
		Failed []int64  `json:"failed"`
	}
	resp := response{}
	for _, pt := range trend {
		resp.Labels = append(resp.Labels, pt.Week)
		resp.Passed = append(resp.Passed, pt.Passed)
		resp.Failed = append(resp.Failed, pt.Failed)
	}
	return c.JSON(resp)
}

func (a *App) HandleAPITopFailingSources(c *fiber.Ctx) error {
	min, _ := strconv.Atoi(c.Query("min", "5"))
	limit, _ := strconv.Atoi(c.Query("limit", "10"))
	if min <= 0 {
		min = 5
	}
	if limit <= 0 || limit > 100 {
		limit = 10
	}

	sources, err := database.GetTopFailingSources(a.DB, min, limit, database.StatsFilter{})
	if err != nil {
		return err
	}
	return c.JSON(sources)
}
