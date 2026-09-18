package handlers

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/alerts"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/scoring"
)

func init() {
	// Later-phase hooks into the dashboard / overview payloads.
	attentionExtras = func(a *App, f database.StatsFilter) []attentionItem {
		open, err := database.ListAlerts(a.DB, "open", f.Domain, 4)
		if err != nil {
			return nil
		}
		var items []attentionItem
		for _, al := range open {
			items = append(items, attentionItem{
				Severity: al.Severity,
				Title:    ruleTitle(al.Rule),
				Sub:      al.Message,
				Tag:      ruleID(al.Rule),
				Href:     "/alerts?state=open",
			})
		}
		return items
	}
	overviewExtras = func(a *App, f database.StatsFilter, resp fiber.Map) {
		if h, err := scoring.Compute(a.DB, f.Domain, f, scoring.WeightsFromConfig(a.Cfg)); err == nil {
			resp["health"] = h
		}
		if open, _, err := database.CountOpenAlerts(a.DB, f.Domain); err == nil {
			resp["open_alerts"] = open
		}
	}
}

// ruleID returns the X-number for a stored rule name ("" when unknown).
func ruleID(name string) string {
	if r := alerts.RuleByName(name); r != nil {
		return r.ID
	}
	return ""
}

// ruleTitle returns a display title for a stored rule name.
func ruleTitle(name string) string {
	return strings.ReplaceAll(name, "_", " ")
}

// alertView is one alert prepared for the template.
type alertView struct {
	database.Alert
	RuleID      string
	Title       string
	PayloadRows [][2]string
	ContextHref string
}

// ruleView is one rule-table row.
type ruleView struct {
	ID, Name, Description, Threshold string
}

func (a *App) alertViews(list []database.Alert) []alertView {
	out := make([]alertView, 0, len(list))
	for _, al := range list {
		v := alertView{Alert: al, RuleID: ruleID(al.Rule), Title: ruleTitle(al.Rule), ContextHref: contextHref(al)}
		if al.Payload != "" {
			var m map[string]any
			if err := json.Unmarshal([]byte(al.Payload), &m); err == nil {
				keys := make([]string, 0, len(m))
				for k := range m {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					v.PayloadRows = append(v.PayloadRows, [2]string{k, payloadValue(m[k])})
				}
			}
		}
		out = append(out, v)
	}
	return out
}

func payloadValue(v any) string {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return fmt.Sprintf("%.2f", x)
	case string:
		return x
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	if len(b) > 200 {
		return string(b[:200]) + "…"
	}
	return string(b)
}

// contextHref links an alert to the page where it can be investigated. Key and
// Domain reach us from report data, so both are escaped: an unescaped segment
// containing "/" or "?" would silently point the link somewhere else.
func contextHref(al database.Alert) string {
	switch al.Rule {
	case "new_failing_source", "known_source_degraded", "spoof_spike":
		if al.Rule != "spoof_spike" && al.Key != "" {
			return "/sources/" + url.PathEscape(al.Key)
		}
		return "/sources?matrix=neither&period=30d"
	case "new_selector", "selector_missing", "policy_changed", "policy_inconsistent", "pass_rate_drop", "override_spike":
		if al.Domain != "" {
			return "/domains/" + url.PathEscape(al.Domain)
		}
	case "reporter_silent", "dns_error_spike":
		return "/reporters"
	}
	return "/"
}

// HandleAlertsPage renders /alerts.
func (a *App) HandleAlertsPage(c *fiber.Ctx) error {
	state := c.Query("state", "open")
	switch state {
	case "open", "ack", "all":
	default:
		state = "open"
	}
	severity := c.Query("severity", "all")
	domain := c.Query("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	list, err := database.ListAlerts(a.DB, state, domain, 500)
	if err != nil {
		return err
	}
	if severity != "all" {
		var filtered []database.Alert
		for _, al := range list {
			if al.Severity == severity {
				filtered = append(filtered, al)
			}
		}
		list = filtered
	}
	open, critical, err := database.CountOpenAlerts(a.DB, "")
	if err != nil {
		return err
	}
	alertDomains, err := database.ListAlertDomains(a.DB)
	if err != nil {
		return err
	}
	rules := make([]ruleView, 0, len(alerts.Rules))
	for _, r := range alerts.Rules {
		rules = append(rules, ruleView{ID: r.ID, Name: r.Name, Description: r.Description, Threshold: r.Threshold(a.Cfg)})
	}
	flashKind, flashMsg := getFlash(c)
	return c.Render("alerts", fiber.Map{
		"Title":         "Alerts — DMARC Reporter",
		"Theme":         getTheme(c),
		"ActivePage":    "alerts",
		"Alerts":        a.alertViews(list),
		"State":         state,
		"Severity":      severity,
		"Domain":        domain,
		"Domains":       alertDomains,
		"OpenCount":     open,
		"CriticalCount": critical,
		"Rules":         rules,
		"Delivery":      alerts.Enabled(a.Cfg),
		"Webhook":       a.Cfg.AlertWebhookURL != "",
		"Email":         a.Cfg.SMTPHost != "" && a.Cfg.SMTPTo != "",
		"EvalInterval":  a.Cfg.AlertEvalInterval.String(),
		"CurrentPath":   currentPath(c),
		"IMAPEnabled":   a.FetchEnabled(),
		"FlashKind":     flashKind,
		"FlashMsg":      flashMsg,
		"CSRFToken":     c.Locals("csrf"),
	}, "layouts/base")
}

// HandleAPIAlerts serves /api/alerts?state=open|ack|all.
func (a *App) HandleAPIAlerts(c *fiber.Ctx) error {
	state := c.Query("state", "open")
	domain := c.Query("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	limit, _ := strconv.Atoi(c.Query("limit", "200"))
	list, err := database.ListAlerts(a.DB, state, domain, limit)
	if err != nil {
		return err
	}
	if list == nil {
		list = []database.Alert{}
	}
	open, critical, err := database.CountOpenAlerts(a.DB, domain)
	if err != nil {
		return err
	}
	type apiAlert struct {
		database.Alert
		RuleID  string          `json:"rule_id"`
		Detail  json.RawMessage `json:"detail"`
		Context string          `json:"context_url"`
	}
	out := make([]apiAlert, 0, len(list))
	for _, al := range list {
		detail := json.RawMessage(al.Payload)
		if !json.Valid(detail) {
			detail = json.RawMessage("null")
		}
		al.Payload = ""
		out = append(out, apiAlert{Alert: al, RuleID: ruleID(al.Rule), Detail: detail, Context: contextHref(al)})
	}
	return c.JSON(fiber.Map{"state": state, "open": open, "critical": critical, "alerts": out})
}

// HandleAPIAlertAck handles POST /api/alerts/:id/ack.
func (a *App) HandleAPIAlertAck(c *fiber.Ctx) error {
	id, err := strconv.ParseInt(c.Params("id"), 10, 64)
	if err != nil || id <= 0 {
		return fiber.ErrBadRequest
	}
	ok, err := database.AcknowledgeAlert(a.DB, id)
	if err != nil {
		return err
	}
	if redirect := c.FormValue("redirect"); safeRedirect(redirect) {
		if ok {
			a.setFlash(c, "success", "Alert acknowledged.")
		} else {
			a.setFlash(c, "info", "Alert was already acknowledged.")
		}
		return c.Redirect(redirect, fiber.StatusSeeOther)
	}
	if !ok {
		al, err := database.GetAlert(a.DB, id)
		if err != nil {
			return err
		}
		if al == nil {
			return fiber.ErrNotFound
		}
	}
	return c.JSON(fiber.Map{"id": id, "acknowledged": true, "changed": ok, "at": time.Now().Unix()})
}

// HandleAPIEvaluateAlerts handles POST /api/alerts/evaluate — runs the rules now.
func (a *App) HandleAPIEvaluateAlerts(c *fiber.Ctx) error {
	go alerts.Evaluate(a.DB, a.Cfg)
	if redirect := c.FormValue("redirect"); safeRedirect(redirect) {
		a.setFlash(c, "info", "Alert rules are being evaluated in the background; reload in a moment.")
		return c.Redirect(redirect, fiber.StatusSeeOther)
	}
	return c.JSON(fiber.Map{"started": true})
}

// HandleAPIHealth serves /api/health and /api/health/:domain.
func (a *App) HandleAPIHealth(c *fiber.Ctx) error {
	domain := c.Params("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	cmp, err := database.WithComparison(f, func(sf database.StatsFilter) (*scoring.Score, error) {
		return scoring.Compute(a.DB, domain, sf, scoring.WeightsFromConfig(a.Cfg))
	})
	if err != nil {
		return err
	}
	var prev *scoring.Score
	if cmp.Previous != nil {
		prev = *cmp.Previous
	}
	return c.JSON(fiber.Map{
		"window":   windowFor(f, c.Query("period")),
		"health":   cmp.Current,
		"previous": prev,
	})
}

// healthKPI is the dashboard tile / banner view model.
type healthKPI struct {
	Score   int
	Max     int
	Label   string
	Class   string
	Summary string
	Delta   *deltaView
}

func (a *App) healthKPIFor(domain string, f database.StatsFilter) *healthKPI {
	cmp, err := database.WithComparison(f, func(sf database.StatsFilter) (*scoring.Score, error) {
		return scoring.Compute(a.DB, domain, sf, scoring.WeightsFromConfig(a.Cfg))
	})
	if err != nil {
		return nil
	}
	s := cmp.Current
	k := &healthKPI{Score: s.Total, Max: s.Max, Label: s.Label, Class: scoring.BannerClass(s.Label)}
	parts := []string{fmt.Sprintf("pass %.0f/%.0f", s.Components.PassRate, s.Weights.PassRate)}
	parts = append(parts, fmt.Sprintf("policy %.0f/%.0f", s.Components.Enforcement, s.Weights.Enforcement))
	parts = append(parts, fmt.Sprintf("spoof %.0f/%.0f", s.Components.Spoof, s.Weights.Spoof))
	parts = append(parts, fmt.Sprintf("coverage %.0f/%.0f", s.Components.Coverage, s.Weights.Coverage))
	parts = append(parts, fmt.Sprintf("alerts %.0f/%.0f", s.Components.Alerts, s.Weights.Alerts))
	k.Summary = strings.Join(parts, " · ")
	if cmp.Previous != nil {
		k.Delta = newDeltaView(float64(s.Total-(*cmp.Previous).Total), "pts", true)
	}
	return k
}
