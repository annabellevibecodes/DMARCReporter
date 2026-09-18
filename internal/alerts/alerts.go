// Package alerts evaluates a table of alert rules against the database,
// persists every firing in the acknowledgeable `alerts` table and delivers
// new (or re-opened) alerts via webhook and/or SMTP email.
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Alert is one firing of a rule. (Rule, Domain, Key) identifies the alert;
// firing it again bumps the stored row instead of creating a new one.
type Alert struct {
	Rule     string         `json:"rule"`
	Type     string         `json:"type"` // == Rule; kept for webhook consumers of the old payload
	Domain   string         `json:"domain,omitempty"`
	Key      string         `json:"key,omitempty"`
	Severity string         `json:"severity"`
	Message  string         `json:"message"`
	Payload  map[string]any `json:"detail,omitempty"`
	ID       int64          `json:"id,omitempty"`
}

// Context is what a rule gets to work with.
type Context struct {
	DB  *sqlx.DB
	Cfg config.Config
	Now time.Time
}

// Recent returns the Unix time `AlertRecentHours` ago (the window used by
// "last 24h" rules; 48h by default because reports for a day arrive the next day).
func (c *Context) Recent() int64 {
	h := c.Cfg.AlertRecentHours
	if h <= 0 {
		h = 48
	}
	return c.Now.Add(-time.Duration(h) * time.Hour).Unix()
}

// Rule is one entry of the rule table.
type Rule struct {
	ID          string // X1 … X11
	Name        string // rule name stored in alerts.rule
	Description string
	Threshold   func(cfg config.Config) string // human-readable threshold for the UI
	Fn          func(c *Context) ([]Alert, error)
}

// Enabled reports whether any delivery channel is configured.
func Enabled(cfg config.Config) bool {
	return cfg.AlertWebhookURL != "" || (cfg.SMTPHost != "" && cfg.SMTPTo != "")
}

var evalMu sync.Mutex

// Evaluate runs every rule, persists the results and delivers new alerts.
// Safe to call from several goroutines; runs are serialised.
func Evaluate(db *sqlx.DB, cfg config.Config) {
	fired, delivered := EvaluateWith(db, cfg, deliver)
	if len(fired) > 0 {
		log.Printf("alerts: %d rule firing(s), %d delivered", len(fired), len(delivered))
	}
}

// EvaluateWith is Evaluate with an injectable delivery function (tests).
// It returns every alert that fired and the subset handed to deliverFn.
func EvaluateWith(db *sqlx.DB, cfg config.Config, deliverFn func(config.Config, []Alert)) (fired, delivered []Alert) {
	evalMu.Lock()
	defer evalMu.Unlock()

	ctx := &Context{DB: db, Cfg: cfg, Now: time.Now().UTC()}
	for _, r := range Rules {
		out, err := r.Fn(ctx)
		if err != nil {
			log.Printf("alerts: rule %s (%s) failed: %v", r.ID, r.Name, err)
			continue
		}
		for _, a := range out {
			a.Rule = r.Name
			a.Type = r.Name
			if a.Severity == "" {
				a.Severity = database.SeverityInfo
			}
			fired = append(fired, a)
		}
	}

	for i := range fired {
		a := &fired[i]
		payload, _ := json.Marshal(a.Payload)
		shouldDeliver, id, err := database.UpsertAlert(db, database.Alert{
			Rule: a.Rule, Domain: a.Domain, Key: a.Key, Severity: a.Severity, Message: a.Message, Payload: string(payload),
		})
		if err != nil {
			log.Printf("alerts: persist %s/%s/%s: %v", a.Rule, a.Domain, a.Key, err)
			continue
		}
		a.ID = id
		if !shouldDeliver {
			continue
		}
		// alerts_sent dedupes delivery to once per alert per day even across
		// acknowledge / re-open cycles.
		sentKey := fmt.Sprintf("%s|%s|%s|%s", a.Rule, a.Domain, a.Key, ctx.Now.Format("2006-01-02"))
		if fresh, _ := database.MarkAlertSent(db, sentKey); !fresh {
			continue
		}
		delivered = append(delivered, *a)
	}

	if len(delivered) > 0 && Enabled(cfg) && deliverFn != nil {
		sort.SliceStable(delivered, func(i, j int) bool { return severityRank(delivered[i].Severity) < severityRank(delivered[j].Severity) })
		deliverFn(cfg, delivered)
	}
	_ = database.PruneAlertsSent(db, 90*24*time.Hour)
	return fired, delivered
}

func severityRank(s string) int {
	switch s {
	case database.SeverityCritical:
		return 0
	case database.SeverityWarning:
		return 1
	}
	return 2
}

// StartScheduler evaluates the rules shortly after start-up and then every
// interval, so time-based rules (silent reporters, missing selectors, …)
// fire even when no new reports arrive.
func StartScheduler(db *sqlx.DB, cfg config.Config, interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		time.Sleep(30 * time.Second)
		Evaluate(db, cfg)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			Evaluate(db, cfg)
		}
	}()
	log.Printf("alerts: scheduled evaluation every %s", interval)
}

func deliver(cfg config.Config, alerts []Alert) {
	if cfg.AlertWebhookURL != "" {
		payload, _ := json.Marshal(map[string]any{
			"source": "dmarcreporter",
			"alerts": alerts,
		})
		resp, err := httpClient.Post(cfg.AlertWebhookURL, "application/json", bytes.NewReader(payload))
		if err != nil {
			log.Printf("alerts: webhook delivery failed: %v", err)
		} else {
			resp.Body.Close()
			log.Printf("alerts: delivered %d alert(s) to webhook (HTTP %d)", len(alerts), resp.StatusCode)
		}
	}

	if cfg.SMTPHost != "" && cfg.SMTPTo != "" {
		if err := sendEmail(cfg, alerts); err != nil {
			log.Printf("alerts: email delivery failed: %v", err)
		} else {
			log.Printf("alerts: delivered %d alert(s) via email to %s", len(alerts), cfg.SMTPTo)
		}
	}
}

func sendEmail(cfg config.Config, alerts []Alert) error {
	from := cfg.SMTPFrom
	if from == "" {
		from = cfg.SMTPUser
	}
	var body strings.Builder
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nSubject: [DMARC Reporter] %d alert(s)\r\n\r\n",
		from, cfg.SMTPTo, len(alerts))
	for _, a := range alerts {
		scope := ""
		if a.Domain != "" {
			scope = " " + a.Domain + ":"
		}
		fmt.Fprintf(&body, "- [%s] [%s]%s %s\r\n", strings.ToUpper(a.Severity), a.Rule, scope, a.Message)
	}

	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}
	to := strings.Split(cfg.SMTPTo, ",")
	return smtp.SendMail(addr, auth, from, to, []byte(body.String()))
}

// RuleByName returns the rule with the given stored name, or nil.
func RuleByName(name string) *Rule {
	for i := range Rules {
		if Rules[i].Name == name {
			return &Rules[i]
		}
	}
	return nil
}
