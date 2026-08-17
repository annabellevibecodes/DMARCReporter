// Package alerts evaluates alert conditions after ingest runs and delivers
// notifications via webhook and/or SMTP email.
package alerts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Alert is one notification event.
type Alert struct {
	Type    string `json:"type"`    // "pass_rate_drop" | "new_failing_source"
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

// Enabled reports whether any delivery channel is configured.
func Enabled(cfg config.Config) bool {
	return cfg.AlertWebhookURL != "" || (cfg.SMTPHost != "" && cfg.SMTPTo != "")
}

// Evaluate checks alert conditions and delivers any new alerts. Alerts are
// deduplicated via the alerts_sent table so re-running is safe.
func Evaluate(db *sqlx.DB, cfg config.Config) {
	if !Enabled(cfg) {
		return
	}
	var alerts []Alert

	// Pass-rate drop: current 7 days vs the 7 days before that.
	now := time.Now().UTC()
	cur, err := database.GetPassRateWindow(db, now.AddDate(0, 0, -7).Unix(), now.Unix()+1)
	if err == nil {
		prev, err2 := database.GetPassRateWindow(db, now.AddDate(0, 0, -14).Unix(), now.AddDate(0, 0, -7).Unix())
		// Require enough volume in both windows to be meaningful.
		if err2 == nil && cur.TotalMessages >= 50 && prev.TotalMessages >= 50 {
			drop := prev.Rate() - cur.Rate()
			if drop > cfg.AlertPassRateDrop {
				key := "passdrop:" + now.Format("2006-01-02")
				if fresh, _ := database.MarkAlertSent(db, key); fresh {
					alerts = append(alerts, Alert{
						Type: "pass_rate_drop",
						Message: fmt.Sprintf("DMARC pass rate dropped %.1f points week-over-week (%.1f%% → %.1f%%)",
							drop, prev.Rate(), cur.Rate()),
						Detail: map[string]any{
							"previous_rate": prev.Rate(), "current_rate": cur.Rate(),
							"previous_messages": prev.TotalMessages, "current_messages": cur.TotalMessages,
						},
					})
				}
			}
		}
	} else {
		log.Printf("alerts: pass-rate query failed: %v", err)
	}

	// New failing sources first seen in the last 48 hours.
	sources, err := database.GetNewFailingSources(db, now.Add(-48*time.Hour).Unix())
	if err != nil {
		log.Printf("alerts: new-source query failed: %v", err)
	}
	for _, s := range sources {
		key := "newsource:" + s.SourceIP
		if fresh, _ := database.MarkAlertSent(db, key); !fresh {
			continue
		}
		alerts = append(alerts, Alert{
			Type: "new_failing_source",
			Message: fmt.Sprintf("New source %s is failing DMARC (%d of %d messages failed)",
				s.SourceIP, s.Failed, s.Total),
			Detail: map[string]any{"source_ip": s.SourceIP, "failed": s.Failed, "total": s.Total},
		})
	}

	if len(alerts) == 0 {
		return
	}
	deliver(cfg, alerts)
	_ = database.PruneAlertsSent(db, 90*24*time.Hour)
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
		fmt.Fprintf(&body, "- [%s] %s\r\n", a.Type, a.Message)
	}

	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	var auth smtp.Auth
	if cfg.SMTPUser != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPass, cfg.SMTPHost)
	}
	to := strings.Split(cfg.SMTPTo, ",")
	return smtp.SendMail(addr, auth, from, to, []byte(body.String()))
}
