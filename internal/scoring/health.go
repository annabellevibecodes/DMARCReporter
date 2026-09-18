// Package scoring computes the per-domain (or global) DMARC health score.
//
// The score adds five components, each capped at its weight (defaults in
// parentheses, configurable via HEALTH_W_*):
//
//	pass rate            pass rate percent × W_pass/100                          (40)
//	enforcement level    p=none 0, p=quarantine 60 %, p=reject 100 % of W_enforce (25)
//	spoof share          (100 − spoof share) × W_spoof/100                        (15)
//	reporter coverage    ≥3 distinct reporters in 7 days → W_cov, 2 → W_cov/2     (10)
//	open alerts          no open critical alert → W_alerts                        (10)
//
// The spoof share is the not-in-SPF volume once the SPF cache is resolved for
// every domain in scope, otherwise the "neither aligned" share of the matrix.
package scoring

import (
	"math"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// Weights are the five component maxima.
type Weights struct {
	PassRate    float64
	Enforcement float64
	Spoof       float64
	Coverage    float64
	Alerts      float64
}

// WeightsFromConfig reads HEALTH_W_* (falling back to the spec defaults).
func WeightsFromConfig(cfg config.Config) Weights {
	w := Weights{PassRate: cfg.HealthWeightPassRate, Enforcement: cfg.HealthWeightEnforcement,
		Spoof: cfg.HealthWeightSpoof, Coverage: cfg.HealthWeightCoverage, Alerts: cfg.HealthWeightAlerts}
	if w.PassRate+w.Enforcement+w.Spoof+w.Coverage+w.Alerts <= 0 {
		return DefaultWeights
	}
	return w
}

// DefaultWeights are the spec defaults.
var DefaultWeights = Weights{PassRate: 40, Enforcement: 25, Spoof: 15, Coverage: 10, Alerts: 10}

// Score is the result with every component exposed for the UI.
type Score struct {
	Total  int    `json:"total"`
	Max    int    `json:"max"`
	Label  string `json:"label"` // Excellent | Good | Fair | Critical
	Domain string `json:"domain"`

	PassRate      float64 `json:"pass_rate"`
	Policy        string  `json:"policy"`
	SpoofShare    float64 `json:"spoof_share"` // percent of messages counted as spoof
	SpoofResolved bool    `json:"spoof_resolved"`
	Reporters7d   int     `json:"reporters_7d"`
	OpenCritical  int     `json:"open_critical_alerts"`
	OpenAlerts    int     `json:"open_alerts"`
	TotalMessages int64   `json:"total_messages"`

	Components struct {
		PassRate    float64 `json:"pass_rate"`
		Enforcement float64 `json:"enforcement"`
		Spoof       float64 `json:"spoof"`
		Coverage    float64 `json:"coverage"`
		Alerts      float64 `json:"alerts"`
	} `json:"components"`
	Weights Weights `json:"weights"`
}

// LabelFor maps a score to its label.
func LabelFor(total, max int) string {
	if max <= 0 {
		max = 100
	}
	pct := float64(total) / float64(max) * 100
	switch {
	case pct >= 85:
		return "Excellent"
	case pct >= 65:
		return "Good"
	case pct >= 40:
		return "Fair"
	}
	return "Critical"
}

// BannerClass maps a label to the CSS modifier used by the health banner.
func BannerClass(label string) string {
	switch label {
	case "Excellent", "Good":
		return "excellent"
	case "Fair":
		return "warning"
	}
	return "critical"
}

// Compute calculates the score for domain ("" = all domains) over the window f.
func Compute(db *sqlx.DB, domain string, f database.StatsFilter, w Weights) (*Score, error) {
	f.Domain = domain
	f.Compare = false
	s := &Score{Domain: domain, Weights: w, Max: int(math.Round(w.PassRate + w.Enforcement + w.Spoof + w.Coverage + w.Alerts))}

	stats, err := database.GetDashboardStats(db, f)
	if err != nil {
		return nil, err
	}
	s.PassRate = stats.PassRate
	s.TotalMessages = stats.TotalMessages
	if stats.TotalMessages > 0 {
		s.Components.PassRate = stats.PassRate / 100 * w.PassRate
	}

	policy, err := database.GetActivePolicy(db, f)
	if err != nil {
		return nil, err
	}
	s.Policy = policy
	switch policy {
	case "reject":
		s.Components.Enforcement = w.Enforcement
	case "quarantine":
		s.Components.Enforcement = w.Enforcement * 0.6
	}

	// Spoof share: not-in-SPF volume when the SPF cache is populated for the
	// domains in scope, otherwise the "neither" share of the matrix.
	sv, err := database.GetSpoofVolume(db, f, 1)
	if err != nil {
		return nil, err
	}
	if sv.Resolved && sv.Unresolved == 0 && stats.TotalMessages > 0 {
		s.SpoofResolved = true
		s.SpoofShare = float64(sv.NotInSPF) / float64(stats.TotalMessages) * 100
	} else if stats.TotalMessages > 0 {
		m, err := database.GetAuthMatrix(db, f)
		if err != nil {
			return nil, err
		}
		s.SpoofShare = m.Share(m.BothFail)
	}
	if stats.TotalMessages > 0 {
		s.Components.Spoof = (100 - s.SpoofShare) / 100 * w.Spoof
	}

	reporters, err := database.CountDistinctReporters(db, domain, time.Now().AddDate(0, 0, -7).Unix())
	if err != nil {
		return nil, err
	}
	s.Reporters7d = reporters
	switch {
	case reporters >= 3:
		s.Components.Coverage = w.Coverage
	case reporters == 2:
		s.Components.Coverage = w.Coverage / 2
	}

	open, critical, err := database.CountOpenAlerts(db, domain)
	if err != nil {
		return nil, err
	}
	s.OpenAlerts, s.OpenCritical = open, critical
	if critical == 0 {
		s.Components.Alerts = w.Alerts
	}

	total := s.Components.PassRate + s.Components.Enforcement + s.Components.Spoof + s.Components.Coverage + s.Components.Alerts
	s.Total = int(math.Round(total))
	if s.Total > s.Max {
		s.Total = s.Max
	}
	s.Label = LabelFor(s.Total, s.Max)
	return s, nil
}
