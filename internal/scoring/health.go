// Package scoring computes the per-domain (or global) mail health score.
//
// The score adds six components, each capped at its weight (defaults in
// parentheses, configurable via HEALTH_W_*):
//
//	pass rate            pass rate percent × W_pass/100                          (40)
//	enforcement level    p=none 0, p=quarantine 60 %, p=reject 100 % of W_enforce (25)
//	spoof share          (100 − spoof share) × W_spoof/100                        (15)
//	reporter coverage    ≥3 distinct reporters in 7 days → W_cov, 2 → W_cov/2     (10)
//	open alerts          no open critical alert → W_alerts                        (10)
//	transport security   TLS success rate (70 %) + TLS reporter coverage (30 %)   (15)
//
// The spoof share is the not-in-SPF volume once the SPF cache is resolved for
// every domain in scope, otherwise the "neither aligned" share of the matrix.
//
// The TLS component is skipped, not zeroed, when a domain has no TLS sessions
// to judge: its weight comes out of Max as well as the total, so a domain
// nobody sends TLS reports about scores exactly as it did before the
// component existed. Absence of evidence and evidence of breakage are
// different states and must not look alike. (The DMARC pass-rate and spoof
// components still score a flat 0 with no data — a pre-existing defect logged
// in ANALYTICS_PLAN.md, deliberately not changed here because it would move
// every existing score.)
package scoring

import (
	"math"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// Weights are the six component maxima.
type Weights struct {
	PassRate    float64
	Enforcement float64
	Spoof       float64
	Coverage    float64
	Alerts      float64
	TLS         float64
	BIMI        float64
}

// WeightsFromConfig reads HEALTH_W_* (falling back to the spec defaults).
func WeightsFromConfig(cfg config.Config) Weights {
	w := Weights{PassRate: cfg.HealthWeightPassRate, Enforcement: cfg.HealthWeightEnforcement,
		Spoof: cfg.HealthWeightSpoof, Coverage: cfg.HealthWeightCoverage, Alerts: cfg.HealthWeightAlerts,
		TLS: cfg.HealthWeightTLS, BIMI: cfg.HealthWeightBIMI}
	if w.PassRate+w.Enforcement+w.Spoof+w.Coverage+w.Alerts <= 0 {
		return DefaultWeights
	}
	return w
}

// DefaultWeights are the spec defaults. The DMARC five still sum to 100; the
// TLS component is added on top rather than by rebalancing them, because Max
// is computed from the weights in play and a domain's DMARC score therefore
// keeps its meaning.
var DefaultWeights = Weights{PassRate: 40, Enforcement: 25, Spoof: 15, Coverage: 10, Alerts: 10, TLS: 15, BIMI: 10}

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

	// TLS transport security. TLSScored is false when there were no TLS
	// sessions to judge, in which case the component is left out of both the
	// total and the maximum rather than scored as a failure.
	TLSScored    bool    `json:"tls_scored"`
	TLSRate      float64 `json:"tls_rate"`
	TLSSessions  int64   `json:"tls_sessions"`
	TLSReporters int     `json:"tls_reporters"`

	// Brand indicators. BIMIScored is false when the domain publishes no BIMI
	// record, in which case the component leaves both the total and the
	// maximum — "does not use BIMI" must never look like "BIMI is broken".
	BIMIScored    bool   `json:"bimi_scored"`
	BIMIState     string `json:"bimi_state,omitempty"`
	BIMIEligible  bool   `json:"bimi_eligible"`
	BIMIValidated bool   `json:"bimi_validated"`
	BIMIValid     bool   `json:"bimi_valid"`
	// BIMIWeight is how much of the BIMI weight was actually in play: the
	// policy half alone when the documents have not been checked.
	BIMIWeight float64 `json:"bimi_weight"`

	Components struct {
		PassRate    float64 `json:"pass_rate"`
		Enforcement float64 `json:"enforcement"`
		Spoof       float64 `json:"spoof"`
		Coverage    float64 `json:"coverage"`
		Alerts      float64 `json:"alerts"`
		TLS         float64 `json:"tls"`
		BIMI        float64 `json:"bimi"`
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
//
// TLS reports that fail the RFC 8460 §3 signature requirement are excluded
// from the TLS component, matching every other TLS figure in the interface.
func Compute(db *sqlx.DB, domain string, f database.StatsFilter, w Weights) (*Score, error) {
	return ComputeWithOptions(db, domain, f, w, true)
}

// ComputeWithOptions is Compute with the DKIM requirement made explicit, for
// callers that carry their own configuration.
func ComputeWithOptions(db *sqlx.DB, domain string, f database.StatsFilter, w Weights, requireDKIM bool) (*Score, error) {
	f.Domain = domain
	f.Compare = false
	s := &Score{Domain: domain, Weights: w}

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

	// Transport security (T1 + T12). Judged only when there are sessions to
	// judge: no TLS reports means no evidence either way, so the component is
	// dropped from the maximum instead of scoring zero.
	if err := s.scoreTLS(db, domain, f, w, requireDKIM); err != nil {
		return nil, err
	}

	// Brand indicators (B10 plus B6–B9). Judged only for a domain that
	// publishes a record: a domain that does not do BIMI is not doing it
	// badly, so the component is dropped from the maximum rather than scored
	// zero — the same rule the TLS component follows.
	if err := s.scoreBIMI(db, domain, f, w); err != nil {
		return nil, err
	}

	maxWeight := w.PassRate + w.Enforcement + w.Spoof + w.Coverage + w.Alerts
	if s.TLSScored {
		maxWeight += w.TLS
	}
	if s.BIMIScored {
		maxWeight += s.BIMIWeight
	}
	s.Max = int(math.Round(maxWeight))

	total := s.Components.PassRate + s.Components.Enforcement + s.Components.Spoof +
		s.Components.Coverage + s.Components.Alerts + s.Components.TLS + s.Components.BIMI
	s.Total = int(math.Round(total))
	if s.Total > s.Max {
		s.Total = s.Max
	}
	s.Label = LabelFor(s.Total, s.Max)
	return s, nil
}

// scoreTLS fills in the transport-security component.
//
// The split is 70 % success rate and 30 % reporter coverage: the rate is what
// the component is about, but a rate computed from a single reporter is one
// provider's view, so coverage carries real weight too.
func (s *Score) scoreTLS(db *sqlx.DB, domain string, f database.StatsFilter, w Weights, requireDKIM bool) error {
	tf := database.TLSFilter{
		Domain: domain, From: f.From, To: f.To, RequireDKIM: requireDKIM,
	}
	rate, err := database.GetTLSRate(db, tf)
	if err != nil {
		return err
	}
	s.TLSSessions = rate.Total
	s.TLSRate = rate.Rate
	if rate.Total == 0 {
		// No sessions: nothing to judge. TLSScored stays false and the
		// weight is left out of Max by the caller.
		return nil
	}

	volume, err := database.GetTLSVolume(db, tf)
	if err != nil {
		return err
	}
	s.TLSReporters = volume.ReporterCount
	s.TLSScored = true

	component := rate.Rate / 100 * w.TLS * 0.7
	switch {
	case volume.ReporterCount >= 2:
		component += w.TLS * 0.3
	case volume.ReporterCount == 1:
		component += w.TLS * 0.15
	}
	s.Components.TLS = component
	return nil
}

// scoreBIMI fills in the brand-indicator component.
//
// It is scored only for a domain that publishes a record offering an
// indicator. A domain with no record, or one that declines to publish, is not
// doing BIMI badly — it is not doing BIMI — so the component leaves both the
// total and the maximum, exactly as the TLS component does when there are no
// sessions. Scoring it zero would tell every operator who has never heard of
// BIMI that their domain is broken.
//
// The split, once a record exists: 40 % that the DMARC policy permits BIMI at
// all (B10), 60 % that the documents check out (B6–B9). A record whose
// documents have not been checked — because BIMI_VALIDATE is off, or because
// Enrich has not run — scores the policy half and keeps the other half out of
// the maximum, since an unperformed check is not a failed one.
func (s *Score) scoreBIMI(db *sqlx.DB, domain string, f database.StatsFilter, w Weights) error {
	if domain == "" {
		// The all-domains score has no single BIMI configuration to judge.
		return nil
	}
	state, err := database.GetBIMIDomainState(db, domain)
	if err != nil {
		return err
	}
	if state == nil || !state.Published() {
		if state != nil {
			s.BIMIState = state.State
		}
		return nil
	}
	s.BIMIScored = true
	s.BIMIState = state.State

	readiness, err := database.GetBIMIReadinessFor(db, domain, f)
	if err != nil {
		return err
	}
	// An unknown policy (no reports in the window) is not scored against the
	// domain: it is scored as eligible, because the record exists and nothing
	// contradicts it.
	s.BIMIEligible = !readiness.Known || readiness.Eligible

	component := 0.0
	if s.BIMIEligible {
		component += w.BIMI * 0.4
	}

	validations, err := database.ListBIMIValidations(db, domain)
	if err != nil {
		return err
	}
	var checked *database.BIMIValidationState
	for i := range validations {
		if validations[i].Selector == state.Selector && validations[i].Checked() {
			checked = &validations[i]
			break
		}
	}
	if checked == nil {
		// The documents have not been checked. Drop that 60 % from the
		// maximum too, so the domain is judged only on what was measured.
		s.BIMIWeight = w.BIMI * 0.4
		s.Components.BIMI = component
		return nil
	}
	s.BIMIValidated = true
	s.BIMIValid = checked.Valid()
	s.BIMIWeight = w.BIMI
	if s.BIMIValid {
		component += w.BIMI * 0.6
	}
	s.Components.BIMI = component
	return nil
}
