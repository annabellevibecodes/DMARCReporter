package handlers

import (
	"fmt"
	"html/template"
	"math"
	"strings"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

// patternThresholds builds the S3 thresholds from config.
func (a *App) patternThresholds() ipinfo.PatternThresholds {
	th := ipinfo.DefaultPatternThresholds
	if a.Cfg.PatternHealthyMin > 0 {
		th.HealthyMin = a.Cfg.PatternHealthyMin
	}
	if a.Cfg.PatternForwarderMin > 0 {
		th.ForwarderMin = a.Cfg.PatternForwarderMin
	}
	if a.Cfg.PatternBrokenSigningMin > 0 {
		th.BrokenSigningMin = a.Cfg.PatternBrokenSigningMin
	}
	if a.Cfg.PatternSpoofMin > 0 {
		th.SpoofMin = a.Cfg.PatternSpoofMin
	}
	if a.Cfg.PatternSpoofMinMsgs > 0 {
		th.SpoofMinMsgs = a.Cfg.PatternSpoofMinMsgs
	}
	return th
}

// matrixPayload is the C5 2×2 matrix with shares.
type matrixPayload struct {
	BothPass int64 `json:"both_pass"`
	DKIMOnly int64 `json:"dkim_only"`
	SPFOnly  int64 `json:"spf_only"`
	Neither  int64 `json:"neither"`
	Total    int64 `json:"total"`
	// Shares in percent.
	BothPassPct float64 `json:"both_pass_pct"`
	DKIMOnlyPct float64 `json:"dkim_only_pct"`
	SPFOnlyPct  float64 `json:"spf_only_pct"`
	NeitherPct  float64 `json:"neither_pct"`
}

func toMatrixPayload(m *database.AuthMatrix) matrixPayload {
	return matrixPayload{
		BothPass: m.BothPass, DKIMOnly: m.DKIMOnlyPass, SPFOnly: m.SPFOnlyPass, Neither: m.BothFail,
		Total:       m.Total(),
		BothPassPct: m.Share(m.BothPass), DKIMOnlyPct: m.Share(m.DKIMOnlyPass),
		SPFOnlyPct: m.Share(m.SPFOnlyPass), NeitherPct: m.Share(m.BothFail),
	}
}

// dispositionPayload is C6.
type dispositionPayload struct {
	None          int64   `json:"none"`
	Quarantine    int64   `json:"quarantine"`
	Reject        int64   `json:"reject"`
	Total         int64   `json:"total"`
	NonePct       float64 `json:"none_pct"`
	QuarantinePct float64 `json:"quarantine_pct"`
	RejectPct     float64 `json:"reject_pct"`
}

func toDispositionPayload(d *database.DispositionStats) dispositionPayload {
	p := dispositionPayload{None: d.None, Quarantine: d.Quarantine, Reject: d.Reject, Total: d.Total()}
	if p.Total > 0 {
		p.NonePct = float64(d.None) / float64(p.Total) * 100
		p.QuarantinePct = float64(d.Quarantine) / float64(p.Total) * 100
		p.RejectPct = float64(d.Reject) / float64(p.Total) * 100
	}
	return p
}

// enforcementPayload is C7.
type enforcementPayload struct {
	Policy   string   `json:"policy"`
	Enforced int64    `json:"enforced"`
	Failing  int64    `json:"failing"`
	Rate     *float64 `json:"rate"` // null when p=none
	// WouldBlockPct is the share of all mail that is currently failing — the
	// volume a move to p=reject would block (used when p=none).
	WouldBlockPct float64 `json:"would_block_pct"`
}

// overviewMetrics is one window's worth of C1–C8 numbers.
type overviewMetrics struct {
	TotalMessages  int64   `json:"total_messages"`
	TotalReports   int64   `json:"total_reports"`
	TotalDomains   int64   `json:"total_domains"`
	TotalReporters int64   `json:"total_reporters"`
	Passed         int64   `json:"passed"`
	Failed         int64   `json:"failed"`
	PassRate       float64 `json:"pass_rate"`
	DKIMAligned    int64   `json:"dkim_aligned"`
	DKIMRate       float64 `json:"dkim_rate"`
	SPFAligned     int64   `json:"spf_aligned"`
	SPFRate        float64 `json:"spf_rate"`

	Matrix      matrixPayload      `json:"matrix"`
	Disposition dispositionPayload `json:"disposition"`
	Enforcement enforcementPayload `json:"enforcement"`

	Overrides            []database.PolicyOverrideStat      `json:"overrides"`
	OverrideMessages     int64                              `json:"override_messages"`
	UnexplainedOverrides *database.UnexplainedOverrideStats `json:"unexplained_overrides"`
	NewSources           int                                `json:"new_sources"`
	NewSourceList        []database.SourceInventoryRow      `json:"-"`
	Spoof                *database.SpoofVolume              `json:"spoof"` // S4
	SpoofStatus          string                             `json:"spoof_status"`
}

// computeOverview gathers C1–C8 (and S2 count) for one window.
func (a *App) computeOverview(f database.StatsFilter) (*overviewMetrics, error) {
	f.Compare = false
	stats, err := database.GetDashboardStats(a.DB, f)
	if err != nil {
		return nil, err
	}
	matrix, err := database.GetAuthMatrix(a.DB, f)
	if err != nil {
		return nil, err
	}
	disp, err := database.GetDispositionStats(a.DB, f)
	if err != nil {
		return nil, err
	}
	enf, err := database.GetEnforcementEffectiveness(a.DB, f)
	if err != nil {
		return nil, err
	}
	overrides, err := database.GetPolicyOverrideBreakdown(a.DB, f)
	if err != nil {
		return nil, err
	}
	unexplained, err := database.GetUnexplainedOverrides(a.DB, f, 5)
	if err != nil {
		return nil, err
	}
	newSources, err := database.GetNewSources(a.DB, f, a.patternThresholds(), 1000)
	if err != nil {
		return nil, err
	}
	spoof, err := database.GetSpoofVolume(a.DB, f, 5)
	if err != nil {
		return nil, err
	}

	m := &overviewMetrics{
		TotalMessages: stats.TotalMessages, TotalReports: stats.TotalReports,
		TotalDomains: stats.TotalDomains, TotalReporters: stats.TotalReporters,
		Passed: stats.Passed, Failed: stats.Failed, PassRate: stats.PassRate,
		DKIMAligned: stats.DKIMAlignedPass, DKIMRate: stats.DKIMPassRate,
		SPFAligned: stats.SPFAlignedPass, SPFRate: stats.SPFPassRate,
		Matrix:      toMatrixPayload(matrix),
		Disposition: toDispositionPayload(disp),
		Enforcement: enforcementPayload{Policy: enf.Policy, Enforced: enf.Enforced, Failing: enf.Failing, Rate: enf.Rate},
		Overrides:   overrides, UnexplainedOverrides: unexplained,
		NewSources: len(newSources), NewSourceList: newSources,
		Spoof: spoof, SpoofStatus: spoofStatus(spoof),
	}
	if stats.TotalMessages > 0 {
		m.Enforcement.WouldBlockPct = float64(enf.Failing) / float64(stats.TotalMessages) * 100
	}
	for _, o := range overrides {
		m.OverrideMessages += o.TotalMessages
	}
	return m, nil
}

// overviewDelta holds current-vs-previous differences for the KPI tiles.
type overviewDelta struct {
	TotalMessagesPct float64 `json:"total_messages_pct"` // relative change in percent
	PassRatePts      float64 `json:"pass_rate_pts"`
	DKIMRatePts      float64 `json:"dkim_rate_pts"`
	SPFRatePts       float64 `json:"spf_rate_pts"`
	NeitherPctPts    float64 `json:"neither_pct_pts"`
}

func computeDelta(cur, prev *overviewMetrics) *overviewDelta {
	if prev == nil {
		return nil
	}
	d := &overviewDelta{
		PassRatePts:   cur.PassRate - prev.PassRate,
		DKIMRatePts:   cur.DKIMRate - prev.DKIMRate,
		SPFRatePts:    cur.SPFRate - prev.SPFRate,
		NeitherPctPts: cur.Matrix.NeitherPct - prev.Matrix.NeitherPct,
	}
	if prev.TotalMessages > 0 {
		d.TotalMessagesPct = (float64(cur.TotalMessages) - float64(prev.TotalMessages)) / float64(prev.TotalMessages) * 100
	}
	return d
}

// ---- view models for the server-rendered dashboard blocks ----

// deltaView is a rendered delta chip.
type deltaView struct {
	Dir  string // up | down | flat (up = good)
	Text string
}

// newDeltaView builds a chip; higherIsBetter flips the colouring.
func newDeltaView(val float64, unit string, higherIsBetter bool) *deltaView {
	v := math.Round(val*10) / 10
	dir := "flat"
	arrow := "→"
	if math.Abs(v) >= 0.3 {
		if v > 0 {
			arrow = "↑"
		} else {
			arrow = "↓"
		}
		if (v > 0) == higherIsBetter {
			dir = "up"
		} else {
			dir = "down"
		}
	}
	return &deltaView{Dir: dir, Text: fmt.Sprintf("%s %.1f%s", arrow, math.Abs(v), unit)}
}

// kpiView is one tile in the overview KPI row.
type kpiView struct {
	Label  string
	ID     string // metric id shown as a hint (C1…)
	Value  string
	Sub    string
	Delta  *deltaView
	Spark  template.HTML
	Health bool
}

// buildKPIs renders the C1–C4 tiles from the current metrics, trend and delta.
func buildKPIs(cur *overviewMetrics, delta *overviewDelta, trend []database.TrendPoint) []kpiView {
	var totals, pass, dkim, spf []float64
	for _, p := range trend {
		t := float64(p.Total())
		totals = append(totals, t)
		if t > 0 {
			pass = append(pass, float64(p.Passed)/t*100)
			dkim = append(dkim, float64(p.DKIMPassed)/t*100)
			spf = append(spf, float64(p.SPFPassed)/t*100)
		} else {
			pass = append(pass, math.NaN())
			dkim = append(dkim, math.NaN())
			spf = append(spf, math.NaN())
		}
	}
	kpis := []kpiView{
		{Label: "Total messages", ID: "C1", Value: commaN(cur.TotalMessages), Spark: sparklineSVG(totals)},
		{Label: "DMARC pass rate", ID: "C2", Value: fmt.Sprintf("%.1f%%", cur.PassRate), Spark: sparklineSVG(pass)},
		{Label: "DKIM aligned", ID: "C3", Value: fmt.Sprintf("%.1f%%", cur.DKIMRate), Spark: sparklineSVG(dkim)},
		{Label: "SPF aligned", ID: "C4", Value: fmt.Sprintf("%.1f%%", cur.SPFRate), Spark: sparklineSVG(spf)},
	}
	if delta != nil {
		kpis[0].Delta = newDeltaView(delta.TotalMessagesPct, "%", true)
		kpis[1].Delta = newDeltaView(delta.PassRatePts, "pts", true)
		kpis[2].Delta = newDeltaView(delta.DKIMRatePts, "pts", true)
		kpis[3].Delta = newDeltaView(delta.SPFRatePts, "pts", true)
	}
	return kpis
}

// attentionItem is one row in the "needs attention" list.
type attentionItem struct {
	Severity string // critical | warning | info
	Title    string
	Sub      string
	Tag      string
	Href     string
}

// sparklineSVG renders a small area sparkline; NaN points are skipped.
func sparklineSVG(values []float64) template.HTML {
	var pts []float64
	for _, v := range values {
		if !math.IsNaN(v) {
			pts = append(pts, v)
		}
	}
	if len(pts) < 2 {
		return ""
	}
	const w, h = 140.0, 34.0
	min, max := pts[0], pts[0]
	for _, v := range pts {
		min = math.Min(min, v)
		max = math.Max(max, v)
	}
	if max == min {
		max = min + 1
	}
	step := w / float64(len(pts)-1)
	var d strings.Builder
	var lastX, lastY float64
	for i, v := range pts {
		x := float64(i) * step
		y := h - ((v-min)/(max-min))*(h-4) - 2
		if i == 0 {
			fmt.Fprintf(&d, "M%.1f,%.1f", x, y)
		} else {
			fmt.Fprintf(&d, " L%.1f,%.1f", x, y)
		}
		lastX, lastY = x, y
	}
	line := d.String()
	area := fmt.Sprintf("%s L%.0f,%.0f L0,%.0f Z", line, w, h, h)
	svg := fmt.Sprintf(`<svg viewBox="0 0 %.0f %.0f" width="100%%" height="%.0f" preserveAspectRatio="none" style="overflow:visible" aria-hidden="true">`+
		`<path d="%s" class="spark-area"/>`+
		`<path d="%s" class="spark-line"/>`+
		`<circle cx="%.1f" cy="%.1f" r="2.4" class="spark-dot"/></svg>`,
		w, h, h, area, line, lastX, lastY)
	return template.HTML(svg)
}

// commaN formats an integer with thousands separators.
func commaN(n int64) string {
	s := fmt.Sprintf("%d", n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}
