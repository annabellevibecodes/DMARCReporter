package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// Rules is the rule table, evaluated in order.
var Rules = []Rule{
	{
		ID: "X1", Name: "new_failing_source",
		Description: "A source IP seen for the first time in the last 48 hours is failing DMARC for a domain.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("≥ %d messages (ALERT_NEW_SOURCE_MIN)", c.AlertNewSourceMin)
		},
		Fn: ruleNewFailingSource,
	},
	{
		ID: "X2", Name: "pass_rate_drop",
		Description: "A domain's 7-day DMARC pass rate fell versus the previous 7 days.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.1f points (ALERT_PASS_RATE_DROP), ≥ %d messages in both windows", c.AlertPassRateDrop, c.AlertMinWindowMessages)
		},
		Fn: rulePassRateDrop,
	},
	{
		ID: "X3", Name: "known_source_degraded",
		Description: "A source labelled known_good is passing far less than its 7-day baseline.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.0f points below baseline (ALERT_KNOWN_DROP)", c.AlertKnownDropPts)
		},
		Fn: ruleKnownSourceDegraded,
	},
	{
		ID: "X4", Name: "new_selector",
		Description: "A DKIM selector not marked as expected started signing mail.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("first seen within %dh (ALERT_NEW_SELECTOR_HOURS)", c.AlertNewSelectorHours)
		},
		Fn: ruleNewSelector,
	},
	{
		ID: "X5", Name: "selector_missing",
		Description: "A selector marked as expected has not signed any mail recently.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("unseen for %d days (ALERT_SELECTOR_MISSING_DAYS)", c.AlertSelectorMissingDays)
		},
		Fn: ruleSelectorMissing,
	},
	{
		ID: "X6", Name: "reporter_silent",
		Description: "A reporter active in the last 14 days has stopped sending reports.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("no report window in %d days (ALERT_REPORTER_GAP_DAYS)", c.AlertReporterGapDays)
		},
		Fn: ruleReporterSilent,
	},
	{
		ID: "X7", Name: "policy_changed",
		Description: "The published DMARC record changed (p, sp, adkim, aspf or pct), as observed by reporters.",
		Threshold:   func(c config.Config) string { return "any change observed in the last 48h" },
		Fn:          rulePolicyChanged,
	},
	{
		ID: "X8", Name: "policy_inconsistent",
		Description: "Reporters disagree on a domain's effective DMARC record.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> 1 effective record in the last %dh", c.AlertRecentHours)
		},
		Fn: rulePolicyInconsistent,
	},
	{
		ID: "X9", Name: "dns_error_spike",
		Description: "A reporter logged DNS temp/perm errors on a large share of its raw DKIM/SPF results.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.0f%% of raw results (ALERT_DNS_ERROR_PCT), ≥ 20 results", c.AlertDNSErrorPct)
		},
		Fn: ruleDNSErrorSpike,
	},
	{
		ID: "X10", Name: "override_spike",
		Description: "Policy-override (\"forgiven failure\") volume jumped versus its 7-day daily mean.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.0f× daily mean (ALERT_OVERRIDE_SPIKE_FACTOR), ≥ 10 messages", c.AlertOverrideFactor)
		},
		Fn: ruleOverrideSpike,
	},
	{
		ID: "X11", Name: "spoof_spike",
		Description: "Unauthenticated mail from IPs outside the domain's resolved SPF record spiked (needs the Enrich SPF expansion).",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.0f× daily mean (ALERT_SPOOF_SPIKE_FACTOR) or > %d messages (ALERT_SPOOF_ABS)", c.AlertSpoofFactor, c.AlertSpoofAbs)
		},
		Fn: ruleSpoofSpike,
	},
}

func ruleSpoofSpike(c *Context) ([]Alert, error) {
	domains, err := database.ListReportDomains(c.DB)
	if err != nil {
		return nil, err
	}
	factor := c.Cfg.AlertSpoofFactor
	if factor <= 0 {
		factor = 3
	}
	abs := c.Cfg.AlertSpoofAbs
	if abs <= 0 {
		abs = 50
	}
	recent := c.Recent()
	recentDays := float64(c.Now.Unix()-recent) / 86400
	if recentDays <= 0 {
		recentDays = 1
	}
	var out []Alert
	for _, d := range domains {
		cur, err := database.GetSpoofVolume(c.DB, database.StatsFilter{Domain: d, From: recent}, 5)
		if err != nil {
			return nil, err
		}
		if !cur.Resolved || cur.Unresolved > 0 || cur.NotInSPF == 0 {
			continue // no SPF expansion for this domain yet, or nothing outside SPF
		}
		base, err := database.GetSpoofVolume(c.DB, database.StatsFilter{Domain: d, From: recent - 7*86400, To: recent - 1}, 1)
		if err != nil {
			return nil, err
		}
		mean := float64(base.NotInSPF) / 7 * recentDays
		if mean <= 0 {
			mean = 1
		}
		spike := float64(cur.NotInSPF) > factor*mean
		if !spike && cur.NotInSPF <= abs {
			continue
		}
		sev := database.SeverityWarning
		if cur.NotInSPF > abs {
			sev = database.SeverityCritical
		}
		var top []string
		for _, s := range cur.Sources {
			if !s.InSPF && s.Resolved {
				top = append(top, s.SourceIP)
			}
		}
		out = append(out, Alert{
			Domain: d, Key: c.Now.Format("2006-01-02"), Severity: sev,
			Message: fmt.Sprintf("%d unauthenticated messages for %s came from IPs outside its SPF record (baseline %.0f per window)", cur.NotInSPF, d, mean),
			Payload: map[string]any{"not_in_spf": cur.NotInSPF, "in_spf": cur.InSPF, "baseline_per_window": mean, "top_sources": top},
		})
	}
	return out, nil
}

func ruleNewFailingSource(c *Context) ([]Alert, error) {
	minMsgs := c.Cfg.AlertNewSourceMin
	if minMsgs <= 0 {
		minMsgs = 1
	}
	sources, err := database.GetNewFailingSourcesByDomain(c.DB, c.Now.Add(-48*time.Hour).Unix(), minMsgs)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, s := range sources {
		sev := database.SeverityWarning
		if s.Failed == s.Total && s.Total >= 50 {
			sev = database.SeverityCritical
		}
		out = append(out, Alert{
			Domain: s.Domain, Key: s.SourceIP, Severity: sev,
			Message: fmt.Sprintf("New source %s is failing DMARC for %s (%d of %d messages failed)", s.SourceIP, s.Domain, s.Failed, s.Total),
			Payload: map[string]any{"source_ip": s.SourceIP, "failed": s.Failed, "total": s.Total, "first_seen": s.FirstSeen},
		})
	}
	return out, nil
}

func rulePassRateDrop(c *Context) ([]Alert, error) {
	domains, err := database.ListReportDomains(c.DB)
	if err != nil {
		return nil, err
	}
	minMsgs := int64(c.Cfg.AlertMinWindowMessages)
	var out []Alert
	for _, d := range domains {
		cur, err := database.GetPassRateWindowDomain(c.DB, d, c.Now.AddDate(0, 0, -7).Unix(), c.Now.Unix()+1)
		if err != nil {
			return nil, err
		}
		prev, err := database.GetPassRateWindowDomain(c.DB, d, c.Now.AddDate(0, 0, -14).Unix(), c.Now.AddDate(0, 0, -7).Unix())
		if err != nil {
			return nil, err
		}
		if cur.TotalMessages < minMsgs || prev.TotalMessages < minMsgs {
			continue
		}
		drop := prev.Rate() - cur.Rate()
		if drop <= c.Cfg.AlertPassRateDrop {
			continue
		}
		sev := database.SeverityWarning
		if drop > 2*c.Cfg.AlertPassRateDrop {
			sev = database.SeverityCritical
		}
		y, w := c.Now.ISOWeek()
		out = append(out, Alert{
			Domain: d, Key: fmt.Sprintf("%04d-W%02d", y, w), Severity: sev,
			Message: fmt.Sprintf("DMARC pass rate for %s dropped %.1f points week-over-week (%.1f%% → %.1f%%)", d, drop, prev.Rate(), cur.Rate()),
			Payload: map[string]any{
				"previous_rate": prev.Rate(), "current_rate": cur.Rate(),
				"previous_messages": prev.TotalMessages, "current_messages": cur.TotalMessages, "drop_pts": drop,
			},
		})
	}
	return out, nil
}

func ruleKnownSourceDegraded(c *Context) ([]Alert, error) {
	labels, err := database.ListIPLabels(c.DB)
	if err != nil {
		return nil, err
	}
	recent := c.Recent()
	var out []Alert
	for ip, l := range labels {
		if l.Classification != "known_good" {
			continue
		}
		cur, err := database.GetDashboardStats(c.DB, database.StatsFilter{SourceIP: ip, From: recent})
		if err != nil {
			return nil, err
		}
		if cur.TotalMessages < 10 {
			continue
		}
		base, err := database.GetDashboardStats(c.DB, database.StatsFilter{SourceIP: ip, From: c.Now.AddDate(0, 0, -9).Unix(), To: recent - 1})
		if err != nil {
			return nil, err
		}
		if base.TotalMessages < int64(c.Cfg.AlertMinWindowMessages) {
			continue
		}
		drop := base.PassRate - cur.PassRate
		if drop <= c.Cfg.AlertKnownDropPts {
			continue
		}
		name := ip
		if l.Label != "" {
			name = l.Label + " (" + ip + ")"
		}
		out = append(out, Alert{
			Key: ip, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Known-good source %s dropped from %.1f%% to %.1f%% pass rate", name, base.PassRate, cur.PassRate),
			Payload: map[string]any{"source_ip": ip, "label": l.Label, "baseline_rate": base.PassRate, "current_rate": cur.PassRate,
				"baseline_messages": base.TotalMessages, "current_messages": cur.TotalMessages},
		})
	}
	return out, nil
}

func ruleNewSelector(c *Context) ([]Alert, error) {
	sels, err := database.ListSelectors(c.DB, "")
	if err != nil {
		return nil, err
	}
	hours := c.Cfg.AlertNewSelectorHours
	if hours <= 0 {
		hours = 48
	}
	since := c.Now.Add(-time.Duration(hours) * time.Hour).Unix()
	var out []Alert
	for _, s := range sels {
		if s.Expected == 1 || s.FirstSeen == 0 || s.FirstSeen < since {
			continue
		}
		out = append(out, Alert{
			Domain: s.Domain, Key: s.Selector, Severity: database.SeverityInfo,
			Message: fmt.Sprintf("New DKIM selector %s._domainkey.%s started signing mail (first seen %s)", s.Selector, s.Domain, time.Unix(s.FirstSeen, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{"selector": s.Selector, "signing_domain": s.Domain, "first_seen": s.FirstSeen, "expected": s.Expected},
		})
	}
	return out, nil
}

func ruleSelectorMissing(c *Context) ([]Alert, error) {
	sels, err := database.ListSelectors(c.DB, "")
	if err != nil {
		return nil, err
	}
	days := c.Cfg.AlertSelectorMissingDays
	if days <= 0 {
		days = 7
	}
	cutoff := c.Now.AddDate(0, 0, -days).Unix()
	var out []Alert
	for _, s := range sels {
		if s.Expected != 1 || s.LastSeen >= cutoff {
			continue
		}
		last := "never"
		if s.LastSeen > 0 {
			last = time.Unix(s.LastSeen, 0).UTC().Format("2006-01-02")
		}
		out = append(out, Alert{
			Domain: s.Domain, Key: s.Selector, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Expected DKIM selector %s._domainkey.%s has not signed any mail since %s", s.Selector, s.Domain, last),
			Payload: map[string]any{"selector": s.Selector, "signing_domain": s.Domain, "last_seen": s.LastSeen},
		})
	}
	return out, nil
}

func ruleReporterSilent(c *Context) ([]Alert, error) {
	gapDays := c.Cfg.AlertReporterGapDays
	if gapDays <= 0 {
		gapDays = 3
	}
	gaps, err := database.GetReporterGaps(c.DB, 14, gapDays)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, g := range gaps {
		out = append(out, Alert{
			Key: g.OrgName, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Reporter %s has sent no report for %d days (last window ended %s)", g.OrgName, g.DaysSilent, time.Unix(g.LastEnd, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{"org_name": g.OrgName, "last_begin": g.LastBegin, "last_end": g.LastEnd, "days_silent": g.DaysSilent},
		})
	}
	return out, nil
}

func policyStrength(p string) int {
	switch p {
	case "reject":
		return 2
	case "quarantine":
		return 1
	}
	return 0
}

func rulePolicyChanged(c *Context) ([]Alert, error) {
	domains, err := database.ListReportDomains(c.DB)
	if err != nil {
		return nil, err
	}
	since := c.Now.Add(-48 * time.Hour).Unix()
	var out []Alert
	for _, d := range domains {
		log, err := database.GetPolicyChangeLog(c.DB, d, 10)
		if err != nil {
			return nil, err
		}
		for _, ch := range log {
			if ch.At < since {
				continue
			}
			var parts []string
			for _, df := range ch.Diff {
				parts = append(parts, df.Field+": "+df.From+" → "+df.To)
			}
			sev := database.SeverityInfo
			if policyStrength(ch.To.P) < policyStrength(ch.From.P) {
				sev = database.SeverityWarning
			}
			out = append(out, Alert{
				Domain: d, Key: time.Unix(ch.At, 0).UTC().Format("2006-01-02") + " " + strings.Join(parts, "; "), Severity: sev,
				Message: fmt.Sprintf("Published DMARC record for %s changed on %s: %s (seen by %s)", d, time.Unix(ch.At, 0).UTC().Format("2006-01-02"), strings.Join(parts, "; "), strings.Join(ch.Reporters, ", ")),
				Payload: map[string]any{"at": ch.At, "diff": ch.Diff, "reporters": ch.Reporters, "from": ch.From, "to": ch.To},
			})
		}
	}
	return out, nil
}

func rulePolicyInconsistent(c *Context) ([]Alert, error) {
	domains, err := database.ListReportDomains(c.DB)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, d := range domains {
		tuples, err := database.GetPolicyConsistency(c.DB, database.StatsFilter{Domain: d, From: c.Recent()})
		if err != nil {
			return nil, err
		}
		if len(tuples) <= 1 {
			continue
		}
		var keys, desc []string
		for _, t := range tuples {
			keys = append(keys, t.Key)
			desc = append(desc, strings.Join(t.Tags, " ")+" ("+strings.Join(t.ReporterList, ", ")+")")
		}
		out = append(out, Alert{
			Domain: d, Key: strings.Join(keys, " | "), Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Reporters disagree on the DMARC record for %s: %s", d, strings.Join(desc, " vs ")),
			Payload: map[string]any{"tuples": tuples},
		})
	}
	return out, nil
}

func ruleDNSErrorSpike(c *Context) ([]Alert, error) {
	rates, err := database.GetDNSErrorRate(c.DB, database.StatsFilter{From: c.Recent()})
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rates {
		if r.Results < 20 || r.Rate <= c.Cfg.AlertDNSErrorPct {
			continue
		}
		out = append(out, Alert{
			Key: r.OrgName, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s reported DNS errors on %.1f%% of raw DKIM/SPF results (%d of %d)", r.OrgName, r.Rate, r.Errors, r.Results),
			Payload: map[string]any{"org_name": r.OrgName, "errors": r.Errors, "results": r.Results, "rate": r.Rate},
		})
	}
	return out, nil
}

func ruleOverrideSpike(c *Context) ([]Alert, error) {
	domains, err := database.ListReportDomains(c.DB)
	if err != nil {
		return nil, err
	}
	factor := c.Cfg.AlertOverrideFactor
	if factor <= 0 {
		factor = 3
	}
	recent := c.Recent()
	recentDays := float64(c.Now.Unix()-recent) / 86400
	if recentDays <= 0 {
		recentDays = 1
	}
	var out []Alert
	for _, d := range domains {
		cur, err := database.CountOverrideMessages(c.DB, d, recent, c.Now.Unix()+1)
		if err != nil {
			return nil, err
		}
		if cur < 10 {
			continue
		}
		base, err := database.CountOverrideMessages(c.DB, d, c.Now.AddDate(0, 0, -7).Unix()-int64(recentDays*86400), recent)
		if err != nil {
			return nil, err
		}
		mean := float64(base) / 7 * recentDays // baseline scaled to the recent window length
		if mean <= 0 {
			mean = 1
		}
		if float64(cur) <= factor*mean {
			continue
		}
		out = append(out, Alert{
			Domain: d, Key: c.Now.Format("2006-01-02"), Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Policy overrides for %s spiked to %d messages (%.1f× the 7-day baseline of %.0f)", d, cur, float64(cur)/mean, mean),
			Payload: map[string]any{"current": cur, "baseline_per_window": mean, "factor": float64(cur) / mean},
		})
	}
	return out, nil
}
