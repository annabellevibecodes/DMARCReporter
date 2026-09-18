package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// TLSRules are the SMTP TLS reporting rules (X12–X19). They are appended to
// Rules in init so the DMARC table above stays as it was.
//
// Every rule scopes its queries with RequireDKIM from the config, so a report
// the operator believes is excluded never raises an alert either.
var TLSRules = []Rule{
	{
		ID: "X12", Name: "tls_rate_drop",
		Description: "A domain's 7-day TLS success rate fell versus the previous 7 days.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.1f points (ALERT_TLS_RATE_DROP), ≥ %d sessions in both windows",
				c.AlertTLSRateDrop, c.AlertTLSMinWindowSessions)
		},
		Fn: ruleTLSRateDrop,
	},
	{
		ID: "X13", Name: "tls_starttls_stripped",
		Description: "A reporter that used to negotiate TLS with an MX host now says STARTTLS was not offered.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("≥ %d sessions (ALERT_TLS_STRIP_MIN_SESSIONS) on a host that previously succeeded",
				c.AlertTLSStripMinSessions)
		},
		Fn: ruleTLSStarttlsStripped,
	},
	{
		ID: "X14", Name: "tls_cert_expired",
		Description: "A reporter saw an expired certificate on one of your MX hosts.",
		Threshold:   func(c config.Config) string { return "any certificate-expired session in the window" },
		Fn:          ruleTLSCertExpired,
	},
	{
		ID: "X15", Name: "tls_policy_inconsistent",
		Description: "Reporters disagree about your TLS policy, or applied one that differs from what you publish.",
		Threshold: func(c config.Config) string {
			return "> 1 policy seen for a domain on one day, or drift against the Enrich snapshot"
		},
		Fn: ruleTLSPolicyInconsistent,
	},
	{
		ID: "X16", Name: "tls_policy_host_error",
		Description: "Senders could not fetch or validate your MTA-STS policy file.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("> %.0f%% of a domain's sessions (ALERT_TLS_POLICY_HOST_ERR_PCT)", c.AlertTLSPolicyHostErrPct)
		},
		Fn: ruleTLSPolicyHostError,
	},
	{
		ID: "X17", Name: "tls_dane_invalid",
		Description: "A reporter could not validate your DANE records.",
		Threshold:   func(c config.Config) string { return "any tlsa-invalid or dnssec-invalid session in the window" },
		Fn:          ruleTLSDaneInvalid,
	},
	{
		ID: "X18", Name: "tls_reporter_silent",
		Description: "A TLS reporter active in the last 14 days has stopped sending reports.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("no report window in %d days (ALERT_TLS_REPORTER_GAP_DAYS)", c.AlertTLSReporterGapDays)
		},
		Fn: ruleTLSReporterSilent,
	},
	{
		ID: "X19", Name: "tls_new_failing_receiver",
		Description: "A receiving node started failing under an MX host whose other nodes are fine.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("≥ %d sessions (ALERT_TLS_NEW_FAILING_IP_MIN) from a node not failing before", c.AlertTLSNewFailingIPMin)
		},
		Fn: ruleTLSNewFailingReceiver,
	},
}

func init() { Rules = append(Rules, TLSRules...) }

// tlsRecentFilter is the window the TLS rules judge, matching the DMARC rules'
// use of ALERT_RECENT_HOURS: TLS reports also arrive about a day late.
func tlsRecentFilter(c *Context) database.TLSFilter {
	return database.TLSFilter{
		From:        c.Recent(),
		RequireDKIM: c.Cfg.TLSRPTRequireDKIM,
	}
}

func ruleTLSRateDrop(c *Context) ([]Alert, error) {
	domains, err := database.ListTLSRPTDomains(c.DB)
	if err != nil {
		return nil, err
	}
	dropPts := c.Cfg.AlertTLSRateDrop
	if dropPts <= 0 {
		dropPts = 5
	}
	minSessions := c.Cfg.AlertTLSMinWindowSessions
	if minSessions <= 0 {
		minSessions = 100
	}

	var out []Alert
	for _, domain := range domains {
		cur, err := database.GetTLSRate(c.DB, database.TLSFilter{
			Domain: domain, From: c.Now.AddDate(0, 0, -7).Unix(),
			RequireDKIM: c.Cfg.TLSRPTRequireDKIM,
		})
		if err != nil {
			return nil, err
		}
		prev, err := database.GetTLSRate(c.DB, database.TLSFilter{
			Domain: domain, From: c.Now.AddDate(0, 0, -14).Unix(), To: c.Now.AddDate(0, 0, -7).Unix() - 1,
			RequireDKIM: c.Cfg.TLSRPTRequireDKIM,
		})
		if err != nil {
			return nil, err
		}
		if cur.Total < minSessions || prev.Total < minSessions {
			continue // too little traffic for the comparison to mean anything
		}
		drop := prev.Rate - cur.Rate
		if drop <= dropPts {
			continue
		}
		severity := database.SeverityWarning
		if cur.Rate < 90 {
			severity = database.SeverityCritical
		}
		out = append(out, Alert{
			Domain: domain, Key: "7d", Severity: severity,
			Message: fmt.Sprintf("TLS success rate for %s fell %.1f points week-over-week (%.1f%% → %.1f%%)",
				domain, drop, prev.Rate, cur.Rate),
			Payload: map[string]any{
				"current_rate": cur.Rate, "previous_rate": prev.Rate, "drop_points": drop,
				"current_sessions": cur.Total, "previous_sessions": prev.Total,
			},
		})
	}
	return out, nil
}

func ruleTLSStarttlsStripped(c *Context) ([]Alert, error) {
	minSessions := c.Cfg.AlertTLSStripMinSessions
	if minSessions <= 0 {
		minSessions = 5
	}
	hosts, err := database.GetTLSStrippedHosts(c.DB, tlsRecentFilter(c), minSessions)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, h := range hosts {
		// Always critical: the server did not stop offering STARTTLS, so
		// something in the path removed it. Low volume, high signal.
		out = append(out, Alert{
			Domain: h.PolicyDomain, Key: h.OrgName + "|" + h.MXHostname,
			Severity: database.SeverityCritical,
			Message: fmt.Sprintf("%s reports STARTTLS was not offered by %s (%d sessions); it negotiated TLS there before (%d sessions)",
				h.OrgName, h.MXHostname, h.FailedSessions, h.PriorSuccess),
			Payload: map[string]any{
				"org_name": h.OrgName, "mx_hostname": h.MXHostname,
				"failed_sessions": h.FailedSessions, "prior_success": h.PriorSuccess,
			},
		})
	}
	return out, nil
}

func ruleTLSCertExpired(c *Context) ([]Alert, error) {
	rows, err := database.GetTLSResultTypeOccurrences(c.DB, tlsRecentFilter(c), []string{"certificate-expired"})
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		out = append(out, Alert{
			Domain: r.PolicyDomain, Key: r.MXHostname, Severity: database.SeverityCritical,
			Message: fmt.Sprintf("%s saw an expired certificate on %s (%d sessions failed)",
				r.OrgName, r.MXHostname, r.FailedSessions),
			Payload: map[string]any{
				"org_name": r.OrgName, "mx_hostname": r.MXHostname, "failed_sessions": r.FailedSessions,
			},
		})
	}
	return out, nil
}

func ruleTLSPolicyInconsistent(c *Context) ([]Alert, error) {
	f := tlsRecentFilter(c)
	var out []Alert

	divergences, err := database.GetTLSPolicyDivergence(c.DB, f)
	if err != nil {
		return nil, err
	}
	for _, d := range divergences {
		out = append(out, Alert{
			Domain: d.PolicyDomain, Key: "divergent|" + d.Day, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("Reporters saw %d different TLS policies for %s on %s — a stale cache or a divergent policy",
				d.Distinct, d.PolicyDomain, d.Day),
			Payload: map[string]any{"day": d.Day, "distinct": d.Distinct, "policies": d.Strings},
		})
	}

	drift, err := database.GetTLSPolicyDrift(c.DB, f)
	if err != nil {
		return nil, err
	}
	for _, d := range drift {
		out = append(out, Alert{
			Domain: d.Domain, Key: "drift|" + d.Kind + "|" + d.Field, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s applied %s=%s for %s while you publish %s",
				d.OrgName, d.Field, d.Reported, d.Domain, d.Published),
			Payload: map[string]any{
				"kind": d.Kind, "field": d.Field, "published": d.Published,
				"reported": d.Reported, "org_name": d.OrgName, "report_window_end": d.LastReport,
			},
		})
	}
	return out, nil
}

func ruleTLSPolicyHostError(c *Context) ([]Alert, error) {
	pct := c.Cfg.AlertTLSPolicyHostErrPct
	if pct <= 0 {
		pct = 5
	}
	rows, err := database.GetTLSPolicyHostErrors(c.DB, tlsRecentFilter(c))
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		if r.Failures == 0 || r.Percent <= pct {
			continue
		}
		out = append(out, Alert{
			Domain: r.PolicyDomain, Key: "policy-host", Severity: database.SeverityCritical,
			Message: fmt.Sprintf("%.1f%% of sessions for %s failed fetching or validating your MTA-STS policy (%d of %d)",
				r.Percent, r.PolicyDomain, r.Failures, r.Sessions),
			Payload: map[string]any{"failures": r.Failures, "sessions": r.Sessions, "percent": r.Percent},
		})
	}
	return out, nil
}

func ruleTLSDaneInvalid(c *Context) ([]Alert, error) {
	rows, err := database.GetTLSResultTypeOccurrences(c.DB, tlsRecentFilter(c),
		[]string{"tlsa-invalid", "dnssec-invalid"})
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		out = append(out, Alert{
			Domain: r.PolicyDomain, Key: r.ResultType + "|" + r.MXHostname,
			Severity: database.SeverityCritical,
			Message: fmt.Sprintf("%s could not validate DANE for %s: %s on %s (%d sessions)",
				r.OrgName, r.PolicyDomain, r.ResultType, r.MXHostname, r.FailedSessions),
			Payload: map[string]any{
				"org_name": r.OrgName, "result_type": r.ResultType,
				"mx_hostname": r.MXHostname, "failed_sessions": r.FailedSessions,
			},
		})
	}
	return out, nil
}

func ruleTLSReporterSilent(c *Context) ([]Alert, error) {
	gapDays := c.Cfg.AlertTLSReporterGapDays
	if gapDays <= 0 {
		gapDays = 3
	}
	gaps, err := database.GetTLSReporterGaps(c.DB, c.Now.Unix(), 14, gapDays)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, g := range gaps {
		out = append(out, Alert{
			Key: "tls|" + g.OrgName, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("TLS reporter %s has sent no report for %d days (last window ended %s)",
				g.OrgName, g.DaysSilent, time.Unix(g.LastEnd, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{
				"org_name": g.OrgName, "last_begin": g.LastBegin,
				"last_end": g.LastEnd, "days_silent": g.DaysSilent,
			},
		})
	}
	return out, nil
}

func ruleTLSNewFailingReceiver(c *Context) ([]Alert, error) {
	minSessions := c.Cfg.AlertTLSNewFailingIPMin
	if minSessions <= 0 {
		minSessions = 10
	}
	rows, err := database.GetTLSNewFailingReceivers(c.DB, tlsRecentFilter(c), minSessions)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range rows {
		severity := database.SeverityWarning
		if r.SiblingNodes > 0 {
			// Other nodes of the same host are fine, so this is one bad node
			// rather than a host-wide problem — the case that hides in an
			// aggregate rate.
			severity = database.SeverityCritical
		}
		out = append(out, Alert{
			Domain: r.PolicyDomain, Key: r.MXHostname + "|" + r.ReceivingIP, Severity: severity,
			Message: fmt.Sprintf("New failing node %s under %s (%d sessions: %s)",
				r.ReceivingIP, r.MXHostname, r.FailedSessions, strings.ReplaceAll(r.ResultTypes, ",", ", ")),
			Payload: map[string]any{
				"receiving_ip": r.ReceivingIP, "mx_hostname": r.MXHostname,
				"failed_sessions": r.FailedSessions, "result_types": r.ResultTypes,
				"sibling_nodes": r.SiblingNodes,
			},
		})
	}
	return out, nil
}
