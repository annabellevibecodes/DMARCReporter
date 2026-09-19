package alerts

import (
	"fmt"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// BIMIRules are the brand-indicator rules (X20–X27). They are appended to
// Rules in init so the tables above stay as they were.
//
// Every one of them reads the snapshots the Enrich worker writes, and none
// resolves DNS or fetches a document of its own: an alert evaluation that went
// to the network would double the outbound traffic and could disagree with
// what the rest of the interface shows.
var BIMIRules = []Rule{
	{
		ID: "X20", Name: "bimi_record_changed",
		Description: "A domain's published BIMI assertion record changed.",
		Threshold:   func(c config.Config) string { return "any change observed in the last 48h" },
		Fn:          ruleBIMIRecordChanged,
	},
	{
		ID: "X21", Name: "bimi_blocked_by_policy",
		Description: "A domain publishes a BIMI record that no receiver can act on, because its DMARC policy does not qualify.",
		Threshold:   func(c config.Config) string { return "a published record on a domain failing the B10 test" },
		Fn:          ruleBIMIBlockedByPolicy,
	},
	{
		ID: "X22", Name: "bimi_unexpected_selector",
		Description: "A BIMI selector not marked as expected appeared.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("first seen within %dh (ALERT_NEW_SELECTOR_HOURS)", c.AlertNewSelectorHours)
		},
		Fn: ruleBIMIUnexpectedSelector,
	},
	{
		ID: "X23", Name: "bimi_indicator_unreachable",
		Description: "The logo at l= could not be retrieved, or the TLS chain of the host serving it did not validate.",
		Threshold:   func(c config.Config) string { return "any retrieval or TLS failure at the current check" },
		Fn:          ruleBIMIIndicatorUnreachable,
	},
	{
		ID: "X24", Name: "bimi_indicator_invalid",
		Description: "The retrieved logo does not conform to the SVG Tiny Portable/Secure profile.",
		Threshold:   func(c config.Config) string { return "any breach of the profile in the retrieved document" },
		Fn:          ruleBIMIIndicatorInvalid,
	},
	{
		ID: "X25", Name: "bimi_evidence_expiring",
		Description: "The evidence document at a= is approaching expiry.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("%d days of runway left (ALERT_BIMI_EXPIRY_DAYS)", c.AlertBIMIExpiryDays)
		},
		Fn: ruleBIMIEvidenceExpiring,
	},
	{
		ID: "X26", Name: "bimi_evidence_invalid",
		Description: "The evidence document has expired, has been revoked, or no longer chains to a trusted root.",
		Threshold:   func(c config.Config) string { return "any of expiry, revocation or a broken chain" },
		Fn:          ruleBIMIEvidenceInvalid,
	},
	{
		ID: "X27", Name: "bimi_indicator_mismatch",
		Description: "The logo served at l= is not the mark inside the evidence document at a=.",
		Threshold:   func(c config.Config) string { return "any difference between the two marks (core spec §7.9)" },
		Fn:          ruleBIMIIndicatorMismatch,
	},
}

func init() { Rules = append(Rules, BIMIRules...) }

// bimiValidations is the shared read for X23–X27: the current state of the
// active checks for every selector of every domain.
//
// A selector the checks have never run for produces no alert of any kind. That
// is the same principle as the TLS component of the health score: absence of
// evidence is not evidence of breakage, and an operator who has switched the
// document fetches off must not be told their logos are broken.
func bimiValidations(c *Context) ([]database.BIMIValidationState, error) {
	all, err := database.ListBIMIValidations(c.DB, "")
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, v := range all {
		if v.Checked() {
			out = append(out, v)
		}
	}
	return out, nil
}

// alertKey names the selector an alert is about, so two selectors of one
// domain raise two alerts rather than overwriting each other.
func alertKey(v database.BIMIValidationState) string { return v.Selector }

func ruleBIMIIndicatorUnreachable(c *Context) ([]Alert, error) {
	states, err := bimiValidations(c)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, v := range states {
		for _, f := range v.Indicator.Findings {
			if f.Code != "indicator_unreachable" && f.Code != "indicator_tls" {
				continue
			}
			out = append(out, Alert{
				Domain: v.Domain, Key: alertKey(v), Severity: database.SeverityWarning,
				Message: fmt.Sprintf("%s: the BIMI logo for selector %s cannot be retrieved — %s",
					v.Domain, v.Selector, f.Message),
				Payload: map[string]any{
					"selector": v.Selector, "code": f.Code,
					"url": v.Indicator.Fetch.URL, "status": v.Indicator.Fetch.Status,
				},
			})
			break // one alert per selector, not one per symptom
		}
	}
	return out, nil
}

func ruleBIMIIndicatorInvalid(c *Context) ([]Alert, error) {
	states, err := bimiValidations(c)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, v := range states {
		// A logo that could not be retrieved is X23's business; this rule is
		// about a logo that arrived and is not conforming.
		if !v.Indicator.Retrieved() || v.Indicator.SVGPS.Valid {
			continue
		}
		var codes []string
		for _, f := range v.Indicator.SVGPS.Findings {
			if f.Severity == bimi.SeverityError {
				codes = append(codes, f.Code)
			}
		}
		if len(codes) == 0 {
			continue
		}
		out = append(out, Alert{
			Domain: v.Domain, Key: alertKey(v), Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s: the BIMI logo for selector %s does not conform to SVG Tiny P/S (%s)",
				v.Domain, v.Selector, strings.Join(codes, ", ")),
			Payload: map[string]any{
				"selector": v.Selector, "codes": codes, "url": v.Indicator.Fetch.URL,
			},
		})
	}
	return out, nil
}

func ruleBIMIEvidenceExpiring(c *Context) ([]Alert, error) {
	states, err := bimiValidations(c)
	if err != nil {
		return nil, err
	}
	days := c.Cfg.AlertBIMIExpiryDays
	if days <= 0 {
		days = 30
	}
	var out []Alert
	for _, v := range states {
		// An already-expired document is X26's business, and at critical
		// severity; warning about its runway as well would be noise.
		if v.Evidence == nil || v.Evidence.NotAfter == 0 || v.Evidence.DaysToExpiry < 0 {
			continue
		}
		if v.Evidence.DaysToExpiry > days {
			continue
		}
		out = append(out, Alert{
			Domain: v.Domain, Key: alertKey(v), Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s: the BIMI evidence document for selector %s expires in %d day(s), on %s",
				v.Domain, v.Selector, v.Evidence.DaysToExpiry,
				time.Unix(v.Evidence.NotAfter, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{
				"selector": v.Selector, "days_to_expiry": v.Evidence.DaysToExpiry,
				"not_after": v.Evidence.NotAfter, "issuer": v.Evidence.Issuer,
			},
		})
	}
	return out, nil
}

func ruleBIMIEvidenceInvalid(c *Context) ([]Alert, error) {
	states, err := bimiValidations(c)
	if err != nil {
		return nil, err
	}
	// The states that stop a receiver accepting the document outright.
	//
	// evidence_mark_hash is here for the same reason as the rest: a
	// certificate whose own recorded hash does not match the mark embedded in
	// it is internally inconsistent, and nothing an evaluator does with it
	// afterwards can be relied on. The plan's table listed only expiry,
	// revocation and trust; this is the same class of defect and was added
	// deliberately (see ANALYTICS_PLAN.md).
	fatal := map[string]bool{
		"evidence_expired": true, "evidence_revoked": true, "evidence_untrusted": true,
		"evidence_not_yet_valid": true, "evidence_mark_hash": true,
	}
	var out []Alert
	for _, v := range states {
		if v.Evidence == nil {
			continue
		}
		for _, f := range v.Evidence.Findings {
			if !fatal[f.Code] {
				continue
			}
			out = append(out, Alert{
				Domain: v.Domain, Key: alertKey(v), Severity: database.SeverityCritical,
				Message: fmt.Sprintf("%s: the BIMI evidence document for selector %s is not usable — %s",
					v.Domain, v.Selector, f.Message),
				Payload: map[string]any{
					"selector": v.Selector, "code": f.Code,
					"issuer": v.Evidence.Issuer, "not_after": v.Evidence.NotAfter,
					"revocation": v.Evidence.Revocation.Status,
				},
			})
			break
		}
	}
	return out, nil
}

func ruleBIMIIndicatorMismatch(c *Context) ([]Alert, error) {
	states, err := bimiValidations(c)
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, v := range states {
		if !v.Agreement.Checked || v.Agreement.Matches {
			continue
		}
		out = append(out, Alert{
			Domain: v.Domain, Key: alertKey(v), Severity: database.SeverityCritical,
			Message: fmt.Sprintf("%s: the logo served for selector %s is not the mark inside its evidence document, so no receiver will display it (core spec §7.9)",
				v.Domain, v.Selector),
			Payload: map[string]any{
				"selector":       v.Selector,
				"indicator_hash": v.Agreement.IndicatorHash,
				"evidence_hash":  v.Agreement.EvidenceHash,
			},
		})
	}
	return out, nil
}

// ruleBIMIRecordChanged reports a changed assertion record.
//
// Info, not a warning: rotating a logo or a certificate is routine, and the
// alert exists so that an unplanned change is noticed, not so that a planned
// one looks like a fault. What it does say is which way the change went, since
// "the record disappeared" and "the logo was updated" both land here.
func ruleBIMIRecordChanged(c *Context) ([]Alert, error) {
	changes, err := database.ListBIMIRecordChanges(c.DB, c.Recent())
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, ch := range changes {
		out = append(out, Alert{
			Domain: ch.Domain, Key: ch.Selector, Severity: database.SeverityInfo,
			Message: fmt.Sprintf("BIMI record for %s._bimi.%s changed on %s: %s → %s",
				ch.Selector, ch.Domain, time.Unix(ch.At, 0).UTC().Format("2006-01-02"),
				describeBIMIState(ch.From, ch.FromError), describeBIMIState(ch.To, ch.ToError)),
			Payload: map[string]any{
				"selector": ch.Selector, "at": ch.At,
				"from": ch.From, "to": ch.To,
				"from_error": ch.FromError, "to_error": ch.ToError,
			},
		})
	}
	return out, nil
}

// ruleBIMIBlockedByPolicy is the one BIMI alert that reports wasted effort
// rather than breakage: the domain has done the work of publishing a record,
// and no receiver will look at it, because the DMARC policy disqualifies the
// domain before BIMI is ever considered.
func ruleBIMIBlockedByPolicy(c *Context) ([]Alert, error) {
	states, err := database.ListBIMIDomainStates(c.DB, "")
	if err != nil {
		return nil, err
	}
	readiness, err := database.GetBIMIReadiness(c.DB, database.StatsFilter{From: c.Recent()})
	if err != nil {
		return nil, err
	}
	byDomain := make(map[string]database.BIMIReadiness, len(readiness))
	for _, r := range readiness {
		byDomain[r.Domain] = r
	}

	var out []Alert
	seen := map[string]bool{}
	for _, s := range states {
		// Only a record offering an indicator is worth complaining about. A
		// declination is a decision, and a record that is already invalid has
		// a more immediate problem than its DMARC policy.
		if s.State != bimi.StatePublished || seen[s.Domain] {
			continue
		}
		r, ok := byDomain[s.Domain]
		// No reports in the window means no verdict, and no alert: an unknown
		// policy must never be reported as a failing one.
		if !ok || !r.Known || r.Eligible {
			continue
		}
		seen[s.Domain] = true
		out = append(out, Alert{
			Domain: s.Domain, Key: "policy", Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s publishes a BIMI record but its DMARC policy blocks BIMI: %s",
				s.Domain, joinReasons(r.Blockers)),
			Payload: map[string]any{
				"blockers": r.Blockers, "policy": r.Policy.Tags(), "selector": s.Selector,
			},
		})
	}
	return out, nil
}

// ruleBIMIUnexpectedSelector mirrors the DKIM new_selector rule: a selector
// nobody has vouched for started answering. For BIMI that is either a second
// brand being published under the domain, or a zone edit nobody meant to make.
func ruleBIMIUnexpectedSelector(c *Context) ([]Alert, error) {
	sels, err := database.ListBIMISelectors(c.DB, "")
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
			Message: fmt.Sprintf("New BIMI selector %s._bimi.%s is publishing a record (first seen %s)",
				s.Selector, s.Domain, time.Unix(s.FirstSeen, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{
				"selector": s.Selector, "source": s.Source,
				"first_seen": s.FirstSeen, "expected": s.Expected,
			},
		})
	}
	return out, nil
}

// describeBIMIState renders one side of a change in a few words. The raw
// record is in the payload; the message needs to be readable in an email.
func describeBIMIState(content, errMsg string) string {
	switch {
	case errMsg != "":
		return "lookup failed (" + errMsg + ")"
	case content == "":
		return "no record"
	}
	rec := bimi.Parse(content)
	switch rec.State() {
	case bimi.StateDeclined:
		return "declination to publish"
	case bimi.StateInvalid:
		return "an unusable record"
	}
	if rec.Authority != "" {
		return "logo and evidence published"
	}
	return "logo published, no evidence"
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "the policy does not qualify"
	}
	out := reasons[0]
	for _, r := range reasons[1:] {
		out += "; " + r
	}
	return out
}

// BIMIReportRules are the rules that read the <bimi> element of aggregate
// reports (X28, X29), as opposed to what the domain publishes.
//
// They will be quiet for most operators for a long time: BIMI reporting
// adoption is close to zero, which is what B18 measures and why neither rule
// tries to infer anything from silence.
var BIMIReportRules = []Rule{
	{
		ID: "X28", Name: "bimi_errors_reported",
		Description: "An evaluator reported a BIMI error tuple for a domain for the first time.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("first seen within the last %dh (ALERT_RECENT_HOURS); permanent errors are critical", c.AlertRecentHours)
		},
		Fn: ruleBIMIErrorsReported,
	},
	{
		ID: "X29", Name: "bimi_evaluator_divergence",
		Description: "Evaluators disagree about one BIMI configuration within the same window.",
		Threshold: func(c config.Config) string {
			return "two evaluators reporting different error sets for one configuration"
		},
		Fn: ruleBIMIEvaluatorDivergence,
	},
}

func init() { Rules = append(Rules, BIMIReportRules...) }

// ruleBIMIErrorsReported fires when an evaluator reports an error tuple for a
// domain that has never carried that tuple before.
//
// A permanent error is critical rather than informational because of what §3.4
// permits it to mean: an evaluator that classes an error permanent MAY stop
// evaluating BIMI for every message from the domain until something changes.
// A temporary error costs one message; a permanent one can cost the domain.
func ruleBIMIErrorsReported(c *Context) ([]Alert, error) {
	tuples, err := database.ListNewBIMIErrorTuples(c.DB, c.Recent())
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, t := range tuples {
		severity := database.SeverityInfo
		note := ""
		if t.Class == "perm" {
			severity = database.SeverityCritical
			note = " — a permanent error lets an evaluator stop evaluating BIMI for this domain entirely"
		}
		key := t.Element + ":" + t.Class
		if t.Type != "" {
			key += ":" + t.Type
		}
		out = append(out, Alert{
			Domain: t.Domain, Key: key, Severity: severity,
			Message: fmt.Sprintf("%s reported a new BIMI %s error (%s) for %s: %d occurrence(s)%s",
				orUnknownOrg(t.Orgs), t.Element, describeTuple(t.Class, t.Type), t.Domain, t.Count, note),
			Payload: map[string]any{
				"element": t.Element, "class": t.Class, "type": t.Type,
				"count": t.Count, "reporters": t.Orgs,
				"description": t.Description, "first_seen": t.FirstSeen,
			},
		})
	}
	return out, nil
}

// ruleBIMIEvaluatorDivergence fires when one configuration draws different
// verdicts from different evaluators in the same window.
//
// This is the alert that tells an operator where *not* to look: where every
// evaluator agrees, the configuration is at fault and B6–B9 will say how.
// Where one refuses what the others accept, nothing in the configuration will
// change its mind.
func ruleBIMIEvaluatorDivergence(c *Context) ([]Alert, error) {
	rows, err := database.GetBIMIDivergence(c.DB, database.StatsFilter{From: c.Recent()})
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, d := range rows {
		if !d.Disagree {
			continue
		}
		var accepted, refused []string
		for _, v := range d.Verdicts {
			if len(v.Errors) == 0 {
				accepted = append(accepted, v.OrgName)
			} else {
				refused = append(refused, v.OrgName+" ("+strings.Join(v.Errors, ", ")+")")
			}
		}
		out = append(out, Alert{
			Domain: d.Domain, Key: d.Selector, Severity: database.SeverityWarning,
			Message: fmt.Sprintf("evaluators disagree about %s selector %s: %s reported no errors, %s did",
				d.Domain, d.Selector, joinOr(accepted, "nobody"), joinOr(refused, "nobody")),
			Payload: map[string]any{
				"selector": d.Selector, "l": d.LValue, "a": d.AValue,
				"clean": d.Clean, "failing": d.Failing,
			},
		})
	}
	return out, nil
}

func describeTuple(class, errType string) string {
	switch {
	case class != "" && errType != "":
		return class + "/" + errType
	case class != "":
		return class
	case errType != "":
		return errType
	}
	return "no class or type given"
}

func orUnknownOrg(orgs string) string {
	if strings.TrimSpace(orgs) == "" {
		return "a reporter"
	}
	return orgs
}

func joinOr(list []string, fallback string) string {
	if len(list) == 0 {
		return fallback
	}
	return strings.Join(list, ", ")
}

// BIMISeedRules are the rules that read verdicts observed on seed mail (X30).
var BIMISeedRules = []Rule{
	{
		ID: "X30", Name: "bimi_verdict_regression",
		Description: "A receiver that used to stamp bimi=pass on seed mail has stopped.",
		Threshold: func(c config.Config) string {
			return fmt.Sprintf("the newest verdict is not a pass and falls within %dh (ALERT_RECENT_HOURS)", c.AlertRecentHours)
		},
		Fn: ruleBIMIVerdictRegression,
	},
}

func init() { Rules = append(Rules, BIMISeedRules...) }

// ruleBIMIVerdictRegression fires when a receiver that has shown the logo
// before stops showing it.
//
// It needs a previous pass to fire at all. A receiver that has never stamped
// bimi=pass may be telling the operator something useful, but it is not
// telling them that anything changed — and an alert for it would fire on the
// day a seed mailbox is first configured, for every receiver at once.
func ruleBIMIVerdictRegression(c *Context) ([]Alert, error) {
	regressions, err := database.FindBIMIVerdictRegressions(c.DB, c.Recent())
	if err != nil {
		return nil, err
	}
	var out []Alert
	for _, r := range regressions {
		reason := ""
		if r.Comment != "" {
			reason = " — " + r.Comment
		}
		out = append(out, Alert{
			Domain: r.FromDomain, Key: r.Receiver + "|" + r.Selector,
			Severity: database.SeverityWarning,
			Message: fmt.Sprintf("%s stopped showing the logo for %s (selector %s): it now says bimi=%s%s. It last passed on %s",
				r.Receiver, r.FromDomain, r.Selector, r.Result, reason,
				time.Unix(r.LastPass, 0).UTC().Format("2006-01-02")),
			Payload: map[string]any{
				"receiver": r.Receiver, "selector": r.Selector, "result": r.Result,
				"comment": r.Comment, "last_pass": r.LastPass,
				"failures_since": r.SinceFailures,
			},
		})
	}
	return out, nil
}
