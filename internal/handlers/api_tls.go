package handlers

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// tlsResultTypeRe bounds the result_type filter. Values are stored verbatim,
// including ones outside the IANA registry, but they are always of this shape.
var tlsResultTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)

func timeNowUTC() time.Time { return time.Now().UTC() }

// tlsWindowPayload is windowPayload for a TLS filter, which has its own type.
type tlsWindowPayload struct {
	From     int64  `json:"from"`
	To       int64  `json:"to"`
	Label    string `json:"label,omitempty"`
	Previous *struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"previous,omitempty"`
	// RequireDKIM says whether RFC 8460 §3 exclusion was applied to these
	// figures, so a consumer can tell a quiet period from a filtered one.
	RequireDKIM bool `json:"require_dkim"`
}

func tlsWindowFor(f database.TLSFilter, label string) tlsWindowPayload {
	w := tlsWindowPayload{From: f.From, To: f.To, Label: label, RequireDKIM: f.RequireDKIM}
	if f.Compare {
		if prev, ok := f.PreviousWindow(); ok {
			w.Previous = &struct {
				From int64 `json:"from"`
				To   int64 `json:"to"`
			}{prev.From, prev.To}
		}
	}
	return w
}

// apiTLSFilter builds a TLS filter from the query string, honouring the same
// period / domain / compare parameters as the rest of the API plus the
// failure-level drill-downs.
func (a *App) apiTLSFilter(c *fiber.Ctx) (database.TLSFilter, error) {
	f := database.TLSFilter{
		Compare:     c.Query("compare") == "1",
		RequireDKIM: a.Cfg.TLSRPTRequireDKIM,
	}
	if domain := strings.ToLower(strings.TrimSpace(c.Query("domain"))); domain != "" {
		if len(domain) > 253 || !domainRe.MatchString(domain) {
			return f, fiber.ErrBadRequest
		}
		f.Domain = domain
	}
	if mx := strings.ToLower(strings.TrimSpace(c.Query("mx"))); mx != "" {
		if len(mx) > 253 || !domainRe.MatchString(mx) {
			return f, fiber.ErrBadRequest
		}
		f.MXHostname = mx
	}
	if rip := strings.TrimSpace(c.Query("receiving_ip")); rip != "" {
		if net.ParseIP(rip) == nil {
			return f, fiber.ErrBadRequest
		}
		// Match what was stored: addresses are canonicalised on import.
		f.ReceivingIP = net.ParseIP(rip).String()
	}
	if sip := strings.TrimSpace(c.Query("sending_ip")); sip != "" {
		if net.ParseIP(sip) == nil {
			return f, fiber.ErrBadRequest
		}
		f.SendingIP = net.ParseIP(sip).String()
	}
	if rt := strings.ToLower(strings.TrimSpace(c.Query("result_type"))); rt != "" {
		if len(rt) > 128 || !tlsResultTypeRe.MatchString(rt) {
			return f, fiber.ErrBadRequest
		}
		f.ResultType = rt
	}

	period := c.Query("period")
	if period == "" {
		period = "30d"
	}
	f.From, f.To, _ = parsePeriod(period)
	return f, nil
}

// HandleAPITLS serves T1–T15 for the window, with the previous window when
// compare=1.
func (a *App) HandleAPITLS(c *fiber.Ctx) error {
	f, err := a.apiTLSFilter(c)
	if err != nil {
		return err
	}
	cmp, err := database.TLSWithComparison(f, func(sf database.TLSFilter) (*tlsPayload, error) {
		// The payload computes its own comparison for the headline rate;
		// inside the comparison run there is nothing further to compare.
		sf.Compare = false
		return a.computeTLS(sf)
	})
	if err != nil {
		return err
	}
	var prev *tlsPayload
	if cmp.Previous != nil {
		prev = *cmp.Previous
	}
	return c.JSON(fiber.Map{
		"window":   tlsWindowFor(f, c.Query("period")),
		"current":  cmp.Current,
		"previous": prev,
	})
}

// HandleAPITLSFailures serves the failure-detail views (T4–T7, T10, T11, T14),
// filterable by result type, MX host, receiving IP and sending IP.
func (a *App) HandleAPITLSFailures(c *fiber.Ctx) error {
	f, err := a.apiTLSFilter(c)
	if err != nil {
		return err
	}
	breakdown, err := database.GetTLSFailureBreakdown(a.DB, f)
	if err != nil {
		return err
	}
	receivers, err := database.GetTLSReceivers(a.DB, f, 200)
	if err != nil {
		return err
	}
	senders, err := database.GetTLSSenders(a.DB, f, 200)
	if err != nil {
		return err
	}
	reasons, err := database.GetTLSReasons(a.DB, f, 100)
	if err != nil {
		return err
	}
	family, err := database.GetTLSFamilySplit(a.DB, f)
	if err != nil {
		return err
	}
	endpoint, err := database.GetTLSEndpointHealth(a.DB, f)
	if err != nil {
		return err
	}
	dane, err := database.GetTLSDaneHealth(a.DB, f)
	if err != nil {
		return err
	}
	incidents, err := database.GetTLSIncidents(a.DB, f, timeNowUTC())
	if err != nil {
		return err
	}

	return c.JSON(fiber.Map{
		"window": tlsWindowFor(f, c.Query("period")),
		"filters": fiber.Map{
			"result_type":  f.ResultType,
			"mx":           f.MXHostname,
			"receiving_ip": f.ReceivingIP,
			"sending_ip":   f.SendingIP,
		},
		"by_result_type": breakdown, // T4
		"receivers":      receivers, // T5
		"senders":        senders,   // T6
		"reasons":        reasons,   // T7
		"endpoint":       endpoint,  // T10
		"dane":           dane,      // T11
		"family":         family,    // T14
		"incidents":      incidents, // T15
		// Failure rows count one session once per result type it hit, so
		// these totals are observations and can exceed the session failures
		// reported by the policy summaries.
		"note": "failure counts are observations, not distinct sessions (RFC 8460 result types are non-exclusive)",
	})
}

// HandleAPITLSPolicies serves the policy views: the type mix (T3), MTA-STS
// mode and readiness (T9), and the same-day divergence check (T8).
func (a *App) HandleAPITLSPolicies(c *fiber.Ctx) error {
	f, err := a.apiTLSFilter(c)
	if err != nil {
		return err
	}
	mix, err := database.GetTLSPolicyMix(a.DB, f)
	if err != nil {
		return err
	}
	readiness, err := database.GetTLSEnforcementReadiness(a.DB, f)
	if err != nil {
		return err
	}
	divergence, err := database.GetTLSPolicyDivergence(a.DB, f)
	if err != nil {
		return err
	}
	if divergence == nil {
		divergence = []database.TLSPolicyDivergence{}
	}
	drift, err := database.GetTLSPolicyDrift(a.DB, f)
	if err != nil {
		return err
	}
	if drift == nil {
		drift = []database.TLSDrift{}
	}
	snapshots, err := database.ListCurrentTLSSnapshots(a.DB, database.TLSSnapshotMTASTS)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window":     tlsWindowFor(f, c.Query("period")),
		"mix":        mix,        // T3
		"readiness":  readiness,  // T9
		"divergence": divergence, // T8, from reports alone
		"drift":      drift,      // T8, reported versus published
		"published":  snapshots,  // the current MTA-STS snapshot per domain
		"note":       "drift compares reports against the newest snapshot, so a difference may be a policy change made after the report's window rather than a fault",
	})
}

// HandleAPITLSReporters serves who is reporting and how completely (T2, T12).
func (a *App) HandleAPITLSReporters(c *fiber.Ctx) error {
	f, err := a.apiTLSFilter(c)
	if err != nil {
		return err
	}
	volume, err := database.GetTLSVolume(a.DB, f)
	if err != nil {
		return err
	}
	gapDays := a.Cfg.AlertReporterGapDays
	if gapDays <= 0 {
		gapDays = 3
	}
	coverage, err := database.GetTLSCoverage(a.DB, f, gapDays, timeNowUTC())
	if err != nil {
		return err
	}
	hygiene, err := database.GetTLSHygiene(a.DB, f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window":   tlsWindowFor(f, c.Query("period")),
		"volume":   volume,   // T2
		"coverage": coverage, // T12
		"hygiene":  hygiene,  // T13
		"gap_days": gapDays,
	})
}
