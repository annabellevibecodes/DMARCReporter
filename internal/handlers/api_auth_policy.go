package handlers

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// authPayload is A1–A8 in one response.
type authPayload struct {
	Selectors        []database.DKIMSelectorStat         `json:"selectors"`          // A1
	DKIMRaw          []database.ResultCount              `json:"dkim_raw"`           // A2
	SigningAlignment *database.SigningAlignment          `json:"signing_alignment"`  // A3
	SPFRaw           []database.ResultCount              `json:"spf_raw"`            // A4
	SPFScope         []database.ResultCount              `json:"spf_scope"`          // A5
	EnvelopeFrom     []database.EnvelopeFromAlignmentRow `json:"envelope_from"`      // A6
	AlignmentGap     *database.AlignmentGap              `json:"alignment_gap"`      // A7
	DNSErrors        []database.ReporterErrorRate        `json:"dns_errors"`         // A8
	DKIMRawPassPct   float64                             `json:"dkim_raw_pass_pct"`  // convenience
	SPFRawPassPct    float64                             `json:"spf_raw_pass_pct"`   // convenience
	SPFMfromPct      float64                             `json:"spf_mfrom_pct"`      // convenience
	DNSErrorMaxRate  float64                             `json:"dns_error_max_rate"` // convenience
}

func sharePct(list []database.ResultCount, value string) float64 {
	for _, r := range list {
		if r.Value == value {
			return r.Share
		}
	}
	return 0
}

// computeAuth gathers A1–A8 for f.
func (a *App) computeAuth(f database.StatsFilter) (*authPayload, error) {
	f.Compare = false
	p := &authPayload{}
	var err error
	if p.Selectors, err = database.GetSelectorInventory(a.DB, f); err != nil {
		return nil, err
	}
	if p.DKIMRaw, err = database.GetDKIMRawResults(a.DB, f); err != nil {
		return nil, err
	}
	if p.SigningAlignment, err = database.GetDKIMSigningAlignment(a.DB, f); err != nil {
		return nil, err
	}
	if p.SPFRaw, err = database.GetSPFRawResults(a.DB, f); err != nil {
		return nil, err
	}
	if p.SPFScope, err = database.GetSPFScopeSplit(a.DB, f); err != nil {
		return nil, err
	}
	if p.EnvelopeFrom, err = database.GetEnvelopeFromAlignment(a.DB, f); err != nil {
		return nil, err
	}
	if p.AlignmentGap, err = database.GetAlignmentGap(a.DB, f, 20); err != nil {
		return nil, err
	}
	if p.DNSErrors, err = database.GetDNSErrorRate(a.DB, f); err != nil {
		return nil, err
	}
	p.DKIMRawPassPct = sharePct(p.DKIMRaw, "pass")
	p.SPFRawPassPct = sharePct(p.SPFRaw, "pass")
	p.SPFMfromPct = sharePct(p.SPFScope, "mfrom")
	for _, r := range p.DNSErrors {
		if r.Rate > p.DNSErrorMaxRate {
			p.DNSErrorMaxRate = r.Rate
		}
	}
	for _, s := range []*[]database.ResultCount{&p.DKIMRaw, &p.SPFRaw, &p.SPFScope} {
		if *s == nil {
			*s = []database.ResultCount{}
		}
	}
	if p.Selectors == nil {
		p.Selectors = []database.DKIMSelectorStat{}
	}
	if p.EnvelopeFrom == nil {
		p.EnvelopeFrom = []database.EnvelopeFromAlignmentRow{}
	}
	if p.DNSErrors == nil {
		p.DNSErrors = []database.ReporterErrorRate{}
	}
	return p, nil
}

// HandleAPIAuth serves /api/auth.
func (a *App) HandleAPIAuth(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	cmp, err := database.WithComparison(f, func(sf database.StatsFilter) (*authPayload, error) {
		return a.computeAuth(sf)
	})
	if err != nil {
		return err
	}
	var prev *authPayload
	if cmp.Previous != nil {
		prev = *cmp.Previous
	}
	return c.JSON(fiber.Map{
		"window":   windowFor(f, c.Query("period")),
		"current":  cmp.Current,
		"previous": prev,
	})
}

// policyPayload is P1–P6 in one response.
type policyPayload struct {
	Active      *database.ActivePolicy         `json:"active"`      // P1
	Consistency []database.PolicyTupleSeen     `json:"consistency"` // P2
	ChangeLog   []database.PolicyChange        `json:"change_log"`  // P3 (domain-scoped only)
	Subdomains  []database.SubdomainTrafficRow `json:"subdomains"`  // P4
	Sampling    *database.PctSampling          `json:"sampling"`    // P5
	Readiness   *database.EnforcementReadiness `json:"readiness"`   // P6
	Domain      string                         `json:"domain"`
}

// computePolicy gathers P1–P6 for f. The change log needs a single domain.
func (a *App) computePolicy(f database.StatsFilter) (*policyPayload, error) {
	f.Compare = false
	p := &policyPayload{Domain: f.Domain}
	var err error
	if p.Active, err = database.GetActivePolicyTuple(a.DB, f); err != nil {
		return nil, err
	}
	if p.Consistency, err = database.GetPolicyConsistency(a.DB, f); err != nil {
		return nil, err
	}
	if f.Domain != "" {
		if p.ChangeLog, err = database.GetPolicyChangeLog(a.DB, f.Domain, 50); err != nil {
			return nil, err
		}
	}
	if p.Subdomains, err = database.GetSubdomainTraffic(a.DB, f); err != nil {
		return nil, err
	}
	if p.Sampling, err = database.GetPctSampling(a.DB, f); err != nil {
		return nil, err
	}
	if p.Readiness, err = database.GetEnforcementReadiness(a.DB, f); err != nil {
		return nil, err
	}
	if p.Consistency == nil {
		p.Consistency = []database.PolicyTupleSeen{}
	}
	if p.ChangeLog == nil {
		p.ChangeLog = []database.PolicyChange{}
	}
	if p.Subdomains == nil {
		p.Subdomains = []database.SubdomainTrafficRow{}
	}
	return p, nil
}

// HandleAPIPolicy serves /api/policy.
func (a *App) HandleAPIPolicy(c *fiber.Ctx) error {
	f, err := apiStatsFilter(c)
	if err != nil {
		return err
	}
	p, err := a.computePolicy(f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window": windowFor(f, c.Query("period")),
		"policy": p,
	})
}

// HandleAPISelectorExpected handles POST /api/selectors/expected
// {domain, selector, expected} (form-encoded, CSRF). expected: 1, 0 or -1.
func (a *App) HandleAPISelectorExpected(c *fiber.Ctx) error {
	// Domain and selector keep the reporter's original case: the inventory is
	// keyed exactly as dkim_results stores them.
	domain := strings.TrimSpace(c.FormValue("domain"))
	selector := strings.TrimSpace(c.FormValue("selector"))
	if domain == "" || len(domain) > 253 || !domainRe.MatchString(domain) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid domain")
	}
	if selector == "" || len(selector) > 253 || strings.ContainsAny(selector, " \t\n\r<>\"'") {
		return fiber.NewError(fiber.StatusBadRequest, "invalid selector")
	}
	expected, err := strconv.Atoi(c.FormValue("expected", "-1"))
	if err != nil || expected < -1 || expected > 1 {
		return fiber.NewError(fiber.StatusBadRequest, "expected must be -1, 0 or 1")
	}
	if err := database.SetSelectorExpected(a.DB, domain, selector, expected); err != nil {
		return err
	}
	if redirect := c.FormValue("redirect"); safeRedirect(redirect) {
		a.setFlash(c, "success", "Selector "+selector+" ("+domain+") updated.")
		return c.Redirect(redirect, fiber.StatusSeeOther)
	}
	return c.JSON(fiber.Map{"domain": domain, "selector": selector, "expected": expected})
}
