package handlers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// bimiPayload is the cross-domain BIMI view: every domain's configuration in
// one place, which the per-domain card cannot show.
type bimiPayload struct {
	// Readiness is the four-state breakdown the dashboard card draws (B10).
	Readiness *database.BIMIReadinessBreakdown `json:"readiness"`
	// Domains is every domain's current default-selector record (B1, B2, B4),
	// with its policy verdict and document checks beside it.
	Domains []bimiDomainRow `json:"domains"`
	// Selectors is the inventory across all domains (B3).
	Selectors []database.BIMISelector `json:"selectors"`
	// Changes is the recent change log across all domains (B5).
	Changes []database.BIMISnapshot `json:"changes,omitempty"`
	// Reporting is B11–B20 over the selected window.
	Reporting *database.BIMIReportingSummary `json:"reporting"`
	// Verdicts is B21, empty unless a seed mailbox is configured.
	Verdicts       []database.BIMIReceiverVerdict `json:"verdicts,omitempty"`
	SeedConfigured bool                           `json:"seed_configured"`
	// ValidationEnabled reports whether the document checks run at all, so an
	// empty B6–B9 column can say which of the two it is.
	ValidationEnabled bool `json:"validation_enabled"`
}

// bimiDomainRow is one domain's line on the cross-domain page.
type bimiDomainRow struct {
	Domain string `json:"domain"`
	// State is the record state: published, declined, invalid, absent, error.
	State string `json:"state"`
	// Checked is false when the domain has never been looked up, which is not
	// the same as publishing nothing.
	Checked   bool   `json:"checked"`
	Selector  string `json:"selector"`
	Location  string `json:"l,omitempty"`
	Authority string `json:"a,omitempty"`
	// FoundAt names the domain the record came from when it was inherited.
	FoundAt  string `json:"found_at,omitempty"`
	Fallback bool   `json:"fallback"`
	// Eligible and Known are B10 for the domain over the selected window.
	Eligible bool     `json:"eligible"`
	Known    bool     `json:"known"`
	Blockers []string `json:"blockers,omitempty"`
	// Validated is true when the documents have been checked; Valid is their
	// verdict. Both false means "not checked", not "failed".
	Validated   bool     `json:"validated"`
	Valid       bool     `json:"valid"`
	Findings    []string `json:"findings,omitempty"`
	ExpiryDays  int      `json:"expiry_days,omitempty"`
	HasEvidence bool     `json:"has_evidence"`
	// Agreement is B9: "", "agrees", "disagrees" or "not applicable".
	Agreement string `json:"agreement,omitempty"`
	Messages  int64  `json:"messages"`
}

// computeBIMI assembles the cross-domain view.
func (a *App) computeBIMI(f database.StatsFilter) (*bimiPayload, error) {
	out := &bimiPayload{ValidationEnabled: a.Cfg.BIMIValidate}
	var err error

	if out.Readiness, err = database.GetBIMIReadinessBreakdown(a.DB, f); err != nil {
		return nil, err
	}
	if out.Selectors, err = database.ListBIMISelectors(a.DB, f.Domain); err != nil {
		return nil, err
	}
	if out.Changes, err = database.ListBIMISnapshots(a.DB, f.Domain, database.BIMISnapshotRecord, 25); err != nil {
		return nil, err
	}
	if out.Reporting, err = database.GetBIMIReportingSummary(a.DB, f); err != nil {
		return nil, err
	}
	seeds, err := database.CountSeedAccounts(a.DB)
	if err != nil {
		return nil, err
	}
	out.SeedConfigured = seeds > 0
	if out.Verdicts, err = database.SummariseBIMIVerdicts(a.DB, f.Domain, f.From); err != nil {
		return nil, err
	}

	readiness, err := database.GetBIMIReadiness(a.DB, f)
	if err != nil {
		return nil, err
	}
	byDomain := make(map[string]database.BIMIReadiness, len(readiness))
	for _, r := range readiness {
		byDomain[r.Domain] = r
	}
	states, err := database.ListBIMIDomainStates(a.DB, f.Domain)
	if err != nil {
		return nil, err
	}
	stateByDomain := map[string]database.BIMIDomainState{}
	for _, s := range states {
		if s.Selector == bimi.DefaultSelector {
			stateByDomain[s.Domain] = s
		}
	}
	validations, err := database.ListBIMIValidations(a.DB, f.Domain)
	if err != nil {
		return nil, err
	}
	validationByDomain := map[string]database.BIMIValidationState{}
	for _, v := range validations {
		if v.Selector == bimi.DefaultSelector {
			validationByDomain[v.Domain] = v
		}
	}

	// Every domain reports name, plus every managed domain: a domain that
	// sends no mail yet can still have a logo configured, and that is exactly
	// the setup someone opening this page is likely to be checking.
	domains, err := database.ListBIMIScopeDomains(a.DB, f)
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		if f.Domain != "" && d.Domain != f.Domain {
			continue
		}
		row := bimiDomainRow{
			Domain:   d.Domain,
			Selector: bimi.DefaultSelector,
			State:    bimi.StateAbsent,
			Messages: d.Messages,
		}
		if r, ok := byDomain[d.Domain]; ok {
			row.Known, row.Eligible, row.Blockers = r.Known, r.Eligible, r.Blockers
		}
		if s, ok := stateByDomain[d.Domain]; ok {
			row.Checked = true
			row.State = s.State
			row.Location = s.Result.Record.Location
			row.Authority = s.Result.Record.Authority
			row.FoundAt, row.Fallback = s.Result.FoundAt, s.Result.Fallback
			row.HasEvidence = s.Result.Record.Authority != ""
		}
		if v, ok := validationByDomain[d.Domain]; ok && v.Checked() {
			row.Validated = true
			row.Valid = v.Valid()
			for _, fnd := range v.Findings() {
				if fnd.Severity == bimi.SeverityError {
					row.Findings = append(row.Findings, fnd.Code)
				}
			}
			if v.Evidence != nil {
				row.ExpiryDays = v.Evidence.DaysToExpiry
			}
			switch {
			case !v.Agreement.Checked:
				row.Agreement = "not applicable"
			case v.Agreement.Matches:
				row.Agreement = "agrees"
			default:
				row.Agreement = "disagrees"
			}
		}
		out.Domains = append(out.Domains, row)
	}
	return out, nil
}

// HandleBIMIPage renders /bimi: the cross-domain brand-indicator view.
func (a *App) HandleBIMIPage(c *fiber.Ctx) error {
	period := c.Query("period", "30d")
	from, to, periodLabel := parsePeriod(period)
	domain := c.Query("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	f := database.StatsFilter{Domain: domain, From: from, To: to}

	payload, err := a.computeBIMI(f)
	if err != nil {
		return err
	}
	domains, err := database.ListReportDomains(a.DB)
	if err != nil {
		return err
	}

	flashKind, flashMsg := getFlash(c)
	return c.Render("bimi", fiber.Map{
		"Title":          "BIMI — DMARC Reporter",
		"Theme":          getTheme(c),
		"ActivePage":     "bimi",
		"BIMI":           payload,
		"Domains":        domains,
		"SelectedDomain": domain,
		"PeriodOptions":  periodOptions,
		"SelectedPeriod": period,
		"PeriodLabel":    periodLabel,
		"CurrentPath":    currentPath(c),
		"IMAPEnabled":    a.FetchEnabled(),
		"FlashKind":      flashKind,
		"FlashMsg":       flashMsg,
		"CSRFToken":      c.Locals("csrf"),
	}, "layouts/base")
}

// HandleAPIBIMI serves /api/bimi: B1–B21 in one payload.
//
// It honours the same period and domain filters as the rest of the API. The
// envelope-from filter is accepted and deliberately ignored for the report
// series: BIMI data hangs off the report, not off a record row, so there is no
// envelope sender to filter it by — see database.bimiWhere.
func (a *App) HandleAPIBIMI(c *fiber.Ctx) error {
	period := c.Query("period", "30d")
	from, to, _ := parsePeriod(period)
	domain := c.Query("domain")
	if domain != "" && (len(domain) > 253 || !domainRe.MatchString(domain)) {
		return fiber.ErrBadRequest
	}
	f := database.StatsFilter{
		Domain:       domain,
		EnvelopeFrom: c.Query("ef"),
		From:         from,
		To:           to,
	}
	payload, err := a.computeBIMI(f)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"window": fiber.Map{
			"period": period,
			"from":   from,
			"to":     f.WindowEnd(),
			"domain": domain,
		},
		"bimi": payload,
	})
}
