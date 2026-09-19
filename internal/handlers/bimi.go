package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/bimi"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/jmoiron/sqlx"
)

// snapshotBIMIRecords records the assertion record a domain publishes for every
// selector known for it, returning a one-line summary and how many records
// changed since the last run.
//
// Selectors probed: "default" always, plus every selector already in the
// inventory. Local-part selectors derived from an lps= prefix list are not
// probed — that would mean guessing local-parts and querying names no
// evaluator would ask for. The prefix list is recorded instead.
func snapshotBIMIRecords(db *sqlx.DB, cfg config.Config, domain string) (summary string, changes int) {
	// The budget covers every selector of one domain, DNS and both documents
	// included, so a slow host cannot hold up the rest of the run.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// How the organizational-domain fallback resolves the parent depends on
	// the discovery method the reporters for this domain declared.
	method, err := database.GetDiscoveryMethod(db, domain)
	if err != nil {
		log.Printf("enrich: discovery method %s: %v", domain, err)
	}

	known, err := database.ListBIMISelectors(db, domain)
	if err != nil {
		log.Printf("enrich: bimi selectors %s: %v", domain, err)
	}
	selectors := make([]string, 0, len(known))
	for _, s := range known {
		selectors = append(selectors, s.Selector)
	}

	client := &bimi.Client{Discovery: method}
	results := client.LookupAll(ctx, domain, selectors)

	var parts []string
	for _, res := range results {
		res.CheckedAt = time.Now().Unix()
		detail, err := json.Marshal(res)
		if err != nil {
			log.Printf("enrich: bimi detail %s/%s: %v", domain, res.Selector, err)
			continue
		}
		changed, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
			Domain: domain, Selector: res.Selector, Kind: database.BIMISnapshotRecord,
			Content: res.Content(), Detail: string(detail), Error: res.Error,
		})
		if err != nil {
			log.Printf("enrich: bimi snapshot %s/%s: %v", domain, res.Selector, err)
		} else if changed {
			changes++
		}

		// Only a selector that answered goes into the inventory: recording the
		// ones that did not would turn every probe into a permanent entry.
		if res.Found || res.Ambiguous() {
			if err := database.UpsertBIMISelector(db, database.BIMISelector{
				Domain: domain, Selector: res.Selector, Source: database.BIMISelectorPublished,
			}); err != nil {
				log.Printf("enrich: bimi selector %s/%s: %v", domain, res.Selector, err)
			}
		}

		line := res.Selector + ": " + bimiSummary(res)
		if v, n := validateBIMIDocuments(ctx, db, cfg, domain, res); v.Indicator != nil {
			changes += n
			line += " · " + validationSummary(v)
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, " · "), changes
}

// validateBIMIDocuments performs B6-B9 for one selector and records each
// document as its own snapshot.
//
// It returns a zero Validation when the record names nothing to fetch, or when
// active validation is switched off — which is a state an operator chooses
// (BIMI_VALIDATE=false, for a network that does not allow arbitrary outbound
// HTTPS), not a failure, so nothing is written in that case either.
func validateBIMIDocuments(ctx context.Context, db *sqlx.DB, cfg config.Config, domain string, res bimi.Result) (bimi.Validation, int) {
	if !cfg.BIMIValidate || res.State != bimi.StatePublished {
		return bimi.Validation{}, 0
	}

	roots, source, err := bimi.LoadRoots(cfg.BIMIRootsPath)
	if err != nil {
		// A misconfigured bundle must not silently become "the OS bundle will
		// do": it is louder to say so and check against nothing but the system
		// store, which the finding text then names.
		log.Printf("enrich: bimi roots: %v", err)
	}

	f := &bimi.Fetcher{
		Timeout:      cfg.BIMIFetchTimeout,
		MaxRedirects: cfg.BIMIMaxRedirects,
	}
	// The evidence document is judged against the domain the record was found
	// at, which for an inherited record is the organizational domain.
	recordDomain := res.FoundAt
	if recordDomain == "" {
		recordDomain = domain
	}
	v := bimi.Validate(ctx, f, res.Record, bimi.EvidenceOptions{
		Roots:           roots,
		RootSource:      source,
		RecordDomain:    recordDomain,
		ExpiryWarnDays:  cfg.AlertBIMIExpiryDays,
		CheckRevocation: cfg.BIMICheckRevocation,
	})

	changes := 0
	if v.Indicator != nil {
		if saveBIMIDocument(db, domain, res.Selector, database.BIMISnapshotIndicator,
			v.Indicator.SHA256, v.Indicator, firstErrorOf(v.Indicator.Findings)) {
			changes++
		}
	}
	if v.Evidence != nil {
		if saveBIMIDocument(db, domain, res.Selector, database.BIMISnapshotEvidence,
			v.Evidence.Fingerprint, v.Evidence, firstErrorOf(v.Evidence.Findings)) {
			changes++
		}
	}
	return v, changes
}

// saveBIMIDocument stores one retrieved document as a snapshot. content is the
// hash or fingerprint, so re-fetching unchanged bytes confirms the existing row
// rather than appending one.
func saveBIMIDocument(db *sqlx.DB, domain, selector, kind, content string, detail any, errMsg string) bool {
	blob, err := json.Marshal(detail)
	if err != nil {
		log.Printf("enrich: bimi %s detail %s/%s: %v", kind, domain, selector, err)
		return false
	}
	changed, err := database.UpsertBIMISnapshot(db, database.BIMISnapshot{
		Domain: domain, Selector: selector, Kind: kind,
		Content: content, Detail: string(blob), Error: errMsg,
	})
	if err != nil {
		log.Printf("enrich: bimi %s snapshot %s/%s: %v", kind, domain, selector, err)
		return false
	}
	return changed
}

func firstErrorOf(findings []bimi.Finding) string {
	for _, f := range findings {
		if f.Severity == bimi.SeverityError {
			return f.Message
		}
	}
	return ""
}

// validationSummary is the one-line account of the active checks for the
// Enrich log.
func validationSummary(v bimi.Validation) string {
	var parts []string
	switch {
	case v.Indicator == nil:
	case v.Indicator.Valid:
		parts = append(parts, "logo ok")
	default:
		parts = append(parts, "logo: "+firstErrorOf(v.Indicator.Findings))
	}
	switch {
	case v.Evidence == nil:
	case v.Evidence.Valid:
		parts = append(parts, fmt.Sprintf("evidence ok (%d days left)", v.Evidence.DaysToExpiry))
	default:
		parts = append(parts, "evidence: "+firstErrorOf(v.Evidence.Findings))
	}
	if v.Agreement.Checked && !v.Agreement.Matches {
		parts = append(parts, "the served logo is not the one in the evidence document")
	}
	if len(parts) == 0 {
		return "nothing to validate"
	}
	return strings.Join(parts, ", ")
}

// bimiSummary is the one-line account of a lookup shown in the Enrich log.
func bimiSummary(res bimi.Result) string {
	switch res.State {
	case bimi.StateError:
		return "lookup failed: " + res.Error
	case bimi.StateAbsent:
		return "no record"
	case bimi.StateDeclined:
		return "declines to publish"
	case bimi.StateInvalid:
		if res.Ambiguous() {
			return fmt.Sprintf("%d records published (must be 1)", len(res.Candidates))
		}
		return "record is not usable: " + firstProblem(res.Record)
	}
	where := ""
	if res.Fallback {
		where = " (inherited from " + res.FoundAt + ")"
	}
	if res.Record.Authority != "" {
		return "logo and evidence published" + where
	}
	return "logo published, no evidence" + where
}

func firstProblem(rec bimi.Record) string {
	for _, p := range rec.Problems {
		if p.Severity == bimi.SeverityError {
			return p.Message
		}
	}
	return "unknown defect"
}

// BIMIView is everything the domain page shows about one domain's BIMI
// configuration: the record per selector (B1, B2, B4), the selector inventory
// (B3), the change log (B5) and the policy precondition (B10).
//
// Every field comes from the database. Nothing here resolves DNS: the Enrich
// worker and the background refresher own that, so a slow or hostile resolver
// cannot hold up a page render.
type BIMIView struct {
	Domain string
	// Checked is false when this domain has never been looked up, which is a
	// different statement from "publishes nothing".
	Checked   bool
	States    []database.BIMIDomainState // current record per selector, default first
	Default   *database.BIMIDomainState
	Selectors []database.BIMISelector
	Changes   []database.BIMISnapshot
	Readiness *database.BIMIReadiness
	// Validations holds the active checks (B6–B9) per selector. A selector
	// with no entry has not been validated, which is different from having
	// been validated and found wanting.
	Validations map[string]database.BIMIValidationState
	// ValidationEnabled reports whether document fetching is switched on, so
	// the page can say "not checked because you turned it off" rather than
	// leaving a silent gap.
	ValidationEnabled bool
	// Reporting is B11–B20: what evaluators said, as opposed to what the
	// domain publishes and what its documents contain.
	Reporting *database.BIMIReportingSummary
	// Verdicts is B21: what receivers actually did with seed mail. Empty
	// unless a seed mailbox is configured, which SeedConfigured reports so the
	// page can say which of the two it is.
	Verdicts       []database.BIMIReceiverVerdict
	SeedConfigured bool
}

// buildBIMIView assembles the card. A domain with no data yields a zero view
// rather than an error, so the page renders before the first Enrich run.
func buildBIMIView(db *sqlx.DB, cfg config.Config, domain string, f database.StatsFilter) (BIMIView, error) {
	out := BIMIView{Domain: domain, ValidationEnabled: cfg.BIMIValidate}

	states, err := database.ListBIMIDomainStates(db, domain)
	if err != nil {
		return out, err
	}
	out.States = states
	out.Checked = len(states) > 0
	for i := range states {
		if states[i].Selector == bimi.DefaultSelector {
			out.Default = &states[i]
			break
		}
	}

	if out.Selectors, err = database.ListBIMISelectors(db, domain); err != nil {
		return out, err
	}
	// The change log is the point of the snapshot table; 20 entries is enough
	// to show a rotation without turning the page into a history book.
	if out.Changes, err = database.ListBIMISnapshots(db, domain, database.BIMISnapshotRecord, 20); err != nil {
		return out, err
	}
	if out.Readiness, err = database.GetBIMIReadinessFor(db, domain, f); err != nil {
		return out, err
	}

	validations, err := database.ListBIMIValidations(db, domain)
	if err != nil {
		return out, err
	}
	out.Validations = make(map[string]database.BIMIValidationState, len(validations))
	for _, v := range validations {
		out.Validations[v.Selector] = v
	}

	if out.Reporting, err = database.GetBIMIReportingSummary(db, f); err != nil {
		return out, err
	}

	seeds, err := database.CountSeedAccounts(db)
	if err != nil {
		return out, err
	}
	out.SeedConfigured = seeds > 0
	if out.Verdicts, err = database.SummariseBIMIVerdicts(db, domain, f.From); err != nil {
		return out, err
	}
	// B14 is only meaningful against what the domain publishes now, so the
	// comparison is made here rather than in SQL: the reported configuration
	// lives in the reports, the published one in the DNS snapshots.
	for i := range out.Reporting.Configs {
		c := &out.Reporting.Configs[i]
		if state, ok := publishedFor(out.States, c.Selector); ok {
			c.Matches = state.Result.Record.Location == c.LValue &&
				state.Result.Record.Authority == c.AValue
		}
	}
	return out, nil
}

// publishedFor finds the current record for one selector.
func publishedFor(states []database.BIMIDomainState, selector string) (database.BIMIDomainState, bool) {
	for _, s := range states {
		if s.Selector == selector {
			return s, true
		}
	}
	return database.BIMIDomainState{}, false
}
