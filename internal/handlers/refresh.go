package handlers

import (
	"log"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// StartDomainCheckRefresher keeps the domain_checks cache (DMARC/BIMI/MTA-STS
// DNS presence) fresh in the background so page handlers never block on live
// DNS lookups. Runs once at startup and then every interval.
func (a *App) StartDomainCheckRefresher(interval time.Duration) {
	go func() {
		a.refreshDomainChecks()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			a.refreshDomainChecks()
		}
	}()
}

func (a *App) refreshDomainChecks() {
	domains, err := database.ListReportDomains(a.DB)
	if err != nil {
		log.Printf("domain-check refresher: list domains: %v", err)
		return
	}
	cache, err := database.GetAllDomainChecks(a.DB)
	if err != nil {
		log.Printf("domain-check refresher: load cache: %v", err)
		return
	}
	now := time.Now()
	refreshed := 0
	for _, domain := range domains {
		if dc, ok := cache[domain]; ok && dc.CheckedAt != 0 &&
			now.Sub(time.Unix(dc.CheckedAt, 0)) <= domainCheckTTL {
			continue
		}
		// The BIMI record is snapshotted rather than merely counted, so the
		// domain page and the change log stay current without the Enrich job
		// having to be run by hand.
		if summary, changes := snapshotBIMIRecords(a.DB, a.Cfg, domain); changes > 0 {
			log.Printf("domain-check refresher: %s BIMI changed — %s", domain, summary)
		}
		hasBIMI, err := database.HasBIMIRecord(a.DB, domain)
		if err != nil {
			log.Printf("domain-check refresher: bimi state %s: %v", domain, err)
		}
		dmarc := lookupDMARCRecord(domain)
		mtaSTS := lookupMTASTS(domain)
		dc := database.DomainCheck{
			Domain:       domain,
			DMARCRecord:  dmarc.Raw,
			DMARCError:   dmarc.Error,
			MTASTSRecord: mtaSTS.Raw,
			MTASTSError:  mtaSTS.Error,
			HasDMARC:     boolToInt(dmarc.Found),
			HasBIMI:      boolToInt(hasBIMI),
			HasMTASTS:    boolToInt(mtaSTS.Found),
			CheckedAt:    time.Now().Unix(),
		}
		if err := database.UpsertDomainCheck(a.DB, dc); err != nil {
			log.Printf("domain-check refresher: upsert %s: %v", domain, err)
		}
		refreshed++
		// Pace lookups so a large domain list does not hammer the resolver.
		time.Sleep(250 * time.Millisecond)
	}
	if refreshed > 0 {
		log.Printf("domain-check refresher: refreshed %d domain(s)", refreshed)
	}
}
