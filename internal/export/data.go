package export

import (
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/jmoiron/sqlx"
)

// recordLimit caps the per-domain record listing in exports.
const recordLimit = 1000

// ReportData holds everything needed to render a management report.
type ReportData struct {
	GeneratedAt time.Time
	Domain      string // empty = all-domains report
	PeriodLabel string // human-readable reporting period ("1 Year", "All Time", …)
	Summary     Summary
	Domains     []database.DomainStat      // all domains, or one entry for per-domain
	TopSources  []database.FailureRateStat // top 10 failing source IPs
	Records     []database.DomainRecord    // per-domain only: recent records
	RecordLimit int                        // cap applied to Records
}

// Summary holds top-level aggregate numbers.
type Summary struct {
	TotalMessages int64
	TotalPassed   int64
	TotalFailed   int64
	PassRate      float64
	DomainCount   int
}

// Fetch loads report data from the database, scoped to the same period and
// domain filters the UI uses so the exported report matches what is on screen.
func Fetch(db *sqlx.DB, domain string, from, to int64, periodLabel string) (*ReportData, error) {
	rd := &ReportData{
		GeneratedAt: time.Now().UTC(),
		Domain:      domain,
		PeriodLabel: periodLabel,
		RecordLimit: recordLimit,
	}

	f := database.StatsFilter{Domain: domain, From: from, To: to}
	domains, err := database.ListDomainsFiltered(db, f)
	if err != nil {
		return nil, err
	}
	rd.Domains = domains
	rd.Summary.DomainCount = len(domains)
	for _, d := range domains {
		rd.Summary.TotalMessages += d.TotalMessages
		rd.Summary.TotalPassed += d.Passed
		rd.Summary.TotalFailed += d.Failed
	}

	if domain != "" {
		records, err := database.GetDomainRecords(db, domain, from, recordLimit)
		if err != nil {
			return nil, err
		}
		rd.Records = records
	}

	if rd.Summary.TotalMessages > 0 {
		rd.Summary.PassRate = float64(rd.Summary.TotalPassed) / float64(rd.Summary.TotalMessages) * 100
	}

	sources, err := database.GetTopFailingSources(db, 1, 10, f)
	if err != nil {
		return nil, err
	}
	rd.TopSources = sources

	return rd, nil
}
