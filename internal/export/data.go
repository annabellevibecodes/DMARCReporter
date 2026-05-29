package export

import (
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/jmoiron/sqlx"
)

// ReportData holds everything needed to render a management report.
type ReportData struct {
	GeneratedAt time.Time
	Domain      string // empty = all-domains report
	Summary     Summary
	Domains     []database.DomainStat      // all domains, or one entry for per-domain
	TopSources  []database.FailureRateStat // top 10 failing source IPs
	Records     []database.DomainRecord    // per-domain only: recent records
}

// Summary holds top-level aggregate numbers.
type Summary struct {
	TotalMessages int64
	TotalPassed   int64
	TotalFailed   int64
	PassRate      float64
	DomainCount   int
}

// Fetch loads report data from the database.
func Fetch(db *sqlx.DB, domain string) (*ReportData, error) {
	rd := &ReportData{
		GeneratedAt: time.Now().UTC(),
		Domain:      domain,
	}

	allDomains, err := database.ListDomains(db)
	if err != nil {
		return nil, err
	}

	if domain == "" {
		rd.Domains = allDomains
		rd.Summary.DomainCount = len(allDomains)
		for _, d := range allDomains {
			rd.Summary.TotalMessages += d.TotalMessages
			rd.Summary.TotalPassed += d.Passed
			rd.Summary.TotalFailed += d.Failed
		}
	} else {
		for _, d := range allDomains {
			if d.Domain == domain {
				rd.Domains = []database.DomainStat{d}
				rd.Summary.TotalMessages = d.TotalMessages
				rd.Summary.TotalPassed = d.Passed
				rd.Summary.TotalFailed = d.Failed
				rd.Summary.DomainCount = 1
				break
			}
		}
		records, err := database.GetDomainRecords(db, domain, 0, 100)
		if err != nil {
			return nil, err
		}
		rd.Records = records
	}

	if rd.Summary.TotalMessages > 0 {
		rd.Summary.PassRate = float64(rd.Summary.TotalPassed) / float64(rd.Summary.TotalMessages) * 100
	}

	sources, err := database.GetTopFailingSources(db, 1, 10, database.StatsFilter{Domain: domain})
	if err != nil {
		return nil, err
	}
	rd.TopSources = sources

	return rd, nil
}
