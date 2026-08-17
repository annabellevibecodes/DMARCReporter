package export

import (
	"encoding/csv"
	"fmt"
	"io"
	"time"
)

// WriteCSV writes the report as CSV to w.
func WriteCSV(w io.Writer, rd *ReportData) error {
	cw := csv.NewWriter(w)

	write := func(row ...string) {
		cw.Write(row) //nolint:errcheck
	}
	blank := func() { write() }

	title := "DMARC Management Report — All Domains"
	if rd.Domain != "" {
		title = "DMARC Management Report — " + rd.Domain
	}
	write(title)
	write("Generated", rd.GeneratedAt.Format(time.RFC3339))
	if rd.PeriodLabel != "" {
		write("Period", rd.PeriodLabel)
	}
	blank()

	// Summary
	write("Summary")
	write("Total Messages", fmt.Sprintf("%d", rd.Summary.TotalMessages))
	write("Passed", fmt.Sprintf("%d", rd.Summary.TotalPassed))
	write("Failed", fmt.Sprintf("%d", rd.Summary.TotalFailed))
	write("Pass Rate", fmt.Sprintf("%.1f%%", rd.Summary.PassRate))
	if rd.Domain == "" {
		write("Domains", fmt.Sprintf("%d", rd.Summary.DomainCount))
	}
	blank()

	// Domain breakdown
	write("Domain Breakdown")
	write("Domain", "Reports", "Messages", "Passed", "Failed", "Pass Rate")
	for _, d := range rd.Domains {
		write(
			escapeFormula(d.Domain),
			fmt.Sprintf("%d", d.ReportCount),
			fmt.Sprintf("%d", d.TotalMessages),
			fmt.Sprintf("%d", d.Passed),
			fmt.Sprintf("%d", d.Failed),
			fmt.Sprintf("%.1f%%", d.PassRate),
		)
	}
	blank()

	// Per-domain records
	if rd.Domain != "" && len(rd.Records) > 0 {
		write(fmt.Sprintf("Recent Records (last %d)", rd.RecordLimit))
		write("Source IP", "Count", "Disposition", "DKIM", "SPF", "Envelope To", "Reporter", "Period Begin", "Period End")
		for _, r := range rd.Records {
			write(
				escapeFormula(r.SourceIP),
				fmt.Sprintf("%d", r.Count),
				escapeFormula(r.Disposition),
				escapeFormula(r.EvalDKIM),
				escapeFormula(r.EvalSPF),
				escapeFormula(r.EnvelopeTo),
				escapeFormula(r.OrgName),
				time.Unix(r.DateRangeBegin, 0).UTC().Format("2006-01-02"),
				time.Unix(r.DateRangeEnd, 0).UTC().Format("2006-01-02"),
			)
		}
		blank()
	}

	// Top failing sources
	if len(rd.TopSources) > 0 {
		write("Top Failing Source IPs")
		write("Source IP", "Messages", "Failed", "Fail Rate")
		for _, s := range rd.TopSources {
			write(
				escapeFormula(s.SourceIP),
				fmt.Sprintf("%d", s.TotalMessages),
				fmt.Sprintf("%d", s.Failed),
				fmt.Sprintf("%.1f%%", s.FailRate*100),
			)
		}
	}

	cw.Flush()
	return cw.Error()
}
