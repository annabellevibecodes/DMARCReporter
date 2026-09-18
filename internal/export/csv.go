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

	// ---- Analytics sections (appended; earlier sections keep their column order) ----
	matrix, enforcement := analyticsKV(rd)
	if len(matrix) > 0 {
		blank()
		write("Authentication Matrix")
		for _, kv := range matrix {
			write(kv[0], kv[1])
		}
	}
	if len(enforcement) > 0 {
		blank()
		write("Enforcement Effectiveness")
		for _, kv := range enforcement {
			write(kv[0], kv[1])
		}
	}
	if len(rd.PolicyTags) > 0 {
		blank()
		write("Published Policy")
		write("Record", escapeFormula(joinStrings(rd.PolicyTags, " ")))
	}
	if len(rd.DomainPolicies) > 0 {
		blank()
		write("Published Policy by Domain")
		write("Domain", "Effective Record")
		for _, d := range rd.DomainPolicies {
			write(escapeFormula(d.Domain), escapeFormula(joinStrings(d.Tags, " ")))
		}
	}
	if rows := changeLogRows(rd); len(rows) > 0 {
		blank()
		write("Policy Change Log")
		write(changeLogHeaders...)
		for _, r := range rows {
			write(escapeRow(r)...)
		}
	}
	if rows := newSourceRows(rd); len(rows) > 0 {
		blank()
		write("New Sources This Period")
		write(newSourceHeaders...)
		for _, r := range rows {
			write(escapeRow(r)...)
		}
	}
	// SMTP TLS reporting.
	blank()
	write("SMTP TLS Reporting (RFC 8460)")
	if kv := tlsSummaryKV(rd); len(kv) > 0 {
		for _, row := range kv {
			write(escapeFormula(row[0]), escapeFormula(row[1]))
		}
		if rows := tlsPolicyRows(rd); len(rows) > 0 {
			blank()
			write("TLS Policy Applied")
			write(tlsPolicyHeaders...)
			for _, r := range rows {
				write(escapeRow(r)...)
			}
		}
		if rows := tlsFailureRows(rd); len(rows) > 0 {
			blank()
			write("TLS Failures by Result Type")
			write(tlsFailureHeaders...)
			for _, r := range rows {
				write(escapeRow(r)...)
			}
		}
		if rows := tlsReceiverRows(rd); len(rows) > 0 {
			blank()
			write("TLS Top Failing Receivers")
			write(tlsReceiverHeaders...)
			for _, r := range rows {
				write(escapeRow(r)...)
			}
		}
		if rows := tlsAlertRows(rd); len(rows) > 0 {
			blank()
			write("Open TLS Alerts")
			write(tlsAlertHeaders...)
			for _, r := range rows {
				write(escapeRow(r)...)
			}
		}
	} else {
		write("No TLS reports for this period")
	}

	if rows := alertRows(rd); len(rows) > 0 {
		blank()
		write("Open Alerts")
		write(alertHeaders...)
		for _, r := range rows {
			write(escapeRow(r)...)
		}
	}

	cw.Flush()
	return cw.Error()
}

// escapeRow applies escapeFormula to every cell.
func escapeRow(row []string) []string {
	out := make([]string, len(row))
	for i, c := range row {
		out[i] = escapeFormula(c)
	}
	return out
}
