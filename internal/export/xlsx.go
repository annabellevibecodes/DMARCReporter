package export

import (
	"fmt"
	"io"
	"time"

	"github.com/xuri/excelize/v2"
)

// WriteXLSX writes the report as an Excel workbook to w.
func WriteXLSX(w io.Writer, rd *ReportData) error {
	f := excelize.NewFile()
	defer f.Close()

	// Styles
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true, Color: "FFFFFF", Size: 10},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"0E2A4A"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center", WrapText: true},
	})
	subHeaderStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 10},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"D9E1F2"}, Pattern: 1},
	})
	boldStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 10},
	})
	passStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Color: "1A7F37"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"DCFCE7"}, Pattern: 1},
	})
	failStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Color: "B91C1C"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"FEE2E2"}, Pattern: 1},
	})
	_ = passStyle
	_ = failStyle

	writeSummarySheet(f, rd, headerStyle, subHeaderStyle, boldStyle)

	if rd.Domain == "" {
		writeDomainsSheet(f, rd, headerStyle)
	} else {
		writeRecordsSheet(f, rd, headerStyle)
	}

	if len(rd.TopSources) > 0 {
		writeSourcesSheet(f, rd, headerStyle)
	}
	writeAnalyticsSheet(f, rd, headerStyle, subHeaderStyle)

	// Remove the default blank Sheet1 if we renamed it
	return f.Write(w)
}

// writeAnalyticsSheet adds the matrix, enforcement, policy, new-source and
// open-alert sections on one "Analytics" sheet.
func writeAnalyticsSheet(f *excelize.File, rd *ReportData, headerStyle, subHeaderStyle int) {
	const sh = "Analytics"
	f.NewSheet(sh)
	row := 1
	section := func(title string) {
		f.SetCellValue(sh, cell(1, row), title)
		f.SetCellStyle(sh, cell(1, row), cell(1, row), subHeaderStyle)
		row++
	}
	kv := func(rows [][2]string) {
		for _, r := range rows {
			f.SetCellValue(sh, cell(1, row), r[0])
			f.SetCellValue(sh, cell(2, row), escapeFormula(r[1]))
			row++
		}
		row++
	}
	table := func(headers []string, rows [][]string) {
		for i, h := range headers {
			f.SetCellValue(sh, cell(i+1, row), h)
		}
		f.SetCellStyle(sh, cell(1, row), cell(len(headers), row), headerStyle)
		row++
		for _, r := range rows {
			for i, c := range r {
				f.SetCellValue(sh, cell(i+1, row), escapeFormula(c))
			}
			row++
		}
		row++
	}

	matrix, enforcement := analyticsKV(rd)
	if len(matrix) > 0 {
		section("Authentication Matrix")
		kv(matrix)
	}
	if len(enforcement) > 0 {
		section("Enforcement Effectiveness")
		kv(enforcement)
	}
	if len(rd.PolicyTags) > 0 {
		section("Published Policy")
		kv([][2]string{{"Record", joinStrings(rd.PolicyTags, " ")}})
	}
	if len(rd.DomainPolicies) > 0 {
		section("Published Policy by Domain")
		rows := make([][]string, len(rd.DomainPolicies))
		for i, d := range rd.DomainPolicies {
			rows[i] = []string{d.Domain, joinStrings(d.Tags, " ")}
		}
		table([]string{"Domain", "Effective Record"}, rows)
	}
	if rows := changeLogRows(rd); len(rows) > 0 {
		section("Policy Change Log")
		table(changeLogHeaders, rows)
	}
	if rows := newSourceRows(rd); len(rows) > 0 {
		section("New Sources This Period")
		table(newSourceHeaders, rows)
	}
	section("SMTP TLS Reporting (RFC 8460)")
	if kvRows := tlsSummaryKV(rd); len(kvRows) > 0 {
		kv(kvRows)
		if rows := tlsPolicyRows(rd); len(rows) > 0 {
			section("TLS Policy Applied")
			table(tlsPolicyHeaders, rows)
		}
		if rows := tlsFailureRows(rd); len(rows) > 0 {
			section("TLS Failures by Result Type")
			table(tlsFailureHeaders, rows)
		}
		if rows := tlsReceiverRows(rd); len(rows) > 0 {
			section("TLS Top Failing Receivers")
			table(tlsReceiverHeaders, rows)
		}
		if rows := tlsAlertRows(rd); len(rows) > 0 {
			section("Open TLS Alerts")
			table(tlsAlertHeaders, rows)
		}
	} else {
		kv([][2]string{{"TLS reports", "none for this period"}})
	}

	section("BIMI (Brand Indicators)")
	if kvRows := bimiSummaryKV(rd); len(kvRows) > 0 {
		kv(kvRows)
	}
	if rows := bimiDomainRows(rd); len(rows) > 0 {
		section("BIMI Configuration by Domain")
		table(bimiDomainHeaders, rows)
	}
	if rows := bimiErrorRows(rd); len(rows) > 0 {
		section("BIMI Errors Reported by Evaluators")
		table(bimiErrorHeaders, rows)
	}
	if rows := bimiVerdictRows(rd); len(rows) > 0 {
		section("BIMI Verdicts on Seed Mail")
		table(bimiVerdictHeaders, rows)
	}

	if rows := alertRows(rd); len(rows) > 0 {
		section("Open Alerts")
		table(alertHeaders, rows)
	}
	f.SetColWidth(sh, "A", "A", 34)
	f.SetColWidth(sh, "B", "G", 22)
}

func setCellStr(f *excelize.File, sheet, cell, val string) {
	f.SetCellValue(sheet, cell, val) //nolint:errcheck
}

func setCellInt(f *excelize.File, sheet, cell string, val int64) {
	f.SetCellValue(sheet, cell, val) //nolint:errcheck
}

func setCellFloat(f *excelize.File, sheet, cell string, val float64) {
	f.SetCellValue(sheet, cell, val) //nolint:errcheck
}

func colName(col int) string {
	// col is 1-based
	name := ""
	for col > 0 {
		col--
		name = string(rune('A'+col%26)) + name
		col /= 26
	}
	return name
}

func cell(col, row int) string {
	return fmt.Sprintf("%s%d", colName(col), row)
}

func writeSummarySheet(f *excelize.File, rd *ReportData, headerStyle, subHeaderStyle, boldStyle int) {
	const sh = "Summary"
	f.SetSheetName("Sheet1", sh)

	title := "DMARC Management Report — All Domains"
	if rd.Domain != "" {
		title = "DMARC Management Report — " + rd.Domain
	}

	f.MergeCell(sh, "A1", "D1")
	setCellStr(f, sh, "A1", title)
	f.SetCellStyle(sh, "A1", "D1", headerStyle)
	f.SetRowHeight(sh, 1, 22)

	f.SetCellValue(sh, "A2", "Generated")
	f.SetCellValue(sh, "B2", rd.GeneratedAt.Format("2006-01-02 15:04:05 UTC"))
	if rd.PeriodLabel != "" {
		f.SetCellValue(sh, "A3", "Period")
		f.SetCellValue(sh, "B3", rd.PeriodLabel)
	}
	f.SetCellStyle(sh, "A2", "A3", boldStyle)

	row := 4
	f.SetCellValue(sh, cell(1, row), "Metric")
	f.SetCellValue(sh, cell(2, row), "Value")
	f.SetCellStyle(sh, cell(1, row), cell(2, row), subHeaderStyle)
	row++

	kpis := [][2]string{
		{"Total Messages", fmt.Sprintf("%d", rd.Summary.TotalMessages)},
		{"Passed", fmt.Sprintf("%d", rd.Summary.TotalPassed)},
		{"Failed", fmt.Sprintf("%d", rd.Summary.TotalFailed)},
		{"Pass Rate", fmt.Sprintf("%.1f%%", rd.Summary.PassRate)},
	}
	if rd.Domain == "" {
		kpis = append(kpis, [2]string{"Domains", fmt.Sprintf("%d", rd.Summary.DomainCount)})
	}
	for _, kv := range kpis {
		f.SetCellValue(sh, cell(1, row), kv[0])
		f.SetCellValue(sh, cell(2, row), kv[1])
		row++
	}

	f.SetColWidth(sh, "A", "A", 22)
	f.SetColWidth(sh, "B", "B", 28)
}

func writeDomainsSheet(f *excelize.File, rd *ReportData, headerStyle int) {
	const sh = "Domains"
	f.NewSheet(sh)

	headers := []string{"Domain", "Reports", "Messages", "Passed", "Failed", "Pass Rate (%)"}
	for i, h := range headers {
		c := cell(i+1, 1)
		f.SetCellValue(sh, c, h)
	}
	f.SetCellStyle(sh, "A1", cell(len(headers), 1), headerStyle)
	f.SetRowHeight(sh, 1, 18)

	for i, d := range rd.Domains {
		r := i + 2
		f.SetCellValue(sh, cell(1, r), escapeFormula(d.Domain))
		setCellInt(f, sh, cell(2, r), d.ReportCount)
		setCellInt(f, sh, cell(3, r), d.TotalMessages)
		setCellInt(f, sh, cell(4, r), d.Passed)
		setCellInt(f, sh, cell(5, r), d.Failed)
		setCellFloat(f, sh, cell(6, r), d.PassRate)
	}

	f.SetColWidth(sh, "A", "A", 30)
	f.SetColWidth(sh, "B", "F", 14)
}

func writeRecordsSheet(f *excelize.File, rd *ReportData, headerStyle int) {
	const sh = "Records"
	f.NewSheet(sh)

	headers := []string{"Source IP", "Count", "Disposition", "DKIM", "SPF", "Envelope To", "Reporter", "Period Begin", "Period End"}
	for i, h := range headers {
		f.SetCellValue(sh, cell(i+1, 1), h)
	}
	f.SetCellStyle(sh, "A1", cell(len(headers), 1), headerStyle)
	f.SetRowHeight(sh, 1, 18)

	for i, r := range rd.Records {
		row := i + 2
		f.SetCellValue(sh, cell(1, row), escapeFormula(r.SourceIP))
		f.SetCellValue(sh, cell(2, row), r.Count)
		f.SetCellValue(sh, cell(3, row), escapeFormula(r.Disposition))
		f.SetCellValue(sh, cell(4, row), escapeFormula(r.EvalDKIM))
		f.SetCellValue(sh, cell(5, row), escapeFormula(r.EvalSPF))
		f.SetCellValue(sh, cell(6, row), escapeFormula(r.EnvelopeTo))
		f.SetCellValue(sh, cell(7, row), escapeFormula(r.OrgName))
		f.SetCellValue(sh, cell(8, row), time.Unix(r.DateRangeBegin, 0).UTC().Format("2006-01-02"))
		f.SetCellValue(sh, cell(9, row), time.Unix(r.DateRangeEnd, 0).UTC().Format("2006-01-02"))
	}

	f.SetColWidth(sh, "A", "A", 18)
	f.SetColWidth(sh, "B", "B", 8)
	f.SetColWidth(sh, "C", "E", 12)
	f.SetColWidth(sh, "F", "F", 22)
	f.SetColWidth(sh, "G", "G", 20)
	f.SetColWidth(sh, "H", "I", 14)
}

func writeSourcesSheet(f *excelize.File, rd *ReportData, headerStyle int) {
	const sh = "Top Failing Sources"
	f.NewSheet(sh)

	headers := []string{"Source IP", "Messages", "Failed", "Fail Rate (%)"}
	for i, h := range headers {
		f.SetCellValue(sh, cell(i+1, 1), h)
	}
	f.SetCellStyle(sh, "A1", cell(len(headers), 1), headerStyle)
	f.SetRowHeight(sh, 1, 18)

	for i, s := range rd.TopSources {
		r := i + 2
		f.SetCellValue(sh, cell(1, r), escapeFormula(s.SourceIP))
		setCellInt(f, sh, cell(2, r), s.TotalMessages)
		setCellInt(f, sh, cell(3, r), s.Failed)
		setCellFloat(f, sh, cell(4, r), s.FailRate*100)
	}

	f.SetColWidth(sh, "A", "A", 20)
	f.SetColWidth(sh, "B", "D", 14)
}
