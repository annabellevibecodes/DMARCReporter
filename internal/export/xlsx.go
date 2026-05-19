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
		Font: &excelize.Font{Bold: true, Color: "FFFFFF", Size: 10},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"0E2A4A"}, Pattern: 1},
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

	// Remove the default blank Sheet1 if we renamed it
	return f.Write(w)
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
	f.SetCellStyle(sh, "A2", "A2", boldStyle)

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
		f.SetCellValue(sh, cell(1, r), d.Domain)
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
		f.SetCellValue(sh, cell(1, row), r.SourceIP)
		f.SetCellValue(sh, cell(2, row), r.Count)
		f.SetCellValue(sh, cell(3, row), r.Disposition)
		f.SetCellValue(sh, cell(4, row), r.EvalDKIM)
		f.SetCellValue(sh, cell(5, row), r.EvalSPF)
		f.SetCellValue(sh, cell(6, row), r.EnvelopeTo)
		f.SetCellValue(sh, cell(7, row), r.OrgName)
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
		f.SetCellValue(sh, cell(1, r), s.SourceIP)
		setCellInt(f, sh, cell(2, r), s.TotalMessages)
		setCellInt(f, sh, cell(3, r), s.Failed)
		setCellFloat(f, sh, cell(4, r), s.FailRate*100)
	}

	f.SetColWidth(sh, "A", "A", 20)
	f.SetColWidth(sh, "B", "D", 14)
}
