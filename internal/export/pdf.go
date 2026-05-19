package export

import (
	"fmt"
	"io"
	"time"

	"github.com/jung-kurt/gofpdf"
)

const (
	pdfMargin    = 15.0
	pdfPageW     = 210.0
	pdfPageH     = 297.0
	pdfBodyW     = pdfPageW - 2*pdfMargin
	pdfRowH      = 6.5
	pdfHeaderH   = 8.0
	colorNavyR   = 14
	colorNavyG   = 42
	colorNavyB   = 74
	colorGrayR   = 245
	colorGrayG   = 245
	colorGrayB   = 245
	colorMutedR  = 100
	colorMutedG  = 100
	colorMutedB  = 100
)

// WritePDF writes the report as a PDF to w.
func WritePDF(w io.Writer, rd *ReportData) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(pdfMargin, 20, pdfMargin)
	pdf.SetAutoPageBreak(true, 18)

	// Footer
	pdf.SetFooterFunc(func() {
		pdf.SetY(-12)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(colorMutedR, colorMutedG, colorMutedB)
		pdf.CellFormat(pdfBodyW/2, 5, "DMARC Reporter — Confidential", "", 0, "L", false, 0, "")
		pdf.CellFormat(pdfBodyW/2, 5, fmt.Sprintf("Page %d", pdf.PageNo()), "", 0, "R", false, 0, "")
	})

	pdf.AddPage()

	// Title banner
	pdf.SetFillColor(colorNavyR, colorNavyG, colorNavyB)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(pdfBodyW, 12, "DMARC Management Report", "", 1, "L", true, 0, "")
	pdf.Ln(1)

	// Subtitle / domain
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetTextColor(colorNavyR, colorNavyG, colorNavyB)
	scope := "All Domains"
	if rd.Domain != "" {
		scope = rd.Domain
	}
	pdf.CellFormat(pdfBodyW/2, 6, "Scope: "+scope, "", 0, "L", false, 0, "")
	pdf.CellFormat(pdfBodyW/2, 6, "Generated: "+rd.GeneratedAt.Format("2006-01-02 15:04 UTC"), "", 1, "R", false, 0, "")
	pdf.Ln(4)

	// Summary KPIs
	pdfSectionHeader(pdf, "Summary")
	kpis := [][2]string{
		{"Total Messages", fmt.Sprintf("%d", rd.Summary.TotalMessages)},
		{"Passed", fmt.Sprintf("%d", rd.Summary.TotalPassed)},
		{"Failed", fmt.Sprintf("%d", rd.Summary.TotalFailed)},
		{"Pass Rate", fmt.Sprintf("%.1f%%", rd.Summary.PassRate)},
	}
	if rd.Domain == "" {
		kpis = append(kpis, [2]string{"Domains", fmt.Sprintf("%d", rd.Summary.DomainCount)})
	}
	pdfKVTable(pdf, kpis)
	pdf.Ln(6)

	// Domain breakdown
	if rd.Domain == "" {
		pdfSectionHeader(pdf, "Domain Breakdown")
		cols := []pdfCol{
			{Header: "Domain", Width: 60, Align: "L"},
			{Header: "Reports", Width: 20, Align: "R"},
			{Header: "Messages", Width: 28, Align: "R"},
			{Header: "Passed", Width: 22, Align: "R"},
			{Header: "Failed", Width: 22, Align: "R"},
			{Header: "Pass Rate", Width: 23, Align: "R"},
		}
		rows := make([][]string, len(rd.Domains))
		for i, d := range rd.Domains {
			rows[i] = []string{
				d.Domain,
				fmt.Sprintf("%d", d.ReportCount),
				fmt.Sprintf("%d", d.TotalMessages),
				fmt.Sprintf("%d", d.Passed),
				fmt.Sprintf("%d", d.Failed),
				fmt.Sprintf("%.1f%%", d.PassRate),
			}
		}
		pdfTable(pdf, cols, rows)
		pdf.Ln(6)
	} else if len(rd.Records) > 0 {
		pdfSectionHeader(pdf, "Recent Records")
		cols := []pdfCol{
			{Header: "Source IP", Width: 36, Align: "L"},
			{Header: "Count", Width: 14, Align: "R"},
			{Header: "Disposition", Width: 24, Align: "L"},
			{Header: "DKIM", Width: 16, Align: "L"},
			{Header: "SPF", Width: 14, Align: "L"},
			{Header: "Reporter", Width: 38, Align: "L"},
			{Header: "Period", Width: 33, Align: "L"},
		}
		rows := make([][]string, len(rd.Records))
		for i, r := range rd.Records {
			period := time.Unix(r.DateRangeBegin, 0).UTC().Format("2006-01-02") +
				" – " + time.Unix(r.DateRangeEnd, 0).UTC().Format("2006-01-02")
			rows[i] = []string{
				r.SourceIP,
				fmt.Sprintf("%d", r.Count),
				r.Disposition,
				r.EvalDKIM,
				r.EvalSPF,
				r.OrgName,
				period,
			}
		}
		pdfTable(pdf, cols, rows)
		pdf.Ln(6)
	}

	// Top failing sources
	if len(rd.TopSources) > 0 {
		pdfSectionHeader(pdf, "Top Failing Source IPs")
		cols := []pdfCol{
			{Header: "Source IP", Width: 55, Align: "L"},
			{Header: "Messages", Width: 30, Align: "R"},
			{Header: "Failed", Width: 30, Align: "R"},
			{Header: "Fail Rate", Width: 30, Align: "R"},
		}
		rows := make([][]string, len(rd.TopSources))
		for i, s := range rd.TopSources {
			rows[i] = []string{
				s.SourceIP,
				fmt.Sprintf("%d", s.TotalMessages),
				fmt.Sprintf("%d", s.Failed),
				fmt.Sprintf("%.1f%%", s.FailRate*100),
			}
		}
		pdfTable(pdf, cols, rows)
	}

	return pdf.Output(w)
}

func pdfSectionHeader(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(colorNavyR, colorNavyG, colorNavyB)
	pdf.SetFillColor(colorGrayR, colorGrayG, colorGrayB)
	pdf.CellFormat(pdfBodyW, 7, title, "B", 1, "L", true, 0, "")
	pdf.Ln(1)
}

func pdfKVTable(pdf *gofpdf.Fpdf, rows [][2]string) {
	pdf.SetFont("Helvetica", "", 9)
	for i, kv := range rows {
		if i%2 == 0 {
			pdf.SetFillColor(colorGrayR, colorGrayG, colorGrayB)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(0, 0, 0)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.CellFormat(50, pdfRowH, kv[0], "", 0, "L", true, 0, "")
		pdf.SetFont("Helvetica", "", 9)
		pdf.CellFormat(pdfBodyW-50, pdfRowH, kv[1], "", 1, "L", true, 0, "")
	}
}

type pdfCol struct {
	Header string
	Width  float64
	Align  string
}

func pdfTable(pdf *gofpdf.Fpdf, cols []pdfCol, rows [][]string) {
	// Header row
	pdf.SetFillColor(colorNavyR, colorNavyG, colorNavyB)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	for _, c := range cols {
		pdf.CellFormat(c.Width, pdfHeaderH, c.Header, "", 0, c.Align, true, 0, "")
	}
	pdf.Ln(-1)

	// Data rows
	pdf.SetFont("Helvetica", "", 8)
	for i, row := range rows {
		if pdf.GetY() > pdfPageH-pdfMargin-20 {
			pdf.AddPage()
		}
		if i%2 == 0 {
			pdf.SetFillColor(colorGrayR, colorGrayG, colorGrayB)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}
		pdf.SetTextColor(0, 0, 0)
		for j, c := range cols {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			pdf.CellFormat(c.Width, pdfRowH, val, "", 0, c.Align, true, 0, "")
		}
		pdf.Ln(-1)
	}
}
