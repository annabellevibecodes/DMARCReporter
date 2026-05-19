package export

import (
	"archive/zip"
	"fmt"
	"html"
	"io"
	"strings"
	"time"
)

// WriteDOCX writes the report as a .docx file to w.
func WriteDOCX(w io.Writer, rd *ReportData) error {
	zw := zip.NewWriter(w)
	defer zw.Close()

	title := "DMARC Management Report — All Domains"
	if rd.Domain != "" {
		title = "DMARC Management Report — " + rd.Domain
	}

	body := buildDocxBody(rd, title)

	files := map[string]string{
		"[Content_Types].xml":          contentTypesXML,
		"_rels/.rels":                   relsXML,
		"word/_rels/document.xml.rels":  docRelsXML,
		"word/document.xml":             buildDocumentXML(body),
	}
	for name, content := range files {
		fw, err := zw.Create(name)
		if err != nil {
			return err
		}
		if _, err = io.WriteString(fw, content); err != nil {
			return err
		}
	}
	return nil
}

func buildDocxBody(rd *ReportData, title string) string {
	var sb strings.Builder

	// Title
	sb.WriteString(docxHeading1(title))
	sb.WriteString(docxPara("Generated: " + rd.GeneratedAt.Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(docxPara(""))

	// Summary
	sb.WriteString(docxHeading2("Summary"))
	kpis := [][2]string{
		{"Total Messages", fmt.Sprintf("%d", rd.Summary.TotalMessages)},
		{"Passed", fmt.Sprintf("%d", rd.Summary.TotalPassed)},
		{"Failed", fmt.Sprintf("%d", rd.Summary.TotalFailed)},
		{"Pass Rate", fmt.Sprintf("%.1f%%", rd.Summary.PassRate)},
	}
	if rd.Domain == "" {
		kpis = append(kpis, [2]string{"Domains", fmt.Sprintf("%d", rd.Summary.DomainCount)})
	}
	kvRows := make([][2]string, len(kpis))
	copy(kvRows, kpis)
	sb.WriteString(docxTable([]string{"Metric", "Value"}, kvSliceToRows(kvRows)))
	sb.WriteString(docxPara(""))

	// Domain breakdown
	if rd.Domain == "" {
		sb.WriteString(docxHeading2("Domain Breakdown"))
		headers := []string{"Domain", "Reports", "Messages", "Passed", "Failed", "Pass Rate"}
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
		sb.WriteString(docxTable(headers, rows))
		sb.WriteString(docxPara(""))
	} else if len(rd.Records) > 0 {
		sb.WriteString(docxHeading2("Recent Records"))
		headers := []string{"Source IP", "Count", "Disposition", "DKIM", "SPF", "Reporter", "Period Begin", "Period End"}
		rows := make([][]string, len(rd.Records))
		for i, r := range rd.Records {
			rows[i] = []string{
				r.SourceIP,
				fmt.Sprintf("%d", r.Count),
				r.Disposition,
				r.EvalDKIM,
				r.EvalSPF,
				r.OrgName,
				time.Unix(r.DateRangeBegin, 0).UTC().Format("2006-01-02"),
				time.Unix(r.DateRangeEnd, 0).UTC().Format("2006-01-02"),
			}
		}
		sb.WriteString(docxTable(headers, rows))
		sb.WriteString(docxPara(""))
	}

	// Top failing sources
	if len(rd.TopSources) > 0 {
		sb.WriteString(docxHeading2("Top Failing Source IPs"))
		headers := []string{"Source IP", "Messages", "Failed", "Fail Rate"}
		rows := make([][]string, len(rd.TopSources))
		for i, s := range rd.TopSources {
			rows[i] = []string{
				s.SourceIP,
				fmt.Sprintf("%d", s.TotalMessages),
				fmt.Sprintf("%d", s.Failed),
				fmt.Sprintf("%.1f%%", s.FailRate*100),
			}
		}
		sb.WriteString(docxTable(headers, rows))
	}

	return sb.String()
}

func kvSliceToRows(kvs [][2]string) [][]string {
	rows := make([][]string, len(kvs))
	for i, kv := range kvs {
		rows[i] = []string{kv[0], kv[1]}
	}
	return rows
}

func xe(s string) string { return html.EscapeString(s) }

func docxHeading1(text string) string {
	return `<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>` + xe(text) + `</w:t></w:r></w:p>`
}

func docxHeading2(text string) string {
	return `<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>` + xe(text) + `</w:t></w:r></w:p>`
}

func docxPara(text string) string {
	return `<w:p><w:r><w:t>` + xe(text) + `</w:t></w:r></w:p>`
}

func docxTable(headers []string, rows [][]string) string {
	var sb strings.Builder
	sb.WriteString(`<w:tbl>`)
	sb.WriteString(`<w:tblPr>`)
	sb.WriteString(`<w:tblStyle w:val="TableGrid"/>`)
	sb.WriteString(`<w:tblW w:w="9360" w:type="dxa"/>`)
	sb.WriteString(`</w:tblPr>`)

	// Header row
	sb.WriteString(`<w:tr>`)
	for _, h := range headers {
		sb.WriteString(`<w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="0E2A4A"/></w:tcPr>`)
		sb.WriteString(`<w:p><w:r><w:rPr><w:b/><w:color w:val="FFFFFF"/><w:sz w:val="18"/></w:rPr>`)
		sb.WriteString(`<w:t>` + xe(h) + `</w:t></w:r></w:p></w:tc>`)
	}
	sb.WriteString(`</w:tr>`)

	// Data rows
	for i, row := range rows {
		fill := "F5F5F5"
		if i%2 == 1 {
			fill = "FFFFFF"
		}
		sb.WriteString(`<w:tr>`)
		for j := range headers {
			val := ""
			if j < len(row) {
				val = row[j]
			}
			sb.WriteString(`<w:tc><w:tcPr><w:shd w:val="clear" w:color="auto" w:fill="` + fill + `"/></w:tcPr>`)
			sb.WriteString(`<w:p><w:r><w:rPr><w:sz w:val="18"/></w:rPr>`)
			sb.WriteString(`<w:t>` + xe(val) + `</w:t></w:r></w:p></w:tc>`)
		}
		sb.WriteString(`</w:tr>`)
	}
	sb.WriteString(`</w:tbl>`)
	return sb.String()
}

func buildDocumentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body>` + body + `<w:sectPr/>` + `</w:body></w:document>`
}

const contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

const relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
	`</Relationships>`

const docRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>`
