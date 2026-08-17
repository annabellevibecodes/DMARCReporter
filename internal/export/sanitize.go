package export

// escapeFormula neutralizes CSV/XLSX formula injection (CWE-1236). Fields
// such as org_name and envelope_to come from parsed DMARC/TLS-RPT report XML,
// which anyone able to email or upload a report can control. If such a value
// starts with a character a spreadsheet application treats as a formula
// trigger, prefix it with a single quote so Excel/LibreOffice/Sheets render
// it as literal text instead of evaluating it as a formula on open.
func escapeFormula(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}
