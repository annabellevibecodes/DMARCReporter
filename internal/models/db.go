package models

import "time"

// Report is the database representation of one DMARC aggregate report.
type Report struct {
	ID               int64  `db:"id"`
	OrgName          string `db:"org_name"`
	Email            string `db:"email"`
	ExtraContactInfo string `db:"extra_contact_info"`
	ReportID         string `db:"report_id"`
	DateRangeBegin   int64  `db:"date_range_begin"`
	DateRangeEnd     int64  `db:"date_range_end"`
	Domain           string `db:"domain"`
	ADKIM            string `db:"adkim"`
	ASPF             string `db:"aspf"`
	Policy           string `db:"policy"`
	SubdomainPolicy  string `db:"subdomain_policy"`
	Pct              int    `db:"pct"`
	FailureOptions   string `db:"failure_options"`
	ImportedAt          int64  `db:"imported_at"`
	SourceFilename      string `db:"source_filename"`
	EnvelopeToDomains   string `db:"envelope_to_domains"` // comma-separated, populated by ListReports
}

// BeginTime returns DateRangeBegin as a UTC time.Time.
func (r Report) BeginTime() time.Time { return time.Unix(r.DateRangeBegin, 0).UTC() }

// EndTime returns DateRangeEnd as a UTC time.Time.
func (r Report) EndTime() time.Time { return time.Unix(r.DateRangeEnd, 0).UTC() }

// ImportedTime returns ImportedAt as a UTC time.Time.
func (r Report) ImportedTime() time.Time { return time.Unix(r.ImportedAt, 0).UTC() }

// RecordRow is the database representation of one record within a report.
type RecordRow struct {
	ID           int64  `db:"id"`
	ReportID     int64  `db:"report_id"`
	SourceIP     string `db:"source_ip"`
	Count        int    `db:"count"`
	Disposition  string `db:"disposition"`
	EvalDKIM     string `db:"eval_dkim"`
	EvalSPF      string `db:"eval_spf"`
	EnvelopeTo   string `db:"envelope_to"`
	EnvelopeFrom string `db:"envelope_from"`
	HeaderFrom   string `db:"header_from"`
}

// Passed returns true if the record passed DMARC (either DKIM or SPF passed).
func (r *RecordRow) Passed() bool {
	return r.EvalDKIM == "pass" || r.EvalSPF == "pass"
}

// DKIMResult is one DKIM auth result row tied to a record.
type DKIMResult struct {
	ID          int64  `db:"id"`
	RecordRowID int64  `db:"record_row_id"`
	Domain      string `db:"domain"`
	Selector    string `db:"selector"`
	Result      string `db:"result"`
	HumanResult string `db:"human_result"`
}

// SPFResult is one SPF auth result row tied to a record.
type SPFResult struct {
	ID          int64  `db:"id"`
	RecordRowID int64  `db:"record_row_id"`
	Domain      string `db:"domain"`
	Scope       string `db:"scope"`
	Result      string `db:"result"`
}

// PolicyOverride is one policy override reason tied to a record.
type PolicyOverride struct {
	ID          int64  `db:"id"`
	RecordRowID int64  `db:"record_row_id"`
	Type        string `db:"type"`
	Comment     string `db:"comment"`
}
