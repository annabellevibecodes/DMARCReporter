package database

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jmoiron/sqlx"

	"github.com/annabellevibecodes/dmarcreporter/internal/dkimcheck"
	"github.com/annabellevibecodes/dmarcreporter/internal/parser"
)

// Transport is how a TLS report reached us.
const (
	// TransportSMTP is a report that arrived as mail, so RFC 8460 §3 applies
	// and its DKIM signature decides whether it counts.
	TransportSMTP = "smtp"
	// TransportUpload is a report handed to the web form as a bare file.
	// There is no carrying message, so there is nothing to verify.
	TransportUpload = "upload"
)

// ErrDuplicateRange is returned when a report_id already imported for this
// organisation arrives again carrying a *different* date range.
//
// An ordinary duplicate is a harmless retry. Report-ID reuse across windows is
// not: the second window is being dropped, and the operator is missing a day
// of data without any sign of it. The two are counted separately in hygiene.
var ErrDuplicateRange = errors.New("duplicate report id with a different date range")

// Field caps. Report content is untrusted — anyone can mail JSON to the
// monitored mailbox — so free-text fields are bounded before they are stored.
const (
	maxPolicyStringLen   = 8192
	maxReasonCodeLen     = 256
	maxAdditionalInfoLen = 1024
	maxHostnameLen       = 253
	maxResultTypeLen     = 128
)

// registeredResultTypes is the IANA "TLS-RPT Result Types" registry as of RFC
// 8460. The registry is Expert Review and expected to grow, so an unlisted
// value is stored verbatim and counted here — never dropped.
var registeredResultTypes = map[string]bool{
	"starttls-not-supported":    true,
	"certificate-host-mismatch": true,
	"certificate-expired":       true,
	"certificate-not-trusted":   true,
	"validation-failure":        true,
	"tlsa-invalid":              true,
	"dnssec-invalid":            true,
	"dane-required":             true,
	"sts-policy-fetch-error":    true,
	"sts-policy-invalid":        true,
	"sts-webpki-invalid":        true,
}

// TLSRPTReport is the database representation of one SMTP TLS report.
type TLSRPTReport struct {
	ID             int64  `db:"id"`
	OrgName        string `db:"org_name"`
	ReportID       string `db:"report_id"`
	ContactInfo    string `db:"contact_info"`
	DateRangeBegin int64  `db:"date_range_begin"`
	DateRangeEnd   int64  `db:"date_range_end"`
	PolicyDomains  string `db:"policy_domains"`
	TotalSuccess   int64  `db:"total_success"`
	TotalFailure   int64  `db:"total_failure"`
	RawJSON        string `db:"raw_json"`
	ImportedAt     int64  `db:"imported_at"`
	SourceFilename string `db:"source_filename"`

	ReceivedAt         int64  `db:"received_at"`
	SubmitterDomain    string `db:"submitter_domain"`
	ReportDomain       string `db:"report_domain"`
	Transport          string `db:"transport"`
	DKIMStatus         string `db:"dkim_status"`
	DKIMDomain         string `db:"dkim_domain"`
	DKIMSelector       string `db:"dkim_selector"`
	DKIMServiceTLSRPT  int    `db:"dkim_stype_tlsrpt"`
	DKIMMatchesContact int    `db:"dkim_matches_contact"`
	DKIMDetail         string `db:"dkim_detail"`

	MultiPolicy          int   `db:"multi_policy"`
	UnattributedFailures int64 `db:"unattributed_failures"`
	MalformedIPs         int   `db:"malformed_ips"`
	UnknownResultTypes   int   `db:"unknown_result_types"`
	RangeVariance        int   `db:"range_variance"`
}

// BeginTime returns DateRangeBegin as a UTC time.Time.
func (r TLSRPTReport) BeginTime() time.Time { return time.Unix(r.DateRangeBegin, 0).UTC() }

// EndTime returns DateRangeEnd as a UTC time.Time.
func (r TLSRPTReport) EndTime() time.Time { return time.Unix(r.DateRangeEnd, 0).UTC() }

// TLSRPTMeta is what the ingest path knows about a report that the report body
// does not say: how it arrived, when, and whether its carrying mail was signed.
type TLSRPTMeta struct {
	ReceivedAt      int64
	Transport       string
	ReportDomain    string
	SubmitterDomain string

	DKIMStatus         string
	DKIMDomain         string
	DKIMSelector       string
	DKIMServiceTLSRPT  bool
	DKIMMatchesContact bool
	DKIMDetail         string
}

// TLSRPTPolicyRow is one stored entry of a report's `policies` array.
type TLSRPTPolicyRow struct {
	ID                   int64  `db:"id"`
	ReportID             int64  `db:"tlsrpt_report_id"`
	PolicyIndex          int    `db:"policy_index"`
	PolicyType           string `db:"policy_type"`
	PolicyDomain         string `db:"policy_domain"`
	MXHostPattern        string `db:"mx_host_pattern"`
	PolicyString         string `db:"policy_string"`
	SuccessCount         int64  `db:"success_count"`
	FailureCount         int64  `db:"failure_count"`
	UnattributedFailures int64  `db:"unattributed_failures"`
	STSVersion           string `db:"sts_version"`
	STSMode              string `db:"sts_mode"`
	STSMaxAge            int64  `db:"sts_max_age"`
}

// TLSRPTFailureRow is one stored `failure-details` entry.
type TLSRPTFailureRow struct {
	ID                    int64          `db:"id"`
	PolicyID              int64          `db:"policy_id"`
	ResultType            string         `db:"result_type"`
	SendingMTAIP          sql.NullString `db:"sending_mta_ip"`
	ReceivingMXHostname   string         `db:"receiving_mx_hostname"`
	ReceivingMXHelo       string         `db:"receiving_mx_helo"`
	ReceivingIP           sql.NullString `db:"receiving_ip"`
	FailedSessionCount    int64          `db:"failed_session_count"`
	AdditionalInformation string         `db:"additional_information"`
	FailureReasonCode     string         `db:"failure_reason_code"`
}

// SaveTLSRPT stores a report that arrived without a carrying message, such as
// a file handed to the upload form. It is SaveTLSRPTWithMeta with nothing to
// verify.
func SaveTLSRPT(db *sqlx.DB, report *parser.TLSReport, filename string, rawJSON []byte) (int64, error) {
	return SaveTLSRPTWithMeta(db, report, TLSRPTMeta{
		Transport:  TransportUpload,
		DKIMStatus: string(dkimcheck.StatusNotApplicable),
	}, filename, rawJSON)
}

// SaveTLSRPTWithMeta stores a parsed TLS report with its policy, MX-pattern
// and failure-detail rows in one transaction, together with what the ingest
// path knows about how the report arrived.
//
// Returns ErrDuplicate when the same (org, report-id) pair was imported
// before with the same window, and ErrDuplicateRange when the window differs.
func SaveTLSRPTWithMeta(db *sqlx.DB, report *parser.TLSReport, meta TLSRPTMeta, filename string, rawJSON []byte) (int64, error) {
	success, failure := report.Totals()
	begin, end := report.DateRange.Start.Unix(), report.DateRange.End.Unix()

	tx, err := db.Beginx()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once the tx is committed

	res, err := tx.Exec(`
		INSERT INTO tlsrpt_reports
			(org_name, report_id, contact_info, date_range_begin, date_range_end,
			 policy_domains, total_success, total_failure, raw_json, imported_at, source_filename,
			 received_at, submitter_domain, report_domain, transport,
			 dkim_status, dkim_domain, dkim_selector, dkim_stype_tlsrpt, dkim_matches_contact, dkim_detail,
			 multi_policy, unattributed_failures, malformed_ips, unknown_result_types, range_variance)
		VALUES (?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?, ?,?,?,?,?,?, ?,?,?,?,?)`,
		report.OrganizationName,
		report.ReportID,
		report.ContactInfo,
		begin,
		end,
		strings.Join(report.Domains(), ","),
		success,
		failure,
		string(rawJSON),
		time.Now().Unix(),
		filename,
		meta.ReceivedAt,
		truncate(meta.SubmitterDomain, maxHostnameLen),
		truncate(meta.ReportDomain, maxHostnameLen),
		meta.Transport,
		statusOrUnknown(meta.DKIMStatus),
		truncate(meta.DKIMDomain, maxHostnameLen),
		truncate(meta.DKIMSelector, maxHostnameLen),
		boolInt(meta.DKIMServiceTLSRPT),
		boolInt(meta.DKIMMatchesContact),
		truncate(meta.DKIMDetail, maxReasonCodeLen),
		0, 0, 0, 0, 0, // hygiene counters, updated below once the children are in
	)
	if err != nil {
		if isUniqueConstraint(err) {
			// Inside the transaction: the pool is capped at one connection,
			// so reading through db here would wait on the tx we still hold.
			return 0, classifyDuplicate(tx, report.OrganizationName, report.ReportID, begin, end)
		}
		return 0, err
	}
	reportID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	h, err := insertTLSRPTPolicies(tx, reportID, report)
	if err != nil {
		return 0, err
	}
	if fnBegin, fnEnd, ok := parser.TLSRPTFilenameRange(filename); ok && (fnBegin != begin || fnEnd != end) {
		// §5.6: the body is authoritative. Record the disagreement, keep the body.
		h.RangeVariance = 1
	}

	if _, err := tx.Exec(`
		UPDATE tlsrpt_reports
		   SET multi_policy = ?, unattributed_failures = ?, malformed_ips = ?,
		       unknown_result_types = ?, range_variance = ?
		 WHERE id = ?`,
		h.MultiPolicy, h.UnattributedFailures, h.MalformedIPs, h.UnknownResultTypes, h.RangeVariance,
		reportID); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return reportID, nil
}

// tlsrptHygiene are the per-report counters derived while storing children.
type tlsrptHygiene struct {
	MultiPolicy          int
	UnattributedFailures int64
	MalformedIPs         int
	UnknownResultTypes   int
	RangeVariance        int
}

// insertTLSRPTPolicies writes the policy, MX-pattern and failure rows of one
// report, storing every value as the reporter sent it (after normalisation and
// capping) and returning the hygiene counters observed on the way through.
func insertTLSRPTPolicies(tx *sqlx.Tx, reportID int64, report *parser.TLSReport) (tlsrptHygiene, error) {
	var h tlsrptHygiene
	groups := map[string]int{} // I2: (policy_domain, mx pattern) → entries

	for i, p := range report.Policies {
		mxPatterns := policyMXPatterns(p)
		groupKey := strings.ToLower(p.Policy.PolicyDomain) + "\x00" + strings.Join(mxPatterns, ",")
		groups[groupKey]++

		policyString, _ := json.Marshal([]string(p.Policy.PolicyString))
		stsVersion, stsMode, stsMaxAge := parseSTSPolicyString(p.Policy.PolicyType, p.Policy.PolicyString)

		success := clampCount(p.Summary.TotalSuccess)
		failure := clampCount(p.Summary.TotalFailure)

		var detailSum int64
		for _, d := range p.FailureDetails {
			detailSum += clampCount(d.FailedSessionCount)
		}
		// I3: the summary is authoritative; detail rows may account for less.
		unattributed := failure - detailSum
		if unattributed < 0 {
			unattributed = 0
		}
		h.UnattributedFailures += unattributed

		res, err := tx.Exec(`
			INSERT INTO tlsrpt_policies
				(tlsrpt_report_id, policy_index, policy_type, policy_domain, mx_host_pattern,
				 policy_string, success_count, failure_count, unattributed_failures,
				 sts_version, sts_mode, sts_max_age)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			reportID, i,
			truncate(p.Policy.PolicyType, maxResultTypeLen),
			truncate(strings.ToLower(p.Policy.PolicyDomain), maxHostnameLen),
			truncate(strings.Join(mxPatterns, ","), maxPolicyStringLen),
			truncate(string(policyString), maxPolicyStringLen),
			success, failure, unattributed,
			truncate(stsVersion, 32), truncate(stsMode, 32), stsMaxAge,
		)
		if err != nil {
			return h, err
		}
		policyID, err := res.LastInsertId()
		if err != nil {
			return h, err
		}

		for j, pattern := range mxPatterns {
			if _, err := tx.Exec(`
				INSERT INTO tlsrpt_policy_mx (policy_id, mx_index, mx_pattern) VALUES (?,?,?)`,
				policyID, j, truncate(pattern, maxHostnameLen)); err != nil {
				return h, err
			}
		}

		for _, d := range p.FailureDetails {
			resultType := truncate(strings.TrimSpace(d.ResultType), maxResultTypeLen)
			if resultType != "" && !registeredResultTypes[strings.ToLower(resultType)] {
				h.UnknownResultTypes++
			}
			sendingIP, okSending := normaliseIP(d.SendingMTAIP)
			receivingIP, okReceiving := normaliseIP(d.ReceivingIP)
			if !okSending {
				h.MalformedIPs++
			}
			if !okReceiving {
				h.MalformedIPs++
			}
			if _, err := tx.Exec(`
				INSERT INTO tlsrpt_failures
					(policy_id, result_type, sending_mta_ip, receiving_mx_hostname, receiving_mx_helo,
					 receiving_ip, failed_session_count, additional_information, failure_reason_code)
				VALUES (?,?,?,?,?,?,?,?,?)`,
				policyID, resultType, sendingIP,
				truncate(strings.ToLower(strings.TrimSpace(d.ReceivingMXHostname)), maxHostnameLen),
				truncate(strings.ToLower(strings.TrimSpace(d.ReceivingMXHelo)), maxHostnameLen),
				receivingIP,
				clampCount(d.FailedSessionCount),
				truncate(d.AdditionalInformation, maxAdditionalInfoLen),
				truncate(d.FailureReasonCode, maxReasonCodeLen),
			); err != nil {
				return h, err
			}
		}
	}

	for _, n := range groups {
		if n > 1 {
			h.MultiPolicy = 1
			break
		}
	}
	return h, nil
}

// policyMXPatterns returns a policy's mx-host patterns, sorted so the same set
// always produces the same I2 group key. RFC 8460 carries them in `mx-host`;
// an STS policy that only lists them inside policy-string is read from there.
func policyMXPatterns(p parser.TLSPolicy) []string {
	var out []string
	for _, h := range p.Policy.MXHost {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		for _, line := range p.Policy.PolicyString {
			key, value, ok := strings.Cut(line, ":")
			if !ok || !strings.EqualFold(strings.TrimSpace(key), "mx") {
				continue
			}
			if v := strings.ToLower(strings.TrimSpace(value)); v != "" {
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TLSMXPatternMatches applies the RFC 8461 §4.1 MX host matching rules: a
// pattern is either an exact hostname or a wildcard in the leftmost label
// only, and that wildcard matches exactly one label.
//
// This is the only correct way to relate a policy's mx_host_pattern to a
// reported receiving_mx_hostname. Equality between the two columns is never
// the right test (I6): "*.mail.example.com" covers "mx3.mail.example.com"
// without ever being equal to it.
func TLSMXPatternMatches(pattern, host string) bool {
	pattern = strings.Trim(strings.ToLower(strings.TrimSpace(pattern)), ".")
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if pattern == "" || host == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		// A wildcard anywhere but the leftmost label is not a valid pattern,
		// and must not be treated as one.
		if strings.Contains(pattern, "*") {
			return false
		}
		return pattern == host
	}
	suffix := pattern[1:] // ".mail.example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

// parseSTSPolicyString pulls version, mode and max_age out of an MTA-STS
// policy body. Non-STS policies (tlsa, no-policy-found) have no such fields.
func parseSTSPolicyString(policyType string, lines parser.FlexStrings) (version, mode string, maxAge int64) {
	if !strings.EqualFold(strings.TrimSpace(policyType), "sts") {
		return "", "", 0
	}
	for _, line := range lines {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "version":
			version = value
		case "mode":
			mode = strings.ToLower(value)
		case "max_age":
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				maxAge = n
			}
		}
	}
	return version, mode, maxAge
}

// classifyDuplicate decides which kind of duplicate a rejected insert was.
// It reads through the caller's transaction, never the pool.
func classifyDuplicate(tx *sqlx.Tx, orgName, reportID string, begin, end int64) error {
	var existing struct {
		Begin int64 `db:"date_range_begin"`
		End   int64 `db:"date_range_end"`
	}
	err := tx.Get(&existing, `
		SELECT date_range_begin, date_range_end FROM tlsrpt_reports
		 WHERE org_name = ? AND report_id = ?`, orgName, reportID)
	if err != nil {
		// The row vanished or is unreadable: report the plain duplicate.
		return ErrDuplicate
	}
	if existing.Begin != begin || existing.End != end {
		return ErrDuplicateRange
	}
	return ErrDuplicate
}

// normaliseIP parses an address and returns its canonical text form, so two
// spellings of one IPv6 address (2001:db8:0::1 and 2001:db8::1) group as one
// row (I5). An unparseable value — anyone can mail us JSON — is stored as NULL
// and counted in hygiene rather than dropping the whole detail row.
func normaliseIP(s string) (sql.NullString, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return sql.NullString{}, true // absent, not malformed
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return sql.NullString{}, false
	}
	return sql.NullString{String: ip.String(), Valid: true}, true
}

// clampCount floors a reported count at zero.
func clampCount(n int64) int64 {
	if n < 0 {
		return 0
	}
	return n
}

// truncate caps a stored string at n bytes, on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

func statusOrUnknown(s string) string {
	if s == "" {
		return string(dkimcheck.StatusUnknown)
	}
	return s
}

// TLSRPTCounted reports whether a report's sessions count toward the T-series.
//
// TLSRPT_REQUIRE_DKIM only ever excludes mail-delivered reports. A report
// uploaded through the web form has no carrying message and so no signature to
// check; gating on dkim_status alone would silently drop every manual upload
// from the metrics.
func TLSRPTCounted(transport, dkimStatus string, requireDKIM bool) bool {
	if !requireDKIM || transport != TransportSMTP {
		return true
	}
	return dkimStatus == string(dkimcheck.StatusValid)
}

// tlsrptListColumns excludes raw_json — list views don't need the blob,
// mirroring the DMARC convention of keeping report_xml out of list queries.
const tlsrptListColumns = `id, org_name, report_id, contact_info, date_range_begin, date_range_end,
	policy_domains, total_success, total_failure, imported_at, source_filename,
	received_at, submitter_domain, report_domain, transport,
	dkim_status, dkim_domain, dkim_selector, dkim_stype_tlsrpt, dkim_matches_contact, dkim_detail,
	multi_policy, unattributed_failures, malformed_ips, unknown_result_types, range_variance`

// ListTLSRPT returns TLS reports newest-first, optionally scoped to
// date_range_begin >= from, capped at limit.
func ListTLSRPT(db *sqlx.DB, from int64, limit int) ([]TLSRPTReport, error) {
	var reports []TLSRPTReport
	var err error
	if from > 0 {
		err = db.Select(&reports, `
			SELECT `+tlsrptListColumns+` FROM tlsrpt_reports
			WHERE date_range_begin >= ?
			ORDER BY date_range_begin DESC LIMIT ?`, from, limit)
	} else {
		err = db.Select(&reports, `
			SELECT `+tlsrptListColumns+` FROM tlsrpt_reports
			ORDER BY date_range_begin DESC LIMIT ?`, limit)
	}
	return reports, err
}

// ListTLSRPTPolicies returns the stored policy rows of one report, in the
// order the reporter sent them.
func ListTLSRPTPolicies(db *sqlx.DB, reportID int64) ([]TLSRPTPolicyRow, error) {
	var rows []TLSRPTPolicyRow
	err := db.Select(&rows, `
		SELECT id, tlsrpt_report_id, policy_index, policy_type, policy_domain, mx_host_pattern,
		       policy_string, success_count, failure_count, unattributed_failures,
		       sts_version, sts_mode, sts_max_age
		  FROM tlsrpt_policies WHERE tlsrpt_report_id = ? ORDER BY policy_index`, reportID)
	return rows, err
}

// ListTLSRPTFailures returns the failure-detail rows of one policy.
func ListTLSRPTFailures(db *sqlx.DB, policyID int64) ([]TLSRPTFailureRow, error) {
	var rows []TLSRPTFailureRow
	err := db.Select(&rows, `
		SELECT id, policy_id, result_type, sending_mta_ip, receiving_mx_hostname, receiving_mx_helo,
		       receiving_ip, failed_session_count, additional_information, failure_reason_code
		  FROM tlsrpt_failures WHERE policy_id = ? ORDER BY id`, policyID)
	return rows, err
}

// GetTLSRPTJSON returns the stored raw JSON for a TLS report, or ("", nil) if not found.
func GetTLSRPTJSON(db *sqlx.DB, id int64) (string, error) {
	var rawJSON string
	err := db.Get(&rawJSON, `SELECT raw_json FROM tlsrpt_reports WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return rawJSON, nil
}

// TLSRPTSummary holds aggregate TLS session counts for a period.
type TLSRPTSummary struct {
	ReportCount  int64 `db:"report_count"`
	TotalSuccess int64 `db:"total_success"`
	TotalFailure int64 `db:"total_failure"`
}

// GetTLSRPTSummary returns aggregate counts, optionally scoped to from.
//
// These are the reports' own sums, so a report describing one set of sessions
// under two policy entries is counted twice; TLSSessionTotals is the corrected
// figure.
func GetTLSRPTSummary(db *sqlx.DB, from int64) (*TLSRPTSummary, error) {
	var s TLSRPTSummary
	var err error
	if from > 0 {
		err = db.Get(&s, `
			SELECT COUNT(*) AS report_count,
			       COALESCE(SUM(total_success), 0) AS total_success,
			       COALESCE(SUM(total_failure), 0) AS total_failure
			FROM tlsrpt_reports WHERE date_range_begin >= ?`, from)
	} else {
		err = db.Get(&s, `
			SELECT COUNT(*) AS report_count,
			       COALESCE(SUM(total_success), 0) AS total_success,
			       COALESCE(SUM(total_failure), 0) AS total_failure
			FROM tlsrpt_reports`)
	}
	return &s, err
}

// TLSTotals is the session count with the multi-policy rollup applied.
type TLSTotals struct {
	Success int64 `db:"total_success"`
	Failure int64 `db:"total_failure"`
	// MultiPolicyReports is how many reports in the window needed the rollup.
	MultiPolicyReports int64 `db:"multi_policy_reports"`
}

// TLSSessionTotals returns session counts with the I2 rollup applied: within
// one report, policy entries sharing a policy domain and mx-host pattern are
// collapsed by taking the maximum success and failure count rather than the
// sum, then the groups are summed.
//
// Two entries (an MTA-STS policy and a TLSA record, say) can describe the same
// sessions, and summing them double-counts. The RFC never states that the
// populations overlap, so this is an inference, not a fact — which is exactly
// why it lives here at query time and not in the stored rows.
func TLSSessionTotals(db *sqlx.DB, from int64) (*TLSTotals, error) {
	var t TLSTotals
	err := db.Get(&t, `
		SELECT COALESCE(SUM(s), 0) AS total_success,
		       COALESCE(SUM(f), 0) AS total_failure,
		       (SELECT COUNT(*) FROM tlsrpt_reports
		         WHERE multi_policy = 1 AND (? = 0 OR date_range_begin >= ?)) AS multi_policy_reports
		  FROM (
		        SELECT MAX(p.success_count) AS s, MAX(p.failure_count) AS f
		          FROM tlsrpt_policies p
		          JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id
		         WHERE (? = 0 OR r.date_range_begin >= ?)
		         GROUP BY p.tlsrpt_report_id, p.policy_domain, p.mx_host_pattern
		       )`, from, from, from, from)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// GetTLSRPT returns one report by id, or (nil, nil) when it does not exist.
func GetTLSRPT(db *sqlx.DB, id int64) (*TLSRPTReport, error) {
	var r TLSRPTReport
	err := db.Get(&r, `SELECT `+tlsrptListColumns+` FROM tlsrpt_reports WHERE id = ?`, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

// ListTLSRPTDomains returns every policy domain seen in a TLS report, for the
// page's domain picker.
func ListTLSRPTDomains(db *sqlx.DB) ([]string, error) {
	var out []string
	err := db.Select(&out, `
		SELECT DISTINCT policy_domain FROM tlsrpt_policies
		 WHERE policy_domain != '' ORDER BY policy_domain`)
	return out, err
}

// TLSPolicyStringLines decodes a stored policy_string back into its lines.
// A value that is not the JSON array we wrote is returned as a single line
// rather than discarded — it still came from a reporter and is still evidence.
func TLSPolicyStringLines(policyString string) []string {
	if strings.TrimSpace(policyString) == "" {
		return nil
	}
	var lines []string
	if err := json.Unmarshal([]byte(policyString), &lines); err != nil {
		return []string{policyString}
	}
	return lines
}
