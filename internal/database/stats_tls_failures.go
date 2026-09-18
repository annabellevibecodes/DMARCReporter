package database

import (
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
)

// Failure-detail metrics all share one caveat, stated once here and repeated
// in each metric's Help entry: RFC 8460 result types are explicitly
// non-exclusive, so one session that hit several errors appears in several
// detail rows. Summing failed-session counts therefore yields failure
// *observations*, not distinct sessions, and can exceed the summary total the
// policy reported (I1). Session totals only ever come from the policy
// summaries — see tlsSessionsCTE.

// tlsFailureJoin is the FROM clause every failure-detail metric uses.
const tlsFailureJoin = `
	  FROM tlsrpt_failures f
	  JOIN tlsrpt_policies p ON p.id = f.policy_id
	  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`

// Result-type groups (T4), as RFC 8460 §4.3 groups them.
const (
	TLSGroupNegotiation  = "negotiation"
	TLSGroupDANE         = "dane"
	TLSGroupMTASTS       = "mta-sts"
	TLSGroupUnregistered = "unregistered"
)

// tlsResultGroups maps each registered result type to its group.
var tlsResultGroups = map[string]string{
	"starttls-not-supported":    TLSGroupNegotiation,
	"certificate-host-mismatch": TLSGroupNegotiation,
	"certificate-expired":       TLSGroupNegotiation,
	"certificate-not-trusted":   TLSGroupNegotiation,
	"validation-failure":        TLSGroupNegotiation,
	"tlsa-invalid":              TLSGroupDANE,
	"dnssec-invalid":            TLSGroupDANE,
	"dane-required":             TLSGroupDANE,
	"sts-policy-fetch-error":    TLSGroupMTASTS,
	"sts-policy-invalid":        TLSGroupMTASTS,
	"sts-webpki-invalid":        TLSGroupMTASTS,
}

// TLSResultGroup returns the group a result type belongs to. Anything outside
// the IANA registry is "unregistered" — the registry is Expert Review and
// expected to grow, so a new value is a finding to surface, not an error.
func TLSResultGroup(resultType string) string {
	if g, ok := tlsResultGroups[strings.ToLower(strings.TrimSpace(resultType))]; ok {
		return g
	}
	return TLSGroupUnregistered
}

// TLSResultTypeRow is one result type's slice of T4.
type TLSResultTypeRow struct {
	ResultType     string  `db:"result_type" json:"result_type"`
	Group          string  `db:"-" json:"group"`
	FailedSessions int64   `db:"failed_sessions" json:"failed_sessions"`
	Rows           int64   `db:"rows" json:"rows"`
	Share          float64 `db:"-" json:"share"`
}

// TLSFailureBreakdown is T4: failures by result type, grouped the way the RFC
// groups them so a DANE problem is never read as a certificate problem.
type TLSFailureBreakdown struct {
	Types  []TLSResultTypeRow `json:"types"`
	Groups []TLSResultTypeRow `json:"groups"` // ResultType holds the group name
	Total  int64              `json:"total_failed_sessions"`
}

// GetTLSFailureBreakdown is T4.
func GetTLSFailureBreakdown(db *sqlx.DB, f TLSFilter) (*TLSFailureBreakdown, error) {
	where, args := f.whereFailures()
	out := &TLSFailureBreakdown{}
	if err := db.Select(&out.Types, `
		SELECT CASE WHEN f.result_type = '' THEN '(unspecified)' ELSE f.result_type END AS result_type,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COUNT(*) AS rows`+tlsFailureJoin+where+`
		 GROUP BY result_type
		 ORDER BY failed_sessions DESC, result_type`, args...); err != nil {
		return nil, err
	}

	byGroup := map[string]*TLSResultTypeRow{}
	var order []string
	for i := range out.Types {
		row := &out.Types[i]
		row.Group = TLSResultGroup(row.ResultType)
		out.Total += row.FailedSessions
		g, ok := byGroup[row.Group]
		if !ok {
			g = &TLSResultTypeRow{ResultType: row.Group, Group: row.Group}
			byGroup[row.Group] = g
			order = append(order, row.Group)
		}
		g.FailedSessions += row.FailedSessions
		g.Rows += row.Rows
	}
	for i := range out.Types {
		if out.Total > 0 {
			out.Types[i].Share = float64(out.Types[i].FailedSessions) / float64(out.Total) * 100
		}
	}
	for _, name := range order {
		g := byGroup[name]
		if out.Total > 0 {
			g.Share = float64(g.FailedSessions) / float64(out.Total) * 100
		}
		out.Groups = append(out.Groups, *g)
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].FailedSessions > out.Groups[j].FailedSessions })
	if out.Types == nil {
		out.Types = []TLSResultTypeRow{}
	}
	if out.Groups == nil {
		out.Groups = []TLSResultTypeRow{}
	}
	return out, nil
}

// TLSReceiverRow is one receiving MX host in T5.
type TLSReceiverRow struct {
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	DistinctIPs    int    `db:"distinct_ips" json:"distinct_ips"`
	ResultTypes    string `db:"result_types" json:"result_types"`
}

// TLSReceiverIPRow is one receiving IP in T5 — the high-value view. A
// load-balanced or anycast MX shows one bad node while the rest are fine, and
// only the per-IP split reveals it.
type TLSReceiverIPRow struct {
	ReceivingIP    string `db:"receiving_ip" json:"receiving_ip"`
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	ResultTypes    string `db:"result_types" json:"result_types"`
}

// TLSHeloMismatch is a HELO name that does not match the MX hostname it was
// reported against — a finding in itself, and often the cause of a
// certificate-host-mismatch.
type TLSHeloMismatch struct {
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	Helo           string `db:"helo" json:"helo"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
}

// TLSReceivers is T5.
type TLSReceivers struct {
	ByHost         []TLSReceiverRow   `json:"by_host"`
	ByIP           []TLSReceiverIPRow `json:"by_ip"`
	HeloMismatches []TLSHeloMismatch  `json:"helo_mismatches"`
	// UnspecifiedIP is failure volume whose reporter did not say which
	// receiving IP was involved, so it cannot appear in ByIP at all.
	UnspecifiedIP int64 `json:"unspecified_ip"`
}

// GetTLSReceivers is T5.
func GetTLSReceivers(db *sqlx.DB, f TLSFilter, limit int) (*TLSReceivers, error) {
	if limit <= 0 {
		limit = 50
	}
	where, args := f.whereFailures()
	out := &TLSReceivers{}

	hostArgs := append(append([]any{}, args...), limit)
	if err := db.Select(&out.ByHost, `
		SELECT CASE WHEN f.receiving_mx_hostname = '' THEN '(unspecified)' ELSE f.receiving_mx_hostname END AS mx_hostname,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COUNT(DISTINCT f.receiving_ip) AS distinct_ips,
		       COALESCE(GROUP_CONCAT(DISTINCT f.result_type), '') AS result_types`+tlsFailureJoin+where+`
		 GROUP BY mx_hostname
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, hostArgs...); err != nil {
		return nil, err
	}

	if err := db.Select(&out.ByIP, `
		SELECT f.receiving_ip,
		       CASE WHEN f.receiving_mx_hostname = '' THEN '(unspecified)' ELSE f.receiving_mx_hostname END AS mx_hostname,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COALESCE(GROUP_CONCAT(DISTINCT f.result_type), '') AS result_types`+tlsFailureJoin+
		whereAnd(where, "f.receiving_ip IS NOT NULL")+`
		 GROUP BY f.receiving_ip, mx_hostname
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, hostArgs...); err != nil {
		return nil, err
	}

	if err := db.Select(&out.HeloMismatches, `
		SELECT f.receiving_mx_hostname AS mx_hostname,
		       f.receiving_mx_helo AS helo,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions`+tlsFailureJoin+
		whereAnd(where, "f.receiving_mx_helo != '' AND f.receiving_mx_hostname != '' AND f.receiving_mx_helo != f.receiving_mx_hostname")+`
		 GROUP BY mx_hostname, helo
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, hostArgs...); err != nil {
		return nil, err
	}

	if err := db.Get(&out.UnspecifiedIP, `
		SELECT COALESCE(SUM(f.failed_session_count), 0)`+tlsFailureJoin+
		whereAnd(where, "f.receiving_ip IS NULL"), args...); err != nil {
		return nil, err
	}

	if out.ByHost == nil {
		out.ByHost = []TLSReceiverRow{}
	}
	if out.ByIP == nil {
		out.ByIP = []TLSReceiverIPRow{}
	}
	if out.HeloMismatches == nil {
		out.HeloMismatches = []TLSHeloMismatch{}
	}
	return out, nil
}

// TLSSenderRow is one sending MTA in T6, enriched from the shared rDNS/WHOIS
// cache. These are hosts sending mail *to* us and are a different population
// from the DMARC source IPs on /sources — the enrichment is shared, the
// behaviour classifications deliberately are not.
type TLSSenderRow struct {
	SendingIP      string `db:"sending_ip" json:"sending_ip"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	ResultTypes    string `db:"result_types" json:"result_types"`
	RDNS           string `db:"rdns" json:"rdns"`
	WhoisOrg       string `db:"whois_org" json:"whois_org"`
	WhoisASN       string `db:"whois_asn" json:"whois_asn"`
}

// TLSSenderNetworkRow rolls T6 up to a network (IPv4 /24, IPv6 /64), which is
// what answers "one broken node, or the whole provider?".
type TLSSenderNetworkRow struct {
	Network        string `json:"network"`
	WhoisOrg       string `json:"whois_org"`
	FailedSessions int64  `json:"failed_sessions"`
	IPs            int    `json:"ips"`
}

// TLSSenders is T6.
type TLSSenders struct {
	ByIP       []TLSSenderRow        `json:"by_ip"`
	ByNetwork  []TLSSenderNetworkRow `json:"by_network"`
	ByOrg      []TLSSenderNetworkRow `json:"by_org"` // Network holds the org/ASN label
	Unresolved int64                 `json:"unspecified_ip"`
}

// GetTLSSenders is T6.
func GetTLSSenders(db *sqlx.DB, f TLSFilter, limit int) (*TLSSenders, error) {
	if limit <= 0 {
		limit = 50
	}
	where, args := f.whereFailures()
	out := &TLSSenders{}

	ipArgs := append(append([]any{}, args...), limit)
	if err := db.Select(&out.ByIP, `
		SELECT f.sending_mta_ip AS sending_ip,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COALESCE(GROUP_CONCAT(DISTINCT f.result_type), '') AS result_types,
		       COALESCE(MAX(i.rdns), '') AS rdns,
		       COALESCE(MAX(i.whois_org), '') AS whois_org,
		       COALESCE(MAX(i.whois_asn), '') AS whois_asn`+tlsFailureJoin+`
		  LEFT JOIN ip_info i ON i.ip = f.sending_mta_ip`+
		whereAnd(where, "f.sending_mta_ip IS NOT NULL")+`
		 GROUP BY f.sending_mta_ip
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, ipArgs...); err != nil {
		return nil, err
	}
	if err := db.Get(&out.Unresolved, `
		SELECT COALESCE(SUM(f.failed_session_count), 0)`+tlsFailureJoin+
		whereAnd(where, "f.sending_mta_ip IS NULL"), args...); err != nil {
		return nil, err
	}

	// The network and org rollups are done here rather than in SQL: netmask
	// arithmetic in SQLite string functions would be wrong for IPv6.
	networks := map[string]*TLSSenderNetworkRow{}
	orgs := map[string]*TLSSenderNetworkRow{}
	for _, row := range out.ByIP {
		net := TLSSenderNetwork(row.SendingIP)
		if net == "" {
			net = "(unparseable)"
		}
		n, ok := networks[net]
		if !ok {
			n = &TLSSenderNetworkRow{Network: net, WhoisOrg: row.WhoisOrg}
			networks[net] = n
		}
		n.FailedSessions += row.FailedSessions
		n.IPs++

		label := row.WhoisOrg
		if label == "" {
			label = "(not enriched)"
		}
		if row.WhoisASN != "" {
			label += " (" + row.WhoisASN + ")"
		}
		o, ok := orgs[label]
		if !ok {
			o = &TLSSenderNetworkRow{Network: label, WhoisOrg: row.WhoisOrg}
			orgs[label] = o
		}
		o.FailedSessions += row.FailedSessions
		o.IPs++
	}
	for _, n := range networks {
		out.ByNetwork = append(out.ByNetwork, *n)
	}
	for _, o := range orgs {
		out.ByOrg = append(out.ByOrg, *o)
	}
	sortNetworks(out.ByNetwork)
	sortNetworks(out.ByOrg)

	if out.ByIP == nil {
		out.ByIP = []TLSSenderRow{}
	}
	if out.ByNetwork == nil {
		out.ByNetwork = []TLSSenderNetworkRow{}
	}
	if out.ByOrg == nil {
		out.ByOrg = []TLSSenderNetworkRow{}
	}
	return out, nil
}

func sortNetworks(rows []TLSSenderNetworkRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].FailedSessions != rows[j].FailedSessions {
			return rows[i].FailedSessions > rows[j].FailedSessions
		}
		return rows[i].Network < rows[j].Network
	})
}

// TLSSenderNetwork returns the network an address rolls up to for T6: /24 for
// IPv4 and /64 for IPv6, the smallest blocks an operator normally assigns to
// one customer. Returns "" when the address does not parse.
func TLSSenderNetwork(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// TLSReasonRow is one failure-reason code in T7.
type TLSReasonRow struct {
	ReasonCode     string `db:"reason_code" json:"reason_code"`
	ResultType     string `db:"result_type" json:"result_type"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	Rows           int64  `db:"rows" json:"rows"`
}

// TLSReasons is T7: free text in the RFC, but highly repetitive in practice —
// this is where the root cause behind validation-failure and
// certificate-not-trusted actually lives (X509_V_ERR_* and friends).
type TLSReasons struct {
	Overall      []TLSReasonRow `json:"overall"`
	ByResultType []TLSReasonRow `json:"by_result_type"`
	// WithoutReason is failure volume whose reporter gave no reason code.
	WithoutReason int64 `json:"without_reason"`
}

// GetTLSReasons is T7.
func GetTLSReasons(db *sqlx.DB, f TLSFilter, limit int) (*TLSReasons, error) {
	if limit <= 0 {
		limit = 25
	}
	where, args := f.whereFailures()
	withReason := whereAnd(where, "f.failure_reason_code != ''")
	limitArgs := append(append([]any{}, args...), limit)

	out := &TLSReasons{}
	if err := db.Select(&out.Overall, `
		SELECT f.failure_reason_code AS reason_code, '' AS result_type,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COUNT(*) AS rows`+tlsFailureJoin+withReason+`
		 GROUP BY reason_code
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, limitArgs...); err != nil {
		return nil, err
	}
	if err := db.Select(&out.ByResultType, `
		SELECT f.failure_reason_code AS reason_code, f.result_type,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COUNT(*) AS rows`+tlsFailureJoin+withReason+`
		 GROUP BY reason_code, f.result_type
		 ORDER BY failed_sessions DESC
		 LIMIT ?`, limitArgs...); err != nil {
		return nil, err
	}
	if err := db.Get(&out.WithoutReason, `
		SELECT COALESCE(SUM(f.failed_session_count), 0)`+tlsFailureJoin+
		whereAnd(where, "f.failure_reason_code = ''"), args...); err != nil {
		return nil, err
	}
	if out.Overall == nil {
		out.Overall = []TLSReasonRow{}
	}
	if out.ByResultType == nil {
		out.ByResultType = []TLSReasonRow{}
	}
	return out, nil
}

// TLSDayCount is one day of a failure series.
type TLSDayCount struct {
	Day            string `db:"day" json:"day"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
}

// TLSEndpointHealth is T10: the health of the mta-sts.<domain> HTTPS host and
// the policy file it serves — nothing to do with the MX hosts, which is why
// it is its own metric.
type TLSEndpointHealth struct {
	FetchError    int64         `json:"sts_policy_fetch_error"`
	WebPKIInvalid int64         `json:"sts_webpki_invalid"`
	PolicyInvalid int64         `json:"sts_policy_invalid"`
	Total         int64         `json:"total"`
	ByDay         []TLSDayCount `json:"by_day"`
}

// GetTLSEndpointHealth is T10.
func GetTLSEndpointHealth(db *sqlx.DB, f TLSFilter) (*TLSEndpointHealth, error) {
	where, args := f.whereFailures()
	stsOnly := whereAnd(where, "f.result_type IN ('sts-policy-fetch-error','sts-webpki-invalid','sts-policy-invalid')")

	var rows []TLSResultTypeRow
	if err := db.Select(&rows, `
		SELECT f.result_type,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COUNT(*) AS rows`+tlsFailureJoin+stsOnly+`
		 GROUP BY f.result_type`, args...); err != nil {
		return nil, err
	}
	out := &TLSEndpointHealth{}
	for _, row := range rows {
		switch row.ResultType {
		case "sts-policy-fetch-error":
			out.FetchError = row.FailedSessions
		case "sts-webpki-invalid":
			out.WebPKIInvalid = row.FailedSessions
		case "sts-policy-invalid":
			out.PolicyInvalid = row.FailedSessions
		}
		out.Total += row.FailedSessions
	}
	if err := db.Select(&out.ByDay, `
		SELECT strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch')) AS day,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions`+tlsFailureJoin+stsOnly+`
		 GROUP BY day ORDER BY day`, args...); err != nil {
		return nil, err
	}
	if out.ByDay == nil {
		out.ByDay = []TLSDayCount{}
	}
	return out, nil
}

// TLSDaneRow is one DANE or DNSSEC failure, with the organisation that
// reported it. dane-required in particular names a partner who has pinned
// mandatory DANE for your domain, so the org is not optional context.
type TLSDaneRow struct {
	ResultType     string `db:"result_type" json:"result_type"`
	OrgName        string `db:"org_name" json:"org_name"`
	PolicyDomain   string `db:"policy_domain" json:"policy_domain"`
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	FirstSeen      int64  `db:"first_seen" json:"first_seen"`
	LastSeen       int64  `db:"last_seen" json:"last_seen"`
}

// GetTLSDaneHealth is T11.
func GetTLSDaneHealth(db *sqlx.DB, f TLSFilter) ([]TLSDaneRow, error) {
	where, args := f.whereFailures()
	var out []TLSDaneRow
	if err := db.Select(&out, `
		SELECT f.result_type, r.org_name, p.policy_domain,
		       CASE WHEN f.receiving_mx_hostname = '' THEN '(unspecified)' ELSE f.receiving_mx_hostname END AS mx_hostname,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       MIN(r.date_range_begin) AS first_seen,
		       MAX(r.date_range_end) AS last_seen`+tlsFailureJoin+
		whereAnd(where, "f.result_type IN ('tlsa-invalid','dnssec-invalid','dane-required')")+`
		 GROUP BY f.result_type, r.org_name, p.policy_domain, mx_hostname
		 ORDER BY failed_sessions DESC`, args...); err != nil {
		return nil, err
	}
	if out == nil {
		out = []TLSDaneRow{}
	}
	return out, nil
}

// TLSFamilySplit is T14: how failures divide between IPv4 and IPv6.
//
// Only failures can be split this way. RFC 8460 reports carry IP addresses on
// failure-detail rows alone — a successful session has no address anywhere in
// the schema — so a true per-family *rate* cannot be derived from these
// reports, and claiming one would be an invention. What this does show is
// whether failures concentrate on one stack, which is the common case and
// invisible in the aggregate figure.
type TLSFamilySplit struct {
	SendingV4      int64 `json:"sending_v4"`
	SendingV6      int64 `json:"sending_v6"`
	SendingUnknown int64 `json:"sending_unknown"`

	ReceivingV4      int64 `json:"receiving_v4"`
	ReceivingV6      int64 `json:"receiving_v6"`
	ReceivingUnknown int64 `json:"receiving_unknown"`

	SendingV6Share   float64 `json:"sending_v6_share"`
	ReceivingV6Share float64 `json:"receiving_v6_share"`
}

// GetTLSFamilySplit is T14.
func GetTLSFamilySplit(db *sqlx.DB, f TLSFilter) (*TLSFamilySplit, error) {
	where, args := f.whereFailures()
	var rows []struct {
		SendingIP   *string `db:"sending_mta_ip"`
		ReceivingIP *string `db:"receiving_ip"`
		Failed      int64   `db:"failed_session_count"`
	}
	if err := db.Select(&rows, `
		SELECT f.sending_mta_ip, f.receiving_ip, f.failed_session_count`+tlsFailureJoin+where, args...); err != nil {
		return nil, err
	}

	out := &TLSFamilySplit{}
	for _, row := range rows {
		switch family(row.SendingIP) {
		case 4:
			out.SendingV4 += row.Failed
		case 6:
			out.SendingV6 += row.Failed
		default:
			out.SendingUnknown += row.Failed
		}
		switch family(row.ReceivingIP) {
		case 4:
			out.ReceivingV4 += row.Failed
		case 6:
			out.ReceivingV6 += row.Failed
		default:
			out.ReceivingUnknown += row.Failed
		}
	}
	if total := out.SendingV4 + out.SendingV6; total > 0 {
		out.SendingV6Share = float64(out.SendingV6) / float64(total) * 100
	}
	if total := out.ReceivingV4 + out.ReceivingV6; total > 0 {
		out.ReceivingV6Share = float64(out.ReceivingV6) / float64(total) * 100
	}
	return out, nil
}

// family returns 4, 6, or 0 when the address is absent or unparseable.
func family(ip *string) int {
	if ip == nil || *ip == "" {
		return 0
	}
	parsed := net.ParseIP(*ip)
	switch {
	case parsed == nil:
		return 0
	case parsed.To4() != nil:
		return 4
	default:
		return 6
	}
}

// TLSIncident is a run of consecutive days on which the same result type was
// reported against the same receiving MX host (T15).
type TLSIncident struct {
	ResultType     string `json:"result_type"`
	MXHostname     string `json:"mx_hostname"`
	FirstDay       string `json:"first_day"`
	LastDay        string `json:"last_day"`
	Days           int    `json:"days"`
	FailedSessions int64  `json:"failed_sessions"`
	Ongoing        bool   `json:"ongoing"`
}

// GetTLSIncidents is T15: it turns a spiky chart into a list an operator can
// work through, by collapsing each (result type, MX host) pair's consecutive
// days into one entry with a duration.
func GetTLSIncidents(db *sqlx.DB, f TLSFilter, now time.Time) ([]TLSIncident, error) {
	where, args := f.whereFailures()
	var rows []struct {
		Day        string `db:"day"`
		ResultType string `db:"result_type"`
		MXHostname string `db:"mx_hostname"`
		Failed     int64  `db:"failed_sessions"`
	}
	if err := db.Select(&rows, `
		SELECT strftime('%Y-%m-%d', datetime(r.date_range_begin, 'unixepoch')) AS day,
		       f.result_type,
		       CASE WHEN f.receiving_mx_hostname = '' THEN '(unspecified)' ELSE f.receiving_mx_hostname END AS mx_hostname,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions`+tlsFailureJoin+
		whereAnd(where, "f.result_type != ''")+`
		 GROUP BY day, f.result_type, mx_hostname
		 ORDER BY f.result_type, mx_hostname, day`, args...); err != nil {
		return nil, err
	}

	const dayFormat = "2006-01-02"
	today := now.UTC().Format(dayFormat)

	var out []TLSIncident
	var cur *TLSIncident
	var lastDay time.Time
	flush := func() {
		if cur != nil {
			cur.Ongoing = cur.LastDay == today
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, row := range rows {
		day, err := time.Parse(dayFormat, row.Day)
		if err != nil {
			continue
		}
		consecutive := cur != nil &&
			cur.ResultType == row.ResultType &&
			cur.MXHostname == row.MXHostname &&
			day.Sub(lastDay) <= 24*time.Hour
		if !consecutive {
			flush()
			cur = &TLSIncident{
				ResultType: row.ResultType, MXHostname: row.MXHostname,
				FirstDay: row.Day, LastDay: row.Day, Days: 1,
				FailedSessions: row.Failed,
			}
		} else {
			cur.LastDay = row.Day
			cur.Days++
			cur.FailedSessions += row.Failed
		}
		lastDay = day
	}
	flush()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Days != out[j].Days {
			return out[i].Days > out[j].Days
		}
		return out[i].FailedSessions > out[j].FailedSessions
	})
	if out == nil {
		out = []TLSIncident{}
	}
	return out, nil
}
