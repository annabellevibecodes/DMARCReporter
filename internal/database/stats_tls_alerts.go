package database

import (
	"strings"

	"github.com/jmoiron/sqlx"
)

// Queries backing the TLS alert rules (X12–X19). They live here rather than
// in the alerts package for the same reason the DMARC rule queries do: the
// SQL belongs with the schema, and the rule stays readable as a threshold.

// TLSResultCount is a failure count attributed to one reporter and host.
type TLSResultCount struct {
	OrgName        string `db:"org_name" json:"org_name"`
	PolicyDomain   string `db:"policy_domain" json:"policy_domain"`
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	ResultType     string `db:"result_type" json:"result_type"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
}

// GetTLSResultTypeOccurrences returns failures of the given result types in
// the window, grouped by reporter, policy domain and receiving host. It backs
// the rules that fire on any occurrence at all (X14, X17).
func GetTLSResultTypeOccurrences(db *sqlx.DB, f TLSFilter, resultTypes []string) ([]TLSResultCount, error) {
	if len(resultTypes) == 0 {
		return nil, nil
	}
	where, args := f.whereFailures()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(resultTypes)), ",")
	for _, rt := range resultTypes {
		args = append(args, rt)
	}

	var out []TLSResultCount
	err := db.Select(&out, `
		SELECT r.org_name, p.policy_domain,
		       CASE WHEN f.receiving_mx_hostname = '' THEN '(unspecified)' ELSE f.receiving_mx_hostname END AS mx_hostname,
		       f.result_type,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions`+tlsFailureJoin+
		whereAnd(where, "f.result_type IN ("+placeholders+")")+`
		 GROUP BY r.org_name, p.policy_domain, mx_hostname, f.result_type
		 ORDER BY failed_sessions DESC`, args...)
	return out, err
}

// TLSPolicyHostErrors is X16: the share of a domain's sessions that failed
// against the MTA-STS policy host rather than against an MX.
type TLSPolicyHostErrors struct {
	PolicyDomain string  `db:"policy_domain" json:"policy_domain"`
	Failures     int64   `db:"failures" json:"failures"`
	Sessions     int64   `db:"sessions" json:"sessions"`
	Percent      float64 `db:"-" json:"percent"`
}

// GetTLSPolicyHostErrors returns policy-host failures per domain with the
// domain's session total, so a rule can express a share.
func GetTLSPolicyHostErrors(db *sqlx.DB, f TLSFilter) ([]TLSPolicyHostErrors, error) {
	cte, sessionArgs := tlsSessions(f)
	failWhere, failArgs := f.whereFailures()

	args := append([]any{}, sessionArgs...)
	args = append(args, failArgs...)

	var out []TLSPolicyHostErrors
	err := db.Select(&out, cte+`
		SELECT s.policy_domain,
		       COALESCE(SUM(s.success) + SUM(s.failure), 0) AS sessions,
		       COALESCE((
		            SELECT SUM(f.failed_session_count)`+tlsFailureJoin+
		whereAnd(failWhere, "f.result_type IN ('sts-policy-fetch-error','sts-webpki-invalid') AND p.policy_domain = s.policy_domain")+`
		       ), 0) AS failures
		  FROM sessions s
		 GROUP BY s.policy_domain`, args...)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Sessions > 0 {
			out[i].Percent = float64(out[i].Failures) / float64(out[i].Sessions) * 100
		}
	}
	return out, nil
}

// TLSStrippedHost is X13: a reporter now seeing STARTTLS refused on a host
// where it used to negotiate TLS successfully.
type TLSStrippedHost struct {
	OrgName        string `json:"org_name"`
	PolicyDomain   string `json:"policy_domain"`
	MXHostname     string `json:"mx_hostname"`
	FailedSessions int64  `json:"failed_sessions"`
	// PriorSuccess is the successful session count that reporter saw for a
	// policy covering this host before the window — the evidence that TLS
	// used to work, which is what makes the new refusal suspicious.
	PriorSuccess int64 `json:"prior_success"`
}

// GetTLSStrippedHosts is X13.
//
// Your server did not stop supporting STARTTLS, so a sender suddenly
// reporting that it did is the classic stripping signature: something in the
// path removed the capability. Low volume, high signal — which is why it is
// its own rule and not folded into a failure-rate threshold.
//
// "Previously succeeded on the same MX host" is evaluated through RFC 8461
// §4.1 pattern matching, because a policy's mx entry may be a wildcard and
// must never be compared to a hostname with equality (I6).
func GetTLSStrippedHosts(db *sqlx.DB, f TLSFilter, minSessions int64) ([]TLSStrippedHost, error) {
	recentWhere, recentArgs := f.whereFailures()

	// Hosts a reporter is now saying refused STARTTLS.
	var recent []struct {
		OrgName      string `db:"org_name"`
		PolicyDomain string `db:"policy_domain"`
		MXHostname   string `db:"mx_hostname"`
		Failed       int64  `db:"failed_sessions"`
	}
	if err := db.Select(&recent, `
		SELECT r.org_name, p.policy_domain, f.receiving_mx_hostname AS mx_hostname,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions`+tlsFailureJoin+
		whereAnd(recentWhere, "f.result_type = 'starttls-not-supported' AND f.receiving_mx_hostname != ''")+`
		 GROUP BY r.org_name, p.policy_domain, mx_hostname
		HAVING failed_sessions >= ?`, append(recentArgs, minSessions)...); err != nil {
		return nil, err
	}
	if len(recent) == 0 {
		return nil, nil
	}

	// Everything that reporter saw for that domain *before* this window: the
	// policy's mx patterns and its success count.
	before := TLSFilter{To: f.From - 1, RequireDKIM: f.RequireDKIM}
	beforeWhere, beforeArgs := before.where()
	var history []struct {
		OrgName      string `db:"org_name"`
		PolicyDomain string `db:"policy_domain"`
		MXPattern    string `db:"mx_host_pattern"`
		Success      int64  `db:"success"`
		Stripped     int64  `db:"stripped"`
	}
	if err := db.Select(&history, `
		SELECT r.org_name, p.policy_domain, p.mx_host_pattern,
		       COALESCE(SUM(p.success_count), 0) AS success,
		       COALESCE((
		            SELECT SUM(hf.failed_session_count) FROM tlsrpt_failures hf
		             WHERE hf.policy_id = p.id AND hf.result_type = 'starttls-not-supported'
		       ), 0) AS stripped
		  FROM tlsrpt_policies p
		  JOIN tlsrpt_reports r ON r.id = p.tlsrpt_report_id`+beforeWhere+`
		 GROUP BY r.org_name, p.policy_domain, p.mx_host_pattern, p.id`, beforeArgs...); err != nil {
		return nil, err
	}

	var out []TLSStrippedHost
	for _, cur := range recent {
		var priorSuccess, priorStripped int64
		for _, h := range history {
			if !strings.EqualFold(h.OrgName, cur.OrgName) || !strings.EqualFold(h.PolicyDomain, cur.PolicyDomain) {
				continue
			}
			covers := false
			for _, pattern := range strings.Split(h.MXPattern, ",") {
				if TLSMXPatternMatches(pattern, cur.MXHostname) {
					covers = true
					break
				}
			}
			if !covers {
				continue
			}
			priorSuccess += h.Success
			priorStripped += h.Stripped
		}
		// Only a host that used to work and was not already being stripped.
		if priorSuccess <= 0 || priorStripped > 0 {
			continue
		}
		out = append(out, TLSStrippedHost{
			OrgName: cur.OrgName, PolicyDomain: cur.PolicyDomain, MXHostname: cur.MXHostname,
			FailedSessions: cur.Failed, PriorSuccess: priorSuccess,
		})
	}
	return out, nil
}

// TLSNewFailingReceiver is X19: a receiving node newly failing under an MX
// host whose other nodes are fine.
type TLSNewFailingReceiver struct {
	PolicyDomain   string `db:"policy_domain" json:"policy_domain"`
	MXHostname     string `db:"mx_hostname" json:"mx_hostname"`
	ReceivingIP    string `db:"receiving_ip" json:"receiving_ip"`
	FailedSessions int64  `db:"failed_sessions" json:"failed_sessions"`
	ResultTypes    string `db:"result_types" json:"result_types"`
	// SiblingNodes is how many other nodes of the same MX host reported no
	// failures in the window — the "otherwise healthy" part of the rule.
	SiblingNodes int `db:"-" json:"sibling_nodes"`
}

// GetTLSNewFailingReceivers is X19.
//
// A load-balanced or anycast MX fails one node at a time, and the aggregate
// rate barely moves. This looks for a receiving IP that is failing now, was
// not failing before the window, and sits behind a host that has other nodes.
func GetTLSNewFailingReceivers(db *sqlx.DB, f TLSFilter, minSessions int64) ([]TLSNewFailingReceiver, error) {
	where, args := f.whereFailures()

	var recent []TLSNewFailingReceiver
	if err := db.Select(&recent, `
		SELECT p.policy_domain, f.receiving_mx_hostname AS mx_hostname, f.receiving_ip,
		       COALESCE(SUM(f.failed_session_count), 0) AS failed_sessions,
		       COALESCE(GROUP_CONCAT(DISTINCT f.result_type), '') AS result_types`+tlsFailureJoin+
		whereAnd(where, "f.receiving_ip IS NOT NULL AND f.receiving_mx_hostname != ''")+`
		 GROUP BY p.policy_domain, mx_hostname, f.receiving_ip
		HAVING failed_sessions >= ?`, append(args, minSessions)...); err != nil {
		return nil, err
	}
	if len(recent) == 0 {
		return nil, nil
	}

	// Nodes that were already failing before the window are not new.
	before := TLSFilter{To: f.From - 1, RequireDKIM: f.RequireDKIM}
	beforeWhere, beforeArgs := before.whereFailures()
	var previous []struct {
		MXHostname  string `db:"mx_hostname"`
		ReceivingIP string `db:"receiving_ip"`
	}
	if err := db.Select(&previous, `
		SELECT DISTINCT f.receiving_mx_hostname AS mx_hostname, f.receiving_ip`+tlsFailureJoin+
		whereAnd(beforeWhere, "f.receiving_ip IS NOT NULL AND f.receiving_mx_hostname != ''"),
		beforeArgs...); err != nil {
		return nil, err
	}
	failedBefore := map[string]bool{}
	for _, p := range previous {
		failedBefore[p.MXHostname+"\x00"+p.ReceivingIP] = true
	}

	// How many nodes each host has been seen on at all, so "otherwise
	// healthy" can mean "the host has other nodes and they are not failing".
	var nodeCounts []struct {
		MXHostname string `db:"mx_hostname"`
		Nodes      int    `db:"nodes"`
	}
	if err := db.Select(&nodeCounts, `
		SELECT f.receiving_mx_hostname AS mx_hostname, COUNT(DISTINCT f.receiving_ip) AS nodes
		  FROM tlsrpt_failures f
		 WHERE f.receiving_mx_hostname != '' AND f.receiving_ip IS NOT NULL
		 GROUP BY mx_hostname`); err != nil {
		return nil, err
	}
	nodes := map[string]int{}
	for _, n := range nodeCounts {
		nodes[n.MXHostname] = n.Nodes
	}

	var out []TLSNewFailingReceiver
	for _, r := range recent {
		if failedBefore[r.MXHostname+"\x00"+r.ReceivingIP] {
			continue
		}
		r.SiblingNodes = nodes[r.MXHostname] - 1
		out = append(out, r)
	}
	return out, nil
}

// TLSReporterSilence is X18: a TLS reporter that has gone quiet.
type TLSReporterSilence = TLSReporterGap

// GetTLSReporterGaps returns TLS reporters active within activeDays that have
// sent nothing for gapDays — the TLS counterpart of X6, over the same shape.
func GetTLSReporterGaps(db *sqlx.DB, now int64, activeDays, gapDays int) ([]TLSReporterGap, error) {
	active := now - int64(activeDays)*86400
	cutoff := now - int64(gapDays)*86400

	var out []TLSReporterGap
	err := db.Select(&out, `
		SELECT org_name, last_begin, last_end,
		       CAST((? - last_end) / 86400 AS INTEGER) AS days_silent
		  FROM (
			SELECT r.org_name,
			       MAX(r.date_range_begin) AS last_begin,
			       MAX(r.date_range_end) AS last_end
			  FROM tlsrpt_reports r
			 GROUP BY r.org_name
		  )
		 WHERE last_end >= ? AND last_end < ?
		 ORDER BY last_end`, now, active, cutoff)
	return out, err
}
