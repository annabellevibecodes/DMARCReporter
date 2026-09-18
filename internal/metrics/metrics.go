// Package metrics is the catalogue of metric identifiers (C1–C8, S1–S6,
// A1–A8, P1–P6, R1–R8 and the X alert rules) used throughout the interface.
// It is the single source of truth for the one-line summary shown when a
// reference is hovered, and for where each one is documented in the Help
// pages.
package metrics

import (
	"fmt"
	"html/template"
	"sort"
	"strings"
)

// Metric is one identifier with the text shown in its tooltip.
type Metric struct {
	ID      string
	Name    string
	Summary string // one plain-text line
	Href    string // Help page anchor documenting it
}

// Family groups the identifiers that share a letter.
type Family struct {
	Letter  string
	Title   string
	Summary string
	Href    string
}

const (
	hrefCompliance = "/help/metrics#compliance"
	hrefSources    = "/help/metrics#sources"
	hrefAuth       = "/help/metrics#auth"
	hrefPolicy     = "/help/metrics#policy"
	hrefReporters  = "/help/metrics#reporters"
	hrefTLS        = "/help/metrics#tls"
	hrefAlerts     = "/help/alerts#alerts"
)

// Families is every identifier family, in display order.
var Families = []Family{
	{"C", "Compliance (C1–C8)", "Volume, pass rates, the authentication matrix, disposition and enforcement.", hrefCompliance},
	{"S", "Sources (S1–S6)", "Who is sending as you, and how each sending IP behaves.", hrefSources},
	{"A", "Authentication (A1–A8)", "The raw DKIM and SPF detail behind the pass or fail verdict.", hrefAuth},
	{"P", "Policy (P1–P6)", "Your published DMARC record as reporters actually saw it.", hrefPolicy},
	{"R", "Reporters (R1–R8)", "Who sends you reports, how promptly, and report hygiene.", hrefReporters},
	{"T", "TLS (T1–T15)", "SMTP TLS reporting: session success, policies applied, and why connections failed.", hrefTLS},
	{"X", "Alerts (X1–X19)", "The rules that raise alerts when a metric crosses its threshold.", hrefAlerts},
}

// All is every identifier, keyed by ID.
var All = map[string]Metric{
	// Compliance.
	"C1": {"C1", "Volume", "Total messages in the window, with the reports, domains and reporters behind them.", hrefCompliance},
	"C2": {"C2", "DMARC pass rate", "Share of messages where the aligned DKIM or aligned SPF result passed.", hrefCompliance},
	"C3": {"C3", "Aligned DKIM pass rate", "Share of messages whose evaluated DKIM result passed, counted on its own.", hrefCompliance},
	"C4": {"C4", "Aligned SPF pass rate", "Share of messages whose evaluated SPF result passed, counted on its own.", hrefCompliance},
	"C5": {"C5", "Authentication matrix", "Every message in one of four cells: both aligned, DKIM only, SPF only, or neither.", hrefCompliance},
	"C6": {"C6", "Disposition split", "What receivers actually did: delivered, quarantined or rejected.", hrefCompliance},
	"C7": {"C7", "Enforcement effectiveness", "Share of failing mail receivers actually quarantined or rejected; n/a while p=none.", hrefCompliance},
	"C8": {"C8", "Policy overrides", "Failing mail delivered against your policy, by reason; rows with no reason are unexplained.", hrefCompliance},

	// Sources.
	"S1": {"S1", "Source inventory", "One row per sending IP with its own matrix, raw results, disposition split and label.", hrefSources},
	"S2": {"S2", "New sources", "IPs whose first appearance anywhere in your data falls inside the selected period.", hrefSources},
	"S3": {"S3", "Source pattern", "A source classed healthy, forwarder, broken signing, spoof suspect or mixed from its own matrix.", hrefSources},
	"S4": {"S4", "Spoof volume", "Unauthenticated mail split by whether the sending IP is inside the domain's SPF networks.", hrefSources},
	"S5": {"S5", "Top failing sources", "Sources ranked by failure rate rather than volume, above a minimum message count.", hrefSources},
	"S6": {"S6", "Source enrichment", "Reverse DNS, provider name, WHOIS organisation, ASN and country for a sending IP.", hrefSources},

	// Authentication.
	"A1": {"A1", "Selector inventory", "Every DKIM selector seen signing, with first and last seen and your expected flag.", hrefAuth},
	"A2": {"A2", "Raw DKIM results", "Distribution of the DKIM result reporters recorded, before alignment is considered.", hrefAuth},
	"A3": {"A3", "Signing alignment", "How each signature's domain relates to the From domain: exact, relaxed or third party.", hrefAuth},
	"A4": {"A4", "Raw SPF results", "Distribution of the SPF result reporters recorded, before alignment is considered.", hrefAuth},
	"A5": {"A5", "SPF scope", "Whether SPF was checked against the envelope sender (mfrom) or the HELO name.", hrefAuth},
	"A6": {"A6", "Envelope-from alignment", "Each envelope-from value classed exact, relaxed, misaligned, or null sender.", hrefAuth},
	"A7": {"A7", "Alignment gap", "Mail where a raw check passed but the aligned result did not: a configuration problem, not an attack.", hrefAuth},
	"A8": {"A8", "DNS error rate", "Share of raw results that were temperror or permerror, per reporting organisation.", hrefAuth},

	// Policy.
	"P1": {"P1", "Active policy", "The full published DMARC record as reporters saw it, plus each reporter's own view.", hrefPolicy},
	"P2": {"P2", "Policy consistency", "Every distinct record seen in the window, with the reporters that saw each.", hrefPolicy},
	"P3": {"P3", "Policy change log", "Each change of the majority record, with the pass rate 7 days before and after.", hrefPolicy},
	"P4": {"P4", "Subdomain traffic", "Mail whose From domain is a subdomain of the policy domain, governed by sp rather than p.", hrefPolicy},
	"P5": {"P5", "pct sampling", "Shown when pct is below 100: the expected versus the observed sampled-out share.", hrefPolicy},
	"P6": {"P6", "Enforcement readiness", "Whether tightening the policy is safe: what would be blocked, or known-good mail at risk.", hrefPolicy},

	// Reporters.
	"R1": {"R1", "Reporter inventory", "Each reporting organisation with its report count, volume, share and schema versions.", hrefReporters},
	"R2": {"R2", "Reporter gaps", "Reporters that were recently active but have gone quiet, plus a per-day presence strip.", hrefReporters},
	"R3": {"R3", "Report latency", "How long after a window closes a report arrives, as median and 95th percentile per reporter.", hrefReporters},
	"R4": {"R4", "Window anomalies", "Reports whose window is not roughly a day, outside 23 to 25 hours.", hrefReporters},
	"R5": {"R5", "Duplicates", "Reports rejected on import because that organisation and report ID were already stored.", hrefReporters},
	"R6": {"R6", "Parse errors and schema", "Attachments that failed to parse, with the report version and namespace distribution.", hrefReporters},
	"R7": {"R7", "Unmanaged domains", "Policy domains appearing in reports that are not on your managed-domains list.", hrefReporters},
	"R8": {"R8", "Recipient domains", "The receiving domains your mail reached, with the pass rate at each.", hrefReporters},

	// TLS reporting (RFC 8460).
	"T1":  {"T1", "TLS success rate", "Share of reported sessions that negotiated TLS successfully, overall, per day and per domain.", hrefTLS},
	"T2":  {"T2", "Volume and reporter share", "Sessions per day and per reporter, with both the session-weighted rate and the per-reporter median.", hrefTLS},
	"T3":  {"T3", "Policy-type mix", "Share of sessions under an MTA-STS policy, a TLSA record, or no policy at all.", hrefTLS},
	"T4":  {"T4", "Failures by result type", "Failure volume per RFC 8460 result type, grouped as negotiation, DANE, MTA-STS or unregistered.", hrefTLS},
	"T5":  {"T5", "Failures by receiver", "Failures by receiving MX host, by receiving IP, and HELO names that disagree with their host.", hrefTLS},
	"T6":  {"T6", "Failures by sender", "Failures by sending MTA, rolled up to network and provider using the shared rDNS and WHOIS cache.", hrefTLS},
	"T7":  {"T7", "Top failure reasons", "The most frequent failure-reason codes, overall and within each result type.", hrefTLS},
	"T8":  {"T8", "Policy divergence", "More than one policy string seen for the same domain on the same day: a stale cache or a divergent policy.", hrefTLS},
	"T9":  {"T9", "MTA-STS mode and readiness", "Observed policy modes, and what the failures seen in testing would have cost in enforce.", hrefTLS},
	"T10": {"T10", "MTA-STS endpoint health", "Fetch, WebPKI and policy-parse errors — the mta-sts host and its policy file, not the MX.", hrefTLS},
	"T11": {"T11", "DANE and DNSSEC health", "tlsa-invalid, dnssec-invalid and dane-required occurrences, each with the organisation reporting it.", hrefTLS},
	"T12": {"T12", "TLS reporter coverage", "Distinct, new and lapsed TLS reporters, days without a report, and arrival latency.", hrefTLS},
	"T13": {"T13", "TLS hygiene", "Everything that makes the TLS numbers less trustworthy: duplicates, DKIM rejections, unattributed failures.", hrefTLS},
	"T14": {"T14", "IPv4 vs IPv6", "How failures divide between address families, for both sending and receiving addresses.", hrefTLS},
	"T15": {"T15", "TLS incidents", "Consecutive days sharing one result type and receiving host, as a worklist with durations.", hrefTLS},

	// Alert rules.
	"X1":  {"X1", "new_failing_source", "A source IP first seen recently is failing DMARC for a domain.", hrefAlerts},
	"X2":  {"X2", "pass_rate_drop", "A domain's 7-day pass rate fell versus the previous 7 days.", hrefAlerts},
	"X3":  {"X3", "known_source_degraded", "A source labelled known_good passes far less than its 7-day baseline.", hrefAlerts},
	"X4":  {"X4", "new_selector", "A DKIM selector not marked expected started signing.", hrefAlerts},
	"X5":  {"X5", "selector_missing", "A selector marked expected has not signed recently.", hrefAlerts},
	"X6":  {"X6", "reporter_silent", "A reporter active in the last 14 days stopped sending.", hrefAlerts},
	"X7":  {"X7", "policy_changed", "The published DMARC record changed as seen by reporters.", hrefAlerts},
	"X8":  {"X8", "policy_inconsistent", "Reporters disagree on a domain's effective record.", hrefAlerts},
	"X9":  {"X9", "dns_error_spike", "A reporter logged DNS temporary or permanent errors on many raw results.", hrefAlerts},
	"X10": {"X10", "override_spike", "Policy-override volume jumped versus its 7-day daily mean.", hrefAlerts},
	"X11": {"X11", "spoof_spike", "Unauthenticated mail from IPs outside the domain's SPF record spiked.", hrefAlerts},
	"X12": {"X12", "tls_rate_drop", "A domain's 7-day TLS success rate fell versus the previous 7 days.", hrefAlerts},
	"X13": {"X13", "tls_starttls_stripped", "A reporter that used to negotiate TLS with a host now says STARTTLS was not offered.", hrefAlerts},
	"X14": {"X14", "tls_cert_expired", "A reporter saw an expired certificate on one of your MX hosts.", hrefAlerts},
	"X15": {"X15", "tls_policy_inconsistent", "Reporters disagree about your TLS policy, or applied one you no longer publish.", hrefAlerts},
	"X16": {"X16", "tls_policy_host_error", "Senders could not fetch or validate your MTA-STS policy file.", hrefAlerts},
	"X17": {"X17", "tls_dane_invalid", "A reporter could not validate your DANE records.", hrefAlerts},
	"X18": {"X18", "tls_reporter_silent", "A TLS reporter active in the last 14 days has stopped sending reports.", hrefAlerts},
	"X19": {"X19", "tls_new_failing_receiver", "A receiving node started failing under an MX host whose other nodes are fine.", hrefAlerts},
}

// Get returns the metric with the given ID.
func Get(id string) (Metric, bool) {
	m, ok := All[strings.ToUpper(strings.TrimSpace(id))]
	return m, ok
}

// FamilyOf returns the family an ID belongs to.
func FamilyOf(id string) (Family, bool) {
	id = strings.ToUpper(strings.TrimSpace(id))
	if id == "" {
		return Family{}, false
	}
	for _, f := range Families {
		if strings.HasPrefix(id, f.Letter) {
			return f, true
		}
	}
	return Family{}, false
}

// IDs returns every identifier, sorted by family order then number.
func IDs() []string {
	out := make([]string, 0, len(All))
	for id := range All {
		out = append(out, id)
	}
	rank := map[string]int{}
	for i, f := range Families {
		rank[f.Letter] = i
	}
	sort.Slice(out, func(i, j int) bool {
		fi, fj := rank[out[i][:1]], rank[out[j][:1]]
		if fi != fj {
			return fi < fj
		}
		if len(out[i]) != len(out[j]) {
			return len(out[i]) < len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

// tooltip is the text shown on hover.
func (m Metric) tooltip() string {
	return m.ID + " · " + m.Name + " — " + m.Summary
}

// Tag renders one identifier as a link to its Help entry carrying a tooltip.
// An unrecognised ID is rendered as plain escaped text so a typo degrades to
// what it says rather than to a broken link.
func Tag(id string) template.HTML {
	m, ok := Get(id)
	if !ok {
		return template.HTML(template.HTMLEscapeString(id))
	}
	return render(m.ID, m.Href, m.tooltip())
}

// RangeTag renders a span of identifiers such as "A1–A8" as one link to the
// family's Help section.
func RangeTag(from, to string) template.HTML {
	f, ok := FamilyOf(from)
	if !ok {
		return template.HTML(template.HTMLEscapeString(from + "–" + to))
	}
	label := strings.ToUpper(strings.TrimSpace(from)) + "–" + strings.ToUpper(strings.TrimSpace(to))
	return render(label, f.Href, f.Title+" — "+f.Summary)
}

func render(label, href, tip string) template.HTML {
	return template.HTML(fmt.Sprintf(
		`<a class="metric-id" href="%s" title="%s">%s</a>`,
		template.HTMLEscapeString(href),
		template.HTMLEscapeString(tip),
		template.HTMLEscapeString(label),
	))
}
