package handlers

import (
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
)

// DMARCRecord holds a parsed DMARC DNS TXT record.
type DMARCRecord struct {
	Found bool
	Error string
	Raw   string
	Tags  []DMARCTag
}

// DMARCTag is one key=value pair from the DMARC TXT record.
type DMARCTag struct {
	Key         string
	Value       string
	Label       string // human-readable key name
	Explanation string // plain-English description of this tag's effect
}

var dmarcTagLabels = map[string]string{
	"v":     "Version",
	"p":     "Policy",
	"sp":    "Subdomain Policy",
	"rua":   "Aggregate Reports (rua)",
	"ruf":   "Forensic Reports (ruf)",
	"adkim": "DKIM Alignment",
	"aspf":  "SPF Alignment",
	"pct":   "Percentage",
	"fo":    "Failure Options",
	"rf":    "Report Format",
	"ri":    "Report Interval",
}

func lookupDMARCRecord(domain string) DMARCRecord {
	txts, err := net.LookupTXT("_dmarc." + domain)
	if err != nil {
		return DMARCRecord{Error: err.Error()}
	}
	// Find the DMARC record among all TXT entries.
	var raw string
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=DMARC1") {
			raw = t
			break
		}
	}
	if raw == "" {
		return DMARCRecord{Error: "no DMARC record found at _dmarc." + domain}
	}

	rec := DMARCRecord{Found: true, Raw: raw}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		val := strings.TrimSpace(part[idx+1:])
		label := dmarcTagLabels[key]
		if label == "" {
			label = key
		}
		rec.Tags = append(rec.Tags, DMARCTag{Key: key, Value: val, Label: label, Explanation: dmarcExplain(key, val)})
	}
	return rec
}

// dmarcExplain returns a plain-English description of a DMARC tag value.
func dmarcExplain(key, val string) string {
	switch key {
	case "v":
		return "DMARC version identifier — must be DMARC1."
	case "p":
		switch val {
		case "none":
			return "Monitor mode — no action is taken on failing mail; reports are still sent. Use this while you are gathering data."
		case "quarantine":
			return "Quarantine mode — mail failing DMARC is sent to spam/junk by receiving servers."
		case "reject":
			return "Reject mode — mail failing DMARC is refused outright by receiving servers. Maximum protection against spoofing."
		}
	case "sp":
		switch val {
		case "none":
			return "Subdomains are in monitor mode — no action taken on subdomain mail that fails DMARC."
		case "quarantine":
			return "Subdomain mail failing DMARC is quarantined."
		case "reject":
			return "Subdomain mail failing DMARC is rejected."
		}
	case "adkim":
		switch val {
		case "r", "":
			return "Relaxed DKIM alignment — the DKIM signing domain may be a parent domain of the From: header domain."
		case "s":
			return "Strict DKIM alignment — the DKIM signing domain must exactly match the From: header domain."
		}
	case "aspf":
		switch val {
		case "r", "":
			return "Relaxed SPF alignment — the SPF authenticated domain may be a parent domain of the From: header domain."
		case "s":
			return "Strict SPF alignment — the SPF authenticated domain must exactly match the From: header domain."
		}
	case "pct":
		if val == "100" {
			return "Policy applies to 100% of messages."
		}
		return "Policy applies to " + val + "% of messages — the rest are treated as if the policy were 'none'."
	case "fo":
		switch val {
		case "0", "":
			return "Generate a forensic report only if both DKIM and SPF fail (default)."
		case "1":
			return "Generate a forensic report if either DKIM or SPF fails."
		case "d":
			return "Generate a forensic report if DKIM fails, regardless of SPF result."
		case "s":
			return "Generate a forensic report if SPF fails, regardless of DKIM result."
		}
	case "rf":
		if val == "afrf" || val == "" {
			return "Report format: Authentication Failure Reporting Format (AFRF / RFC 5965)."
		}
	case "ri":
		return "Aggregate reports are requested every " + val + " seconds (default 86400 = 24 hours)."
	case "rua":
		return "Aggregate (RUA) reports are sent to this address. These summarise all mail claiming to be from your domain."
	case "ruf":
		return "Forensic (RUF) failure reports are sent to this address. These contain details of individual failing messages. Many providers no longer send these due to privacy concerns."
	}
	return ""
}

// BIMIRecord holds a parsed BIMI DNS TXT record.
type BIMIRecord struct {
	Found   bool
	Error   string
	Raw     string
	LogoURL string // l= tag
	VMCCert string // a= tag
}

// MTASTSRecord holds a parsed MTA-STS DNS TXT record.
type MTASTSRecord struct {
	Found bool
	Error string
	Raw   string
	ID    string // id= tag
}

func lookupBIMI(domain string) BIMIRecord {
	txts, err := net.LookupTXT("default._bimi." + domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return BIMIRecord{} // NXDOMAIN — no record, not an error
		}
		return BIMIRecord{Error: err.Error()}
	}
	var raw string
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=BIMI1") {
			raw = t
			break
		}
	}
	if raw == "" {
		return BIMIRecord{} // DNS answered but no BIMI TXT present
	}
	rec := BIMIRecord{Found: true, Raw: raw}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		val := strings.TrimSpace(part[idx+1:])
		switch key {
		case "l":
			rec.LogoURL = val
		case "a":
			rec.VMCCert = val
		}
	}
	return rec
}

func lookupMTASTS(domain string) MTASTSRecord {
	txts, err := net.LookupTXT("_mta-sts." + domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return MTASTSRecord{} // NXDOMAIN — no record, not an error
		}
		return MTASTSRecord{Error: err.Error()}
	}
	var raw string
	for _, t := range txts {
		if strings.HasPrefix(strings.TrimSpace(t), "v=STSv1") {
			raw = t
			break
		}
	}
	if raw == "" {
		return MTASTSRecord{} // DNS answered but no MTA-STS TXT present
	}
	rec := MTASTSRecord{Found: true, Raw: raw}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:idx]))
		val := strings.TrimSpace(part[idx+1:])
		if key == "id" {
			rec.ID = val
		}
	}
	return rec
}

// domainRe accepts valid RFC 1123 hostnames (including internationalized labels are not validated here,
// but DMARC domains in practice are ASCII).
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)

const domainsPageSize = 50

func (a *App) HandleDomainsList(c *fiber.Ctx) error {
	page, _ := strconv.Atoi(c.Query("page", "1"))
	domains, total, err := database.ListDomainsPaged(a.DB, page, domainsPageSize)
	if err != nil {
		return err
	}
	totalPages := (total + domainsPageSize - 1) / domainsPageSize
	return c.Render("domains", fiber.Map{
		"Title":       "Domains — DMARC Reporter",
		"Theme":       getTheme(c),
		"ActivePage":  "domains",
		"Domains":     domains,
		"Page":        page,
		"TotalPages":  totalPages,
		"Total":       total,
		"PageNums":    pageWindow(page, totalPages),
		"IMAPEnabled": a.Cfg.IMAPHost != "",
		"CSRFToken":   c.Locals("csrf"),
	}, "layouts/base")
}

func (a *App) HandleDomainDetail(c *fiber.Ctx) error {
	domain := c.Params("domain")
	if domain == "" || len(domain) > 253 || !domainRe.MatchString(domain) {
		return fiber.ErrBadRequest
	}

	records, err := database.GetDomainRecords(a.DB, domain, 100)
	if err != nil {
		return err
	}

	trend, err := database.GetDomainTrend(a.DB, domain, 90)
	if err != nil {
		return err
	}

	type trendPayload struct {
		Labels []string `json:"labels"`
		Passed []int64  `json:"passed"`
		Failed []int64  `json:"failed"`
	}
	td := trendPayload{}
	for _, pt := range trend {
		td.Labels = append(td.Labels, pt.Week)
		td.Passed = append(td.Passed, pt.Passed)
		td.Failed = append(td.Failed, pt.Failed)
	}
	trendBytes, err := json.Marshal(td)
	if err != nil {
		return err
	}

	recipients, err := database.GetEnvelopeToBreakdown(a.DB, domain, 25)
	if err != nil {
		return err
	}

	// Compute summary from records
	var totalMsgs, totalPassed, totalFailed int
	uniqueIPs := map[string]struct{}{}
	uniqueRecipients := map[string]struct{}{}
	for _, r := range records {
		totalMsgs += r.Count
		if r.EvalDKIM == "pass" || r.EvalSPF == "pass" {
			totalPassed += r.Count
		} else {
			totalFailed += r.Count
		}
		uniqueIPs[r.SourceIP] = struct{}{}
		if r.EnvelopeTo != "" && r.EnvelopeTo != "<>" {
			uniqueRecipients[r.EnvelopeTo] = struct{}{}
		}
	}
	var passRate float64
	if totalMsgs > 0 {
		passRate = float64(totalPassed) / float64(totalMsgs) * 100
	}

	dkimSelectors, err := database.GetDKIMSelectorStats(a.DB, domain)
	if err != nil {
		return err
	}

	type selectorPayload struct {
		Labels []string `json:"labels"`
		Passed []int64  `json:"passed"`
		Failed []int64  `json:"failed"`
	}
	sp := selectorPayload{}
	for _, s := range dkimSelectors {
		label := s.Selector
		if s.SigningDomain != "" && s.SigningDomain != domain {
			label = s.Selector + " (" + s.SigningDomain + ")"
		}
		sp.Labels = append(sp.Labels, label)
		sp.Passed = append(sp.Passed, s.Passed)
		sp.Failed = append(sp.Failed, s.Failed)
	}
	selectorBytes, err := json.Marshal(sp)
	if err != nil {
		return err
	}

	dmarcRec := lookupDMARCRecord(domain)
	bimiRec := lookupBIMI(domain)
	mtaStsRec := lookupMTASTS(domain)

	return c.Render("domain_detail", fiber.Map{
		"Title":            domain + " — DMARC Reporter",
		"Theme":            getTheme(c),
		"ActivePage":       "domains",
		"Domain":           domain,
		"Records":          records,
		"TotalMessages":    totalMsgs,
		"TotalPassed":      totalPassed,
		"TotalFailed":      totalFailed,
		"PassRate":         passRate,
		"UniqueSenders":    len(uniqueIPs),
		"UniqueRecipients": len(uniqueRecipients),
		"RecipientDomains": recipients,
		"DomainTrendData":  template.JS(trendBytes),
		"DKIMSelectors":    dkimSelectors,
		"DKIMSelectorData": template.JS(selectorBytes),
		"DMARCRecord":      dmarcRec,
		"BIMIRecord":       bimiRec,
		"MTASTSRecord":     mtaStsRec,
		"IMAPEnabled":      a.Cfg.IMAPHost != "",
		"CSRFToken":        c.Locals("csrf"),
	}, "layouts/base")
}
