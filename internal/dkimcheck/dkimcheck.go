// Package dkimcheck verifies the DKIM signature of a mail carrying an RFC 8460
// TLS report.
//
// RFC 8460 §3 is stricter than DMARC about this: a report delivered by SMTP
// MUST carry a valid DKIM signature by the reporting domain, MUST NOT use the
// l= body-length tag, and a receiver MUST ignore reports that lack one. The
// signing key record may also carry the s=tlsrpt service type, which a
// receiver MAY additionally require.
//
// The service-type tag lives in the same <selector>._domainkey.<d> TXT record
// the verifier already fetches to check the signature, so this package reads it
// from that lookup rather than querying DNS a second time.
package dkimcheck

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-msgauth/dkim"
)

// Status is the verification outcome stored on a report.
type Status string

const (
	// StatusValid means at least one signature verified.
	StatusValid Status = "valid"
	// StatusInvalid means signatures were present but none verified.
	StatusInvalid Status = "invalid"
	// StatusAbsent means the message carried no DKIM-Signature header.
	StatusAbsent Status = "absent"
	// StatusLTagPresent means a signature used the l= tag, which RFC 8460 §3
	// forbids because it lets an attacker append content to a signed report.
	StatusLTagPresent Status = "l_tag_present"
	// StatusNotApplicable is for reports that did not arrive as mail (a file
	// uploaded through the web form), where there is nothing to verify.
	StatusNotApplicable Status = "not_applicable"
	// StatusUnknown means verification could not be completed — a DNS temp
	// failure, a timeout, or a message this library could not read.
	StatusUnknown Status = "unknown"
)

// defaultTimeout caps the DNS work done while a report is being imported.
// Verification is best-effort: a slow resolver degrades a report to
// StatusUnknown rather than holding up the import.
const defaultTimeout = 5 * time.Second

// Result is what verification found.
type Result struct {
	Status   Status
	Domain   string // d= of the signature the status refers to
	Selector string // s= of that signature
	// ServiceTLSRPT reports that the signing key record carries an explicit
	// s=tlsrpt service type. A key record with no s= tag defaults to "*" (all
	// service types) per RFC 6376 §3.6.1 and is *not* counted here: this
	// records what the reporter published, not what is permitted.
	ServiceTLSRPT bool
	// Detail is the verifier's error text when Status is invalid or unknown.
	Detail string
}

// Options tunes verification. The zero value is what production uses.
type Options struct {
	// LookupTXT replaces DNS resolution (tests, and any caller that wants to
	// supply its own resolver). When nil, a resolver bounded by Timeout is used.
	LookupTXT func(name string) ([]string, error)
	// Timeout bounds the default resolver; defaultTimeout when zero.
	Timeout time.Duration
}

// Verify checks the DKIM signatures of a raw RFC 5322 message.
//
// It never returns an error: every failure mode is a Status, because a report
// that cannot be verified still has to be stored and shown with the reason.
func Verify(raw []byte, opts *Options) Result {
	if len(raw) == 0 {
		return Result{Status: StatusUnknown, Detail: "empty message"}
	}
	if opts == nil {
		opts = &Options{}
	}

	sigs := parseSignatureHeaders(raw)
	if len(sigs) == 0 {
		return Result{Status: StatusAbsent}
	}
	// The l= tag is disqualifying on its own, whether or not the signature
	// verifies: the unsigned remainder of the body could say anything.
	for _, s := range sigs {
		if _, ok := s["l"]; ok {
			return Result{
				Status: StatusLTagPresent, Domain: s["d"], Selector: s["s"],
				Detail: "signature carries the l= body-length tag, which RFC 8460 §3 forbids",
			}
		}
	}

	rec := &recordingResolver{lookup: opts.LookupTXT, timeout: opts.Timeout}
	verifications, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        rec.LookupTXT,
		MaxVerifications: 10,
	})
	if err != nil && len(verifications) == 0 {
		return Result{Status: StatusUnknown, Detail: err.Error()}
	}

	var firstErr error
	for _, v := range verifications {
		if v.Err == nil {
			res := Result{Status: StatusValid, Domain: v.Domain}
			res.Selector = selectorFor(sigs, v.Domain)
			res.ServiceTLSRPT = rec.hasTLSRPTService(res.Selector, v.Domain)
			return res
		}
		if firstErr == nil {
			firstErr = v.Err
		}
	}

	// Two RFCs disagree here, and reporters follow the newer one. RFC 6376
	// §3.6.1 says a key whose s= list omits "email" must not verify an email
	// message — and a mailed TLS report is email. RFC 8460 §3 nonetheless
	// publishes "v=DKIM1; k=rsa; s=tlsrpt; p=..." as *the* key record for
	// signing these reports, so a strict verifier refuses exactly the
	// signatures the TLS-RPT spec tells senders to produce.
	//
	// When a key record we fetched does carry s=tlsrpt, re-run the check with
	// the service list widened — replayed from the records already fetched,
	// so no second DNS query. If it passes, the signature is cryptographically
	// sound and was refused only over that conflict, which is precisely the
	// case RFC 8460 intends to accept.
	if rec.hasAnyTLSRPTService() {
		widened, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
			LookupTXT:        rec.replayWithAllServices(),
			MaxVerifications: 10,
		})
		if err == nil || len(widened) > 0 {
			for _, v := range widened {
				if v.Err == nil {
					return Result{
						Status: StatusValid, Domain: v.Domain,
						Selector: selectorFor(sigs, v.Domain), ServiceTLSRPT: true,
					}
				}
			}
		}
	}

	res := Result{Status: StatusInvalid, Domain: sigs[0]["d"], Selector: sigs[0]["s"]}
	if firstErr != nil {
		res.Detail = firstErr.Error()
		// A temp failure is "we could not tell", not "the report is bad".
		if dkim.IsTempFail(firstErr) {
			res.Status = StatusUnknown
		}
	}
	return res
}

// DomainMatches reports whether the signing domain covers addr's domain —
// used to record whether d= matches the report's contact-info address, as
// RFC 8460 §3 expects. A signature by the organisational parent counts.
func DomainMatches(signing, addr string) bool {
	addrDomain := addr
	if i := strings.LastIndex(addrDomain, "@"); i >= 0 {
		addrDomain = addrDomain[i+1:]
	}
	addrDomain = strings.Trim(strings.ToLower(strings.TrimSpace(addrDomain)), ".")
	signing = strings.Trim(strings.ToLower(strings.TrimSpace(signing)), ".")
	if signing == "" || addrDomain == "" {
		return false
	}
	return signing == addrDomain || strings.HasSuffix(addrDomain, "."+signing)
}

// recordingResolver wraps the TXT lookup so the key records fetched during
// verification can be re-read for their s= tag without a second query.
type recordingResolver struct {
	lookup  func(name string) ([]string, error)
	timeout time.Duration

	mu      sync.Mutex
	records map[string][]string
}

func (r *recordingResolver) LookupTXT(name string) ([]string, error) {
	txts, err := r.resolve(name)
	r.mu.Lock()
	if r.records == nil {
		r.records = map[string][]string{}
	}
	r.records[strings.ToLower(strings.TrimSuffix(name, "."))] = txts
	r.mu.Unlock()
	return txts, err
}

func (r *recordingResolver) resolve(name string) ([]string, error) {
	if r.lookup != nil {
		return r.lookup(name)
	}
	timeout := r.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return net.DefaultResolver.LookupTXT(ctx, name)
}

// hasTLSRPTService reports whether the key record used for selector/domain
// lists tlsrpt in its s= tag.
func (r *recordingResolver) hasTLSRPTService(selector, domain string) bool {
	if selector == "" || domain == "" {
		return false
	}
	key := strings.ToLower(fmt.Sprintf("%s._domainkey.%s", selector, domain))
	r.mu.Lock()
	txts := r.records[key]
	r.mu.Unlock()

	for _, txt := range txts {
		if serviceTagIncludesTLSRPT(txt) {
			return true
		}
	}
	return false
}

// hasAnyTLSRPTService reports whether any key record fetched during
// verification lists tlsrpt among its service types.
func (r *recordingResolver) hasAnyTLSRPTService() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, txts := range r.records {
		for _, txt := range txts {
			if serviceTagIncludesTLSRPT(txt) {
				return true
			}
		}
	}
	return false
}

// replayWithAllServices returns a resolver that serves the already-fetched key
// records with their service-type restriction lifted. It never queries DNS: a
// name that was not fetched during the first pass is an error.
func (r *recordingResolver) replayWithAllServices() func(string) ([]string, error) {
	r.mu.Lock()
	snapshot := make(map[string][]string, len(r.records))
	for name, txts := range r.records {
		widened := make([]string, len(txts))
		for i, txt := range txts {
			widened[i] = widenServiceTag(txt)
		}
		snapshot[name] = widened
	}
	r.mu.Unlock()

	return func(name string) ([]string, error) {
		txts, ok := snapshot[strings.ToLower(strings.TrimSuffix(name, "."))]
		if !ok {
			return nil, fmt.Errorf("dkimcheck: no recorded key record for %s", name)
		}
		return txts, nil
	}
}

// serviceTagIncludesTLSRPT reports whether a key record's s= tag lists tlsrpt.
func serviceTagIncludesTLSRPT(txt string) bool {
	for _, tag := range strings.Split(txt, ";") {
		name, value, ok := strings.Cut(tag, "=")
		if !ok || strings.TrimSpace(name) != "s" {
			continue
		}
		for _, service := range strings.Split(value, ":") {
			if strings.EqualFold(strings.TrimSpace(service), "tlsrpt") {
				return true
			}
		}
	}
	return false
}

// widenServiceTag rewrites a key record's s= tag to "*" (all service types),
// leaving every other tag — the key material included — untouched.
func widenServiceTag(txt string) string {
	tags := strings.Split(txt, ";")
	for i, tag := range tags {
		name, _, ok := strings.Cut(tag, "=")
		if !ok || strings.TrimSpace(name) != "s" {
			continue
		}
		// Keep the original leading whitespace so the record still reads
		// the way the reporter published it.
		lead := tag[:len(tag)-len(strings.TrimLeft(tag, " \t"))]
		tags[i] = lead + "s=*"
	}
	return strings.Join(tags, ";")
}

// parseSignatureHeaders returns the tag maps of every DKIM-Signature header,
// in the order they appear. go-msgauth exposes the verification result but not
// the signature's own tags, and RFC 8460 needs two of them: s= to find the key
// record, and l= to reject the signature outright.
func parseSignatureHeaders(raw []byte) []map[string]string {
	var out []map[string]string
	for _, field := range headerFields(raw) {
		name, value, ok := strings.Cut(field, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "DKIM-Signature") {
			continue
		}
		tags := map[string]string{}
		for _, tag := range strings.Split(value, ";") {
			k, v, ok := strings.Cut(tag, "=")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			// Only the first occurrence of a tag counts (RFC 6376 §3.2).
			if _, seen := tags[k]; !seen {
				tags[k] = strings.TrimSpace(v)
			}
		}
		out = append(out, tags)
	}
	return out
}

// headerFields splits a raw message's header block into unfolded fields.
func headerFields(raw []byte) []string {
	header := raw
	// The header block ends at the first blank line, in either line ending.
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		header = raw[:i]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		header = raw[:i]
	}
	text := strings.ReplaceAll(string(header), "\r\n", "\n")

	var fields []string
	var current strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			current.WriteString(" ")
			current.WriteString(strings.TrimSpace(line))
			continue
		}
		if current.Len() > 0 {
			fields = append(fields, current.String())
			current.Reset()
		}
		current.WriteString(line)
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	return fields
}

// selectorFor returns the s= tag of the first signature whose d= is domain.
func selectorFor(sigs []map[string]string, domain string) string {
	for _, s := range sigs {
		if strings.EqualFold(s["d"], domain) {
			return s["s"]
		}
	}
	return ""
}
