package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
	"github.com/annabellevibecodes/dmarcreporter/internal/spf"
	"github.com/jmoiron/sqlx"
)

// EnrichStatus is a point-in-time snapshot of the enrichment worker's state.
type EnrichStatus struct {
	Running     bool   `json:"running"`
	IPTotal     int    `json:"ip_total"`
	IPDone      int    `json:"ip_done"`
	DomainTotal int    `json:"domain_total"`
	DomainDone  int    `json:"domain_done"`
	SPFTotal    int    `json:"spf_total"`
	SPFDone     int    `json:"spf_done"`
	Error       string `json:"error,omitempty"`
}

// spfCacheTTL is how long a resolved SPF expansion stays fresh.
const spfCacheTTL = 24 * time.Hour

// enrichEvent is one item pushed to SSE subscribers.
type enrichEvent struct {
	name string // SSE event name; "" for the default "message" event
	data any
}

// EnrichWorker runs bulk DNS/WHOIS enrichment in the background, independent
// of any single HTTP request. Any number of SSE viewers can attach via
// subscribe() to watch live progress without affecting the run itself, and
// the run keeps going even if every viewer disconnects.
type EnrichWorker struct {
	db *sqlx.DB

	mu     sync.Mutex
	status EnrichStatus
	subs   map[chan enrichEvent]struct{}
}

// NewEnrichWorker creates an EnrichWorker bound to db.
func NewEnrichWorker(db *sqlx.DB) *EnrichWorker {
	return &EnrichWorker{db: db, subs: make(map[chan enrichEvent]struct{})}
}

// Status returns a snapshot of the current (or most recently finished) run.
func (w *EnrichWorker) Status() EnrichStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// Trigger starts a background run if one is not already in progress.
// Returns false without doing anything if a run was already running.
func (w *EnrichWorker) Trigger() bool {
	w.mu.Lock()
	if w.status.Running {
		w.mu.Unlock()
		return false
	}
	w.status = EnrichStatus{Running: true}
	w.mu.Unlock()

	go w.run()
	return true
}

// subscribe registers a channel that receives every event published from
// this point on. The returned func must be called to unsubscribe.
func (w *EnrichWorker) subscribe() (chan enrichEvent, func()) {
	ch := make(chan enrichEvent, 32)
	w.mu.Lock()
	w.subs[ch] = struct{}{}
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		delete(w.subs, ch)
		w.mu.Unlock()
	}
}

// publish fans an event out to every current subscriber, dropping it for any
// subscriber whose buffer is full rather than blocking the run.
func (w *EnrichWorker) publish(name string, data any) {
	w.mu.Lock()
	recipients := make([]chan enrichEvent, 0, len(w.subs))
	for ch := range w.subs {
		recipients = append(recipients, ch)
	}
	w.mu.Unlock()

	for _, ch := range recipients {
		select {
		case ch <- enrichEvent{name: name, data: data}:
		default:
		}
	}
}

// finish marks the run as complete (success or failure) before publishing the
// terminal event, so a subscriber that reads Status() after seeing Running is
// guaranteed to still receive the event if they subscribed first.
func (w *EnrichWorker) finish(ips, domains, spfDomains int, errMsg string) {
	w.mu.Lock()
	w.status.Running = false
	w.status.Error = errMsg
	w.mu.Unlock()

	if errMsg != "" {
		w.publish("error", map[string]string{"message": errMsg})
		return
	}
	w.publish("done", map[string]any{"ips": ips, "domains": domains, "spf": spfDomains})
}

func (w *EnrichWorker) run() {
	ips, err := database.ListStaleSourceIPs(w.db, time.Now().Add(-ipinfo.CacheTTL).Unix())
	if err != nil {
		w.finish(0, 0, 0, err.Error())
		return
	}
	w.mu.Lock()
	w.status.IPTotal = len(ips)
	w.mu.Unlock()
	w.publish("", map[string]any{"type": "ip_start", "total": len(ips)})

	for i, ip := range ips {
		country := ""
		status := "ok"
		if net.ParseIP(ip) == nil {
			// Rows imported before source_ip validation existed: never hand
			// arbitrary reporter-supplied strings to rDNS / WHOIS.
			status = "skipped"
		} else if info, err := ipinfo.Get(w.db, ip); err != nil {
			status = "error"
			log.Printf("enrich: ipinfo.Get(%s): %v", ip, err)
		} else if info != nil {
			country = info.WhoisCountry
		}
		w.mu.Lock()
		w.status.IPDone = i + 1
		w.mu.Unlock()
		w.publish("", map[string]any{
			"type": "ip", "ip": ip, "status": status, "country": country,
			"done": i + 1, "total": len(ips),
		})
	}

	domains, err := database.ListDomains(w.db)
	if err != nil {
		w.finish(len(ips), 0, 0, err.Error())
		return
	}
	existingChecks, _ := database.GetAllDomainChecks(w.db)
	now := time.Now()

	var toCheck []string
	for _, d := range domains {
		dc, ok := existingChecks[d.Domain]
		if !ok || dc.CheckedAt == 0 || now.Sub(time.Unix(dc.CheckedAt, 0)) > domainCheckTTL {
			toCheck = append(toCheck, d.Domain)
		}
	}
	w.mu.Lock()
	w.status.DomainTotal = len(toCheck)
	w.mu.Unlock()
	w.publish("", map[string]any{"type": "domain_start", "total": len(toCheck)})

	for i, domain := range toCheck {
		hasDMARC := lookupDMARCRecord(domain).Found
		hasBIMI := lookupBIMI(domain).Found
		hasMTASTS := lookupMTASTS(domain).Found
		dc := database.DomainCheck{
			Domain:    domain,
			HasDMARC:  boolToInt(hasDMARC),
			HasBIMI:   boolToInt(hasBIMI),
			HasMTASTS: boolToInt(hasMTASTS),
			CheckedAt: time.Now().Unix(),
		}
		if err := database.UpsertDomainCheck(w.db, dc); err != nil {
			log.Printf("enrich: upsert %s: %v", domain, err)
		}
		w.mu.Lock()
		w.status.DomainDone = i + 1
		w.mu.Unlock()
		w.publish("", map[string]any{
			"type": "domain", "domain": domain, "has_dmarc": hasDMARC, "has_bimi": hasBIMI,
			"has_mta_sts": hasMTASTS, "done": i + 1, "total": len(toCheck),
		})
	}

	// Third job: expand SPF records for every managed / reported domain so the
	// spoof-volume split (S4) and the spoof_spike rule (X11) have data.
	spfDomains, err := database.ListStaleSPFDomains(w.db, now.Add(-spfCacheTTL).Unix())
	if err != nil {
		w.finish(len(ips), len(toCheck), 0, err.Error())
		return
	}
	w.mu.Lock()
	w.status.SPFTotal = len(spfDomains)
	w.mu.Unlock()
	w.publish("", map[string]any{"type": "spf_start", "total": len(spfDomains)})

	for i, domain := range spfDomains {
		entry, summary := resolveSPFEntry(domain)
		if err := database.UpsertSPFCache(w.db, entry); err != nil {
			log.Printf("enrich: spf cache %s: %v", domain, err)
		}
		w.mu.Lock()
		w.status.SPFDone = i + 1
		w.mu.Unlock()
		w.publish("", map[string]any{
			"type": "spf", "domain": domain, "cidrs": len(entry.Prefixes()), "lookups": entry.Lookups,
			"over_limit": entry.OverLimit == 1, "error": entry.Error, "summary": summary,
			"done": i + 1, "total": len(spfDomains),
		})
	}

	w.finish(len(ips), len(toCheck), len(spfDomains), "")
}

// resolveSPFEntry expands one domain's SPF record into a cache row.
func resolveSPFEntry(domain string) (database.SPFCacheEntry, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	entry := database.SPFCacheEntry{Domain: domain, CIDRs: "[]", CheckedAt: time.Now().Unix()}
	res, err := spf.Resolve(ctx, nil, domain)
	if err != nil {
		entry.Error = err.Error()
		return entry, "error: " + err.Error()
	}
	b, _ := json.Marshal(res.CIDRs)
	entry.CIDRs = string(b)
	entry.Lookups = res.Lookups
	if res.OverLimit {
		entry.OverLimit = 1
	}
	if len(res.Errors) > 0 {
		entry.Error = strings.Join(res.Errors, "; ")
		if len(entry.Error) > 500 {
			entry.Error = entry.Error[:500]
		}
	}
	switch {
	case res.Record == "":
		return entry, "no SPF record"
	case res.OverLimit:
		return entry, fmt.Sprintf("%d networks, over the %d-lookup limit (incomplete)", len(res.CIDRs), spf.MaxLookups)
	}
	return entry, fmt.Sprintf("%d networks, %d lookups", len(res.CIDRs), res.Lookups)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
