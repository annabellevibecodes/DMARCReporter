package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

const domainCheckTTL = 24 * time.Hour

// enrichRunning prevents more than one enrichment run at a time.
var enrichRunning atomic.Bool

// enrichRateMu and enrichLastRun enforce a 60-second minimum gap between
// /enrich/clear calls from the same process (the rate limiter in main.go
// covers per-IP throttling; this covers the global case).
var (
	enrichClearMu      sync.Mutex
	enrichClearLastRun time.Time
)

// HandleEnrichPage renders the enrichment overview page.
func (a *App) HandleEnrichPage(c *fiber.Ctx) error {
	uncachedIPs, err := database.ListUncachedSourceIPs(a.DB)
	if err != nil {
		return err
	}
	domains, err := database.ListDomains(a.DB)
	if err != nil {
		return err
	}
	domainChecks, _ := database.GetAllDomainChecks(a.DB)
	staleCount := 0
	now := time.Now()
	for _, d := range domains {
		dc, ok := domainChecks[d.Domain]
		if !ok || dc.CheckedAt == 0 || now.Sub(time.Unix(dc.CheckedAt, 0)) > domainCheckTTL {
			staleCount++
		}
	}
	return c.Render("enrich", fiber.Map{
		"Title":        "Enrich — DMARC Reporter",
		"Theme":        getTheme(c),
		"ActivePage":   "enrich",
		"UncachedIPs":  len(uncachedIPs),
		"StaleDomains": staleCount,
		"TotalDomains": len(domains),
		"IMAPEnabled":  a.Cfg.IMAPHost != "",
		"CSRFToken":    c.Locals("csrf"),
	}, "layouts/base")
}

// HandleEnrichStream runs bulk enrichment and pushes progress via Server-Sent Events.
func (a *App) HandleEnrichStream(c *fiber.Ctx) error {
	if !enrichRunning.CompareAndSwap(false, true) {
		return fiber.NewError(fiber.StatusConflict, "Enrichment already running")
	}
	defer enrichRunning.Store(false)

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	db := a.DB

	c.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(w *bufio.Writer) {
		send := func(eventName string, payload any) {
			b, _ := json.Marshal(payload)
			if eventName != "" {
				fmt.Fprintf(w, "event: %s\n", eventName)
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			w.Flush()
		}

		// ── IP enrichment ───────────────────────────────────────────────────
		ips, err := database.ListUncachedSourceIPs(db)
		if err != nil {
			send("error", map[string]string{"message": err.Error()})
			return
		}
		send("", map[string]any{"type": "ip_start", "total": len(ips)})

		for i, ip := range ips {
			country := ""
			status := "ok"
			if info, err := ipinfo.Get(db, ip); err != nil {
				status = "error"
				log.Printf("enrich: ipinfo.Get(%s): %v", ip, err)
			} else if info != nil {
				country = info.WhoisCountry
			}
			send("", map[string]any{
				"type":    "ip",
				"ip":      ip,
				"status":  status,
				"country": country,
				"done":    i + 1,
				"total":   len(ips),
			})
		}

		// ── Domain enrichment ────────────────────────────────────────────────
		domains, err := database.ListDomains(db)
		if err != nil {
			send("error", map[string]string{"message": err.Error()})
			return
		}
		existingChecks, _ := database.GetAllDomainChecks(db)
		now := time.Now()

		var toCheck []string
		for _, d := range domains {
			dc, ok := existingChecks[d.Domain]
			if !ok || dc.CheckedAt == 0 || now.Sub(time.Unix(dc.CheckedAt, 0)) > domainCheckTTL {
				toCheck = append(toCheck, d.Domain)
			}
		}
		send("", map[string]any{"type": "domain_start", "total": len(toCheck)})

		for i, domain := range toCheck {
			hasDMARC := lookupDMARCRecord(domain).Found
			hasBIMI := lookupBIMI(domain).Found
			hasMTASTS := lookupMTASTS(domain).Found
			dc := database.DomainCheck{
				Domain:    domain,
				HasDMARC:  boolToInt(hasDMARC),
				HasBIMI:   boolToInt(hasBIMI),
				HasMTASTS: boolToInt(hasMTASTS),
				CheckedAt: now.Unix(),
			}
			if err := database.UpsertDomainCheck(db, dc); err != nil {
				log.Printf("enrich: upsert %s: %v", domain, err)
			}
			send("", map[string]any{
				"type":        "domain",
				"domain":      domain,
				"has_dmarc":   hasDMARC,
				"has_bimi":    hasBIMI,
				"has_mta_sts": hasMTASTS,
				"done":        i + 1,
				"total":       len(toCheck),
			})
		}

		send("done", map[string]any{"ips": len(ips), "domains": len(toCheck)})
	}))
	return nil
}

// HandleEnrichClear deletes all cached DNS data so the next enrichment run
// re-fetches everything from scratch. Rejected if enrichment is currently running.
func (a *App) HandleEnrichClear(c *fiber.Ctx) error {
	if enrichRunning.Load() {
		a.setFlash(c, "error", "Cannot clear cache while enrichment is running.")
		return c.Redirect("/enrich")
	}
	enrichClearMu.Lock()
	defer enrichClearMu.Unlock()
	if time.Since(enrichClearLastRun) < 60*time.Second {
		a.setFlash(c, "warning", "Cache was cleared recently. Please wait before clearing again.")
		return c.Redirect("/enrich")
	}
	if err := database.ClearDNSCache(a.DB); err != nil {
		return err
	}
	enrichClearLastRun = time.Now()
	return c.Redirect("/enrich")
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
