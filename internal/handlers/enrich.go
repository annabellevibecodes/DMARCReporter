package handlers

import (
	"bufio"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"

	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/ipinfo"
)

const domainCheckTTL = 24 * time.Hour

// enrichClearMu and enrichClearLastRun enforce a 60-second minimum gap between
// /enrich/clear calls from the same process (the rate limiter in main.go
// covers per-IP throttling; this covers the global case).
var (
	enrichClearMu      sync.Mutex
	enrichClearLastRun time.Time
)

// HandleEnrichPage renders the enrichment overview page.
func (a *App) HandleEnrichPage(c *fiber.Ctx) error {
	now := time.Now()

	staleIPs, err := database.ListStaleSourceIPs(a.DB, now.Add(-ipinfo.CacheTTL).Unix())
	if err != nil {
		return err
	}
	domains, err := database.ListDomains(a.DB)
	if err != nil {
		return err
	}
	domainChecks, _ := database.GetAllDomainChecks(a.DB)
	staleCount := 0
	for _, d := range domains {
		dc, ok := domainChecks[d.Domain]
		if !ok || dc.CheckedAt == 0 || now.Sub(time.Unix(dc.CheckedAt, 0)) > domainCheckTTL {
			staleCount++
		}
	}

	staleSPF, err := database.ListStaleSPFDomains(a.DB, now.Add(-spfCacheTTL).Unix())
	if err != nil {
		return err
	}
	totalSPF, err := database.CountSPFDomains(a.DB)
	if err != nil {
		return err
	}

	status := a.EnrichWorker.Status()
	flashKind, flashMsg := getFlash(c)
	return c.Render("enrich", fiber.Map{
		"StaleSPF":          len(staleSPF),
		"TotalSPF":          totalSPF,
		"EnrichSPFDone":     status.SPFDone,
		"EnrichSPFTotal":    status.SPFTotal,
		"EnrichTLSDone":     status.TLSDone,
		"EnrichTLSTotal":    status.TLSTotal,
		"EnrichBIMIDone":    status.BIMIDone,
		"EnrichBIMITotal":   status.BIMITotal,
		"Title":             "Enrich — DMARC Reporter",
		"Theme":             getTheme(c),
		"ActivePage":        "enrich",
		"StaleIPs":          len(staleIPs),
		"StaleDomains":      staleCount,
		"TotalDomains":      len(domains),
		"IMAPEnabled":       a.FetchEnabled(),
		"EnrichRunning":     status.Running,
		"EnrichIPDone":      status.IPDone,
		"EnrichIPTotal":     status.IPTotal,
		"EnrichDomainDone":  status.DomainDone,
		"EnrichDomainTotal": status.DomainTotal,
		"FlashKind":         flashKind,
		"FlashMsg":          flashMsg,
		"CSRFToken":         c.Locals("csrf"),
	}, "layouts/base")
}

// HandleEnrichStart triggers a background enrichment run and redirects back
// to the Enrich page. The run is owned by App.EnrichWorker, not by this
// request, so it keeps going even after the response is sent and the browser
// navigates away; /enrich/stream and subsequent loads of this page both
// reflect its live progress.
func (a *App) HandleEnrichStart(c *fiber.Ctx) error {
	if a.EnrichWorker.Trigger() {
		a.setFlash(c, "info", "Enrichment started in the background.")
	} else {
		a.setFlash(c, "info", "Enrichment is already running.")
	}
	return c.Redirect("/enrich")
}

// HandleEnrichStream streams live progress for the current (or most recently
// finished) enrichment run via Server-Sent Events. It only observes the
// background worker's state — it never performs any work itself, so any
// number of tabs can watch the same run and closing them does not stop it.
func (a *App) HandleEnrichStream(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	w := a.EnrichWorker
	c.Context().SetBodyStreamWriter(fasthttp.StreamWriter(func(bw *bufio.Writer) {
		// Subscribe before reading status so we cannot miss the terminal
		// event that fires between our status read and the channel send.
		ch, unsubscribe := w.subscribe()
		defer unsubscribe()

		status := w.Status()
		writeSSE(bw, "sync", status)
		if !status.Running {
			return
		}

		for ev := range ch {
			writeSSE(bw, ev.name, ev.data)
			if ev.name == "done" || ev.name == "error" {
				return
			}
		}
	}))
	return nil
}

func writeSSE(w *bufio.Writer, eventName string, payload any) {
	b, _ := json.Marshal(payload)
	if eventName != "" {
		fmt.Fprintf(w, "event: %s\n", eventName)
	}
	fmt.Fprintf(w, "data: %s\n\n", b)
	w.Flush()
}

// HandleEnrichClear deletes all cached DNS data so the next enrichment run
// re-fetches everything from scratch. Rejected if enrichment is currently running.
func (a *App) HandleEnrichClear(c *fiber.Ctx) error {
	if a.EnrichWorker.Status().Running {
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
