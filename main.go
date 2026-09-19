package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/template/html/v2"

	"github.com/annabellevibecodes/dmarcreporter/internal/alerts"
	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/handlers"
	"github.com/annabellevibecodes/dmarcreporter/internal/ingest"
	"github.com/annabellevibecodes/dmarcreporter/internal/mailauth"
	"github.com/annabellevibecodes/dmarcreporter/internal/secrets"
)

func main() {
	cfg := config.Load()

	audit.Init()
	if cfg.Debug {
		audit.EnableDebug()
	}

	if cfg.AuthPassword == "" && !cfg.AuthDisabled {
		log.Fatal("AUTH_PASSWORD is not set. Set AUTH_PASSWORD to enable authentication, " +
			"or set AUTH_DISABLED=true to explicitly run without authentication (development only).")
	}
	if cfg.AuthDisabled {
		log.Println("WARNING: AUTH_DISABLED=true — the application is running without authentication")
	}

	if cfg.IMAPHost != "" && !cfg.IMAPTLS {
		log.Println("WARNING: IMAP_TLS=false — IMAP credentials and mail content will be transmitted in plaintext")
	}

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	// Secrets box for account credentials at rest (SECRETS_KEY or key file).
	box, err := secrets.Open(cfg.SecretsKey, cfg.DBPath+".key")
	if err != nil {
		log.Fatalf("open secrets store: %v", err)
	}

	worker := ingest.NewWorker(db, cfg, box, mailauth.NewManager())
	if err := worker.SyncEnvAccount(); err != nil {
		log.Printf("WARNING: could not sync IMAP_* environment account: %v", err)
	}
	worker.StartScheduler(cfg.FetchInterval)

	engine := html.New("./views", ".html")
	engine.AddFuncMap(handlers.TemplateFuncs())

	app := fiber.New(fiber.Config{
		Views:        engine,
		ErrorHandler: handlers.ErrorHandler,
		BodyLimit:    11 * 1024 * 1024,
	})

	app.Use(logger.New(logger.Config{
		// Omit query strings from access logs to avoid leaking filter params.
		Format: "${time} ${ip} ${method} ${path} ${status} ${latency}\n",
	}))

	// Prevent browsers from caching dynamic pages. Static assets under /static
	// can still be cached by their own Cache-Control headers.
	app.Use(func(c *fiber.Ctx) error {
		if !strings.HasPrefix(c.Path(), "/static") {
			c.Set("Cache-Control", "no-store")
		}
		return c.Next()
	})

	// Authentication — enabled unless AUTH_DISABLED=true.
	if !cfg.AuthDisabled {
		// Lock out an IP after repeated 401s so the single admin password
		// cannot be brute-forced. Registered before basicauth so it sees the 401.
		app.Use(handlers.AuthThrottle(cfg.AuthFailMax, cfg.AuthFailWindow))
		app.Use(basicauth.New(basicauth.Config{
			Users: map[string]string{cfg.AuthUser: cfg.AuthPassword},
		}))
	}

	// Security headers.
	helmetCfg := helmet.Config{
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"media-src 'self' data:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none';",
		XFrameOptions:    "DENY",
		ReferrerPolicy:   "strict-origin-when-cross-origin",
		PermissionPolicy: "camera=(), microphone=(), geolocation=(), payment=()",
	}
	if cfg.HSTSEnabled {
		helmetCfg.HSTSMaxAge = 31536000 // include subdomains (HSTSExcludeSubdomains defaults false)
	}
	app.Use(helmet.New(helmetCfg))

	// CSRF protection for all state-mutating POST endpoints.
	app.Use(csrf.New(csrf.Config{
		KeyLookup:      "form:_csrf",
		CookieName:     "csrf_",
		CookieHTTPOnly: true,
		CookieSameSite: "Lax",
		CookieSecure:   cfg.SecureCookies,
		ContextKey:     "csrf",
	}))

	app.Static("/static", "./static")

	a := &handlers.App{DB: db, Cfg: cfg, Worker: worker, EnrichWorker: handlers.NewEnrichWorker(db, cfg)}
	// Keep DMARC/BIMI/MTA-STS DNS checks fresh without blocking page loads.
	a.StartDomainCheckRefresher(6 * time.Hour)
	// Time-based alert rules (silent reporters, missing selectors, …) need a
	// ticker; ingest runs also evaluate after importing new reports.
	alerts.StartScheduler(db, cfg, cfg.AlertEvalInterval)

	app.Get("/theme", a.HandleSetTheme)
	app.Get("/", a.HandleDashboard)
	// /reports/dmarc and /reports/tlsrpt are literal 2-segment paths at the
	// same depth as /reports/:id, so they must be registered before it —
	// Fiber v2 matches routes in registration order, not by static-over-param
	// priority, so a param route registered first would shadow them.
	app.Get("/reports", a.HandleReportsRedirect)
	app.Get("/reports/dmarc", a.HandleReportsList)
	app.Get("/reports/tlsrpt", a.HandleReportsTLSRPTList)
	app.Get("/reports/tlsrpt/:id/json", a.HandleTLSRPTReportJSON)
	app.Get("/reports/:id", a.HandleReportDetail)
	app.Get("/reports/:id/xml", a.HandleReportXML)
	app.Get("/upload", a.HandleUploadForm)

	uploadHandlers := []fiber.Handler{a.HandleUploadSubmit}
	if cfg.UploadRateMax > 0 {
		uploadHandlers = append([]fiber.Handler{limiter.New(limiter.Config{
			Max: cfg.UploadRateMax, Expiration: 1 * time.Minute,
		})}, uploadHandlers...)
	}
	app.Post("/upload", uploadHandlers...)

	fetchHandlers := []fiber.Handler{a.HandleFetch}
	if cfg.FetchRateMax > 0 {
		fetchHandlers = append([]fiber.Handler{limiter.New(limiter.Config{
			Max: cfg.FetchRateMax, Expiration: 5 * time.Minute,
		})}, fetchHandlers...)
	}
	app.Post("/fetch", fetchHandlers...)

	// Mail account management.
	accountLimiter := limiter.New(limiter.Config{Max: 30, Expiration: 5 * time.Minute})
	app.Get("/accounts", a.HandleAccountsPage)
	app.Post("/accounts", accountLimiter, a.HandleAccountCreate)
	app.Post("/accounts/:id/delete", accountLimiter, a.HandleAccountDelete)
	app.Post("/accounts/:id/toggle", accountLimiter, a.HandleAccountToggle)
	app.Post("/accounts/:id/test", accountLimiter, a.HandleAccountTest)
	app.Post("/accounts/:id/google-connect", accountLimiter, a.HandleGoogleConnect)
	app.Get("/oauth/google/callback", accountLimiter, a.HandleGoogleCallback)

	app.Get("/tlsrpt", a.HandleTLSRPTList)
	app.Get("/bimi", a.HandleBIMIPage)
	app.Get("/enrich", a.HandleEnrichPage)
	// /enrich/start triggers the background run; it is rate-limited since it
	// mutates state. /enrich/stream only observes the run (any number of tabs
	// may attach), so it gets a looser limit purely against reconnect storms.
	app.Post("/enrich/start", limiter.New(limiter.Config{
		Max: 5, Expiration: 5 * time.Minute,
	}), a.HandleEnrichStart)
	app.Get("/enrich/stream", limiter.New(limiter.Config{
		Max: 30, Expiration: 5 * time.Minute,
	}), a.HandleEnrichStream)
	app.Post("/enrich/clear", limiter.New(limiter.Config{
		Max: 5, Expiration: 5 * time.Minute,
	}), a.HandleEnrichClear)
	app.Get("/export", a.HandleExport)
	app.Get("/domains", a.HandleDomainsList)
	// Domain and source detail pages trigger live DNS/WHOIS lookups — rate-limited.
	detailLimiter := limiter.New(limiter.Config{Max: 30, Expiration: 1 * time.Minute})
	app.Get("/domains/:domain", detailLimiter, a.HandleDomainDetail)
	app.Get("/tlsrpt/:id", detailLimiter, a.HandleTLSRPTDetail)
	app.Get("/help", a.HandleHelpPage)
	app.Get("/help/:section", a.HandleHelpPage)
	app.Get("/reporters", a.HandleReportersPage)
	app.Get("/alerts", a.HandleAlertsPage)
	app.Get("/sources", a.HandleSourcesList)
	app.Get("/sources/:ip", detailLimiter, a.HandleSourceDetail)
	app.Get("/recipients/:domain", detailLimiter, a.HandleRecipientDetail)
	// API endpoints are called by the dashboard charts on every page load.
	apiLimiter := limiter.New(limiter.Config{Max: 60, Expiration: 1 * time.Minute})
	app.Get("/api/stats", apiLimiter, a.HandleAPIStats)
	app.Get("/api/failure-modes", apiLimiter, a.HandleAPIFailureModes)
	app.Get("/api/domain-trend", apiLimiter, a.HandleAPIDomainTrend)
	app.Get("/api/top-failing-sources", apiLimiter, a.HandleAPITopFailingSources)
	// Analytics extension (all honour period / domain / ef / compare=1).
	app.Get("/api/overview", apiLimiter, a.HandleAPIOverview)
	app.Get("/api/auth-matrix", apiLimiter, a.HandleAPIAuthMatrix)
	app.Get("/api/sources", apiLimiter, a.HandleAPISources)
	app.Get("/api/sources/:ip", apiLimiter, a.HandleAPISourceDetail)
	app.Get("/api/new-sources", apiLimiter, a.HandleAPINewSources)
	app.Get("/api/spoof", apiLimiter, a.HandleAPISpoof)
	app.Post("/api/labels/:ip", apiLimiter, a.HandleAPILabelUpsert)
	app.Get("/api/auth", apiLimiter, a.HandleAPIAuth)
	app.Get("/api/policy", apiLimiter, a.HandleAPIPolicy)
	app.Post("/api/selectors/expected", apiLimiter, a.HandleAPISelectorExpected)
	app.Get("/api/reporters", apiLimiter, a.HandleAPIReporters)
	app.Get("/api/bimi", apiLimiter, a.HandleAPIBIMI)
	app.Get("/api/tls", apiLimiter, a.HandleAPITLS)
	app.Get("/api/tls/failures", apiLimiter, a.HandleAPITLSFailures)
	app.Get("/api/tls/policies", apiLimiter, a.HandleAPITLSPolicies)
	app.Get("/api/tls/reporters", apiLimiter, a.HandleAPITLSReporters)
	app.Get("/api/managed-domains", apiLimiter, a.HandleAPIManagedDomainsList)
	app.Post("/api/managed-domains", apiLimiter, a.HandleAPIManagedDomainAdd)
	app.Delete("/api/managed-domains", apiLimiter, a.HandleAPIManagedDomainDelete)
	app.Post("/api/managed-domains/delete", apiLimiter, a.HandleAPIManagedDomainDelete)
	app.Get("/api/alerts", apiLimiter, a.HandleAPIAlerts)
	app.Post("/api/alerts/evaluate", apiLimiter, a.HandleAPIEvaluateAlerts)
	app.Post("/api/alerts/:id/ack", apiLimiter, a.HandleAPIAlertAck)
	app.Get("/api/health", apiLimiter, a.HandleAPIHealth)
	app.Get("/api/health/:domain", apiLimiter, a.HandleAPIHealth)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting DMARC Reporter on http://localhost%s", addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
