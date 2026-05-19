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

	"github.com/annabellevibecodes/dmarcreporter/internal/audit"
	"github.com/annabellevibecodes/dmarcreporter/internal/config"
	"github.com/annabellevibecodes/dmarcreporter/internal/database"
	"github.com/annabellevibecodes/dmarcreporter/internal/handlers"
)

func main() {
	cfg := config.Load()

	audit.Init()
	if cfg.Debug {
		audit.EnableDebug()
	}

	if cfg.AuthPassword == "" {
		log.Println("WARNING: AUTH_PASSWORD is not set — the application is running without authentication")
	}

	if cfg.IMAPHost != "" && !cfg.IMAPTLS {
		log.Println("WARNING: IMAP_TLS=false — IMAP credentials and mail content will be transmitted in plaintext")
	}

	db, err := database.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()

	engine := html.New("./views", ".html")
	engine.AddFunc("add", func(a, b int) int { return a + b })
	engine.AddFunc("unixTime", func(ts int64) string {
		return time.Unix(ts, 0).UTC().Format("2006-01-02")
	})
	engine.AddFunc("pct", func(f float64) string {
		return fmt.Sprintf("%.1f", f*100)
	})
	engine.AddFunc("splitComma", func(s string) []string {
		if s == "" {
			return nil
		}
		return strings.Split(s, ",")
	})
	engine.AddFunc("commaN", func(n int64) string {
		s := fmt.Sprintf("%d", n)
		for i := len(s) - 3; i > 0; i -= 3 {
			s = s[:i] + "," + s[i:]
		}
		return s
	})

	app := fiber.New(fiber.Config{
		Views:        engine,
		ErrorHandler: handlers.ErrorHandler,
		BodyLimit:    11 * 1024 * 1024,
	})

	app.Use(logger.New(logger.Config{
		// Omit query strings from access logs to avoid leaking filter params.
		Format: "${time} ${method} ${path} ${status} ${latency}\n",
	}))

	// Authentication — enabled when AUTH_PASSWORD is set.
	if cfg.AuthPassword != "" {
		app.Use(basicauth.New(basicauth.Config{
			Users: map[string]string{cfg.AuthUser: cfg.AuthPassword},
		}))
	}

	// Security headers.
	helmetCfg := helmet.Config{
		ContentSecurityPolicy: "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline'; " +
			"style-src 'self' 'unsafe-inline'; " +
			"img-src 'self' data:; " +
			"media-src 'self' data:; " +
			"font-src 'self'; " +
			"connect-src 'self'; " +
			"frame-ancestors 'none';",
		XFrameOptions:   "DENY",
		ReferrerPolicy:  "strict-origin-when-cross-origin",
		PermissionPolicy: "camera=(), microphone=(), geolocation=(), payment=()",
	}
	if cfg.SecureCookies {
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

	a := &handlers.App{DB: db, Cfg: cfg}

	app.Get("/theme", a.HandleSetTheme)
	app.Get("/", a.HandleDashboard)
	app.Get("/reports", a.HandleReportsList)
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
	app.Get("/enrich", a.HandleEnrichPage)
	app.Get("/enrich/stream", limiter.New(limiter.Config{
		Max: 3, Expiration: 5 * time.Minute,
	}), a.HandleEnrichStream)
	app.Post("/enrich/clear", limiter.New(limiter.Config{
		Max: 5, Expiration: 5 * time.Minute,
	}), a.HandleEnrichClear)
	app.Get("/export", a.HandleExport)
	app.Get("/domains", a.HandleDomainsList)
	app.Get("/domains/:domain", a.HandleDomainDetail)
	app.Get("/help", a.HandleHelpPage)
	app.Get("/sources", a.HandleSourcesList)
	app.Get("/sources/:ip", a.HandleSourceDetail)
	app.Get("/recipients/:domain", a.HandleRecipientDetail)
	app.Get("/api/stats", a.HandleAPIStats)
	app.Get("/api/failure-modes", a.HandleAPIFailureModes)
	app.Get("/api/domain-trend", a.HandleAPIDomainTrend)
	app.Get("/api/top-failing-sources", a.HandleAPITopFailingSources)

	addr := fmt.Sprintf(":%s", cfg.Port)
	log.Printf("Starting DMARC Reporter on http://localhost%s", addr)
	if err := app.Listen(addr); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
